package com.telegram.vpncore

import android.app.ForegroundServiceStartNotAllowedException
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.util.Log
import androidx.core.content.ContextCompat
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import io.nekohasekai.libbox.CommandServer
import io.nekohasekai.libbox.Libbox
import io.nekohasekai.libbox.OverrideOptions
import io.nekohasekai.libbox.SetupOptions
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Manages the embedded sing-box SOCKS5 proxy (via libbox).
 *
 * Usage:
 *   VpnProxyManager.getInstance(context).startProxy(config)
 *   VpnProxyManager.getInstance(context).stopProxy()
 */
class VpnProxyManager private constructor(private val context: Context) {

    /**
     * Java-friendly callback interface for proxy connection state changes.
     * Registered listeners are notified on the Main thread.
     */
    interface ConnectionListener {
        fun onProxyConnected(host: String, port: Int, username: String, password: String)
        fun onProxyDisconnected()
    }

    companion object {
        private const val TAG = "VpnProxyManager"
        const val LOCAL_HOST = "127.0.0.1"
        const val LOCAL_PORT = 10808

        @Volatile
        private var instance: VpnProxyManager? = null

        fun getInstance(context: Context): VpnProxyManager =
            instance ?: synchronized(this) {
                instance ?: VpnProxyManager(context.applicationContext).also { instance = it }
            }
    }

    // ─────────────────────────── State ───────────────────────────

    sealed class ProxyState {
        object Idle : ProxyState()
        object Connecting : ProxyState()
        data class Connected(val config: VpnConfig) : ProxyState()
        /** Tunnel stopped for Energy Saving; command server kept warm for fast resume. */
        data class Paused(val config: VpnConfig) : ProxyState()
        data class Error(val message: String) : ProxyState()
    }

    private val _state = MutableStateFlow<ProxyState>(ProxyState.Idle)
    val state: StateFlow<ProxyState> = _state

    // Global listeners — notified on Main thread whenever the proxy connects or disconnects.
    // Use addConnectionListener() from ApplicationLoader to wire up TelegramProxyBridge globally.
    private val connectionListeners = CopyOnWriteArrayList<ConnectionListener>()

    fun addConnectionListener(listener: ConnectionListener) {
        connectionListeners.add(listener)
    }

    fun removeConnectionListener(listener: ConnectionListener) {
        connectionListeners.remove(listener)
    }

    // The core is started with every known server as its own outbound, so the list is read
    // here rather than passed in: a caller that only knows the server it wants would
    // otherwise silently drop the rest and make measurements impossible.
    private val configRepository by lazy { VpnConfigRepository(context) }

    private var commandServer: CommandServer? = null

    /** Last JSON passed to the core — reused on Energy Saving resume without rebuilding. */
    private var cachedJsonConfig: String? = null

    /**
     * Latency per server, keyed by [VpnConfig.id], as measured by the core itself.
     * Read the values through [SingBoxLatency]: they are unsigned, so 0 means "no result"
     * rather than "instant". Restored from disk, so it is populated before the first
     * [measureLatency] of a session finishes.
     */
    private val _latency = MutableStateFlow(runCatching { configRepository.getLatency() }.getOrDefault(emptyMap()))
    val latency: StateFlow<Map<String, Int>> = _latency

    private val commandClient by lazy {
        SingBoxCommandClient(scope) { delays ->
            // Keep previously measured servers: a run only reports what it retested, and a
            // number vanishing from the list would look like the measurement was lost.
            val merged = _latency.value + delays
            _latency.value = merged
            runCatching { configRepository.saveLatency(merged) }
        }
    }

    @Volatile
    private var pauseRequested = false

    @Volatile
    private var coreSetupDone = false
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val mutex = Mutex()

    // Per-install stable SOCKS5 credentials (generated once, persisted). Stable credentials let
    // TelegramProxyBridge.enableProxy() -> SharedConfig.addProxy() deduplicate the VPN proxy by
    // (address, port, username, password). Regenerating them on every startProxy() made that
    // dedup never match and appended a fresh 127.0.0.1:10808 entry on every reconnect,
    // growing the proxy list without bound.
    private val socksPrefs = context.getSharedPreferences("vpn_socks", Context.MODE_PRIVATE)

    @Volatile
    private var socksUsername: String = loadOrCreateToken("socks_user")
    @Volatile
    private var socksPassword: String = loadOrCreateToken("socks_pass")

    private fun loadOrCreateToken(key: String): String {
        val existing = socksPrefs.getString(key, null)
        if (!existing.isNullOrEmpty()) {
            return existing
        }
        val token = randomToken()
        socksPrefs.edit().putString(key, token).apply()
        return token
    }

    private fun randomToken(): String {
        val bytes = ByteArray(16)
        java.security.SecureRandom().nextBytes(bytes)
        return bytes.joinToString("") { "%02x".format(it) }
    }

    // ───────────────────── Auto-reconnect ────────────────────────

    var autoReconnect: Boolean = false
        set(value) {
            field = value
            if (value) registerNetworkMonitor() else unregisterNetworkMonitor()
        }

    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    // Read from the network-callback thread and the watchdog (IO), written from startProxy (IO).
    @Volatile
    private var lastConnectedConfig: VpnConfig? = null

    private fun registerNetworkMonitor() {
        if (networkCallback != null) return
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                val config = lastConnectedConfig ?: return
                val current = _state.value
                // Paused = Energy Saving; Connecting/Connected = already up or in progress.
                if (current is ProxyState.Connected ||
                    current is ProxyState.Paused ||
                    current is ProxyState.Connecting
                ) return
                Log.d(TAG, "Network available, auto-reconnecting...")
                startProxy(config)
            }
            override fun onLost(network: Network) {
                Log.d(TAG, "Network lost, proxy will reconnect when network returns")
            }
        }
        cm.registerNetworkCallback(request, callback)
        networkCallback = callback
    }

    private fun unregisterNetworkMonitor() {
        val cb = networkCallback ?: return
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        try { cm.unregisterNetworkCallback(cb) } catch (_: Exception) {}
        networkCallback = null
    }

    // ────────────────────────── Public API ───────────────────────

    /**
     * Drops the cached sing-box JSON so the next start/resume rebuilds from disk.
     * Call after the server list changes (subscription refresh, add/delete).
     */
    fun invalidateCachedConfig() {
        cachedJsonConfig = null
    }

    /**
     * Applies a changed server list to a running tunnel (subscription refresh).
     *
     * While Connected the core is hot-reloaded with the new list: the outbounds live in the
     * generated JSON, so a cached copy would keep dialling servers that no longer exist. In
     * any other state only the cache is dropped — a Paused tunnel then cold-starts from the
     * fresh list on resume, and nothing is running that could use the new one earlier.
     */
    suspend fun reloadServers() {
        mutex.withLock {
            invalidateCachedConfig()
            val current = _state.value as? ProxyState.Connected ?: return
            val stored = runCatching { configRepository.getAll() }.getOrDefault(emptyList())
            val config = stored.firstOrNull { it.id == current.config.id }
                ?: configRepository.getActive()
                ?: stored.firstOrNull()
            if (config == null) {
                Log.w(TAG, "reloadServers: no servers left, keeping the running core as is")
                return
            }
            cachedJsonConfig = SingBoxConfigGenerator.generate(
                stored, config.id, LOCAL_PORT, socksUsername, socksPassword
            )
            // Reuses the warm-reload path, which already falls back to a full start. Calling
            // it while Connected is safe: startForeground and startWatchdog are both
            // idempotent (the notification is updated, the old watchdog is cancelled).
            resumeProxyLocked(config)
        }
    }

    fun parseLink(uri: String): Result<VpnConfig> = runCatching {
        LinkParser.parse(uri)
    }

    fun startProxy(config: VpnConfig) {
        scope.launch {
            mutex.withLock {
                when (val current = _state.value) {
                    is ProxyState.Connected -> stopProxyInternal()
                    is ProxyState.Paused -> {
                        if (current.config.id == config.id &&
                            commandServer != null && cachedJsonConfig != null
                        ) {
                            resumeProxyLocked(config)
                            return@launch
                        }
                        stopProxyInternal()
                    }
                    else -> Unit
                }
                startProxyLocked(config)
            }
        }
    }

    /**
     * Restarts the tunnel after [pauseProxy]. Reuses the warm command server when possible
     * instead of a full cold start.
     */
    fun resumeProxy() {
        scope.launch {
            mutex.withLock {
                when (_state.value) {
                    is ProxyState.Connected, is ProxyState.Connecting -> return@launch
                    else -> Unit
                }
                val config = when (val current = _state.value) {
                    is ProxyState.Paused -> current.config
                    else -> lastConnectedConfig ?: configRepository.getActive()
                } ?: return@launch
                if (commandServer != null && cachedJsonConfig != null) {
                    resumeProxyLocked(config)
                } else {
                    startProxyLocked(config)
                }
            }
        }
    }

    fun stopProxy() {
        scope.launch {
            mutex.withLock {
                lastConnectedConfig = null
                stopProxyInternal()
            }
        }
    }

    /**
     * Pauses the tunnel for Energy Saving: stops SOCKS traffic and the foreground service,
     * but keeps the command server and cached config so [resumeProxy] can reload quickly.
     */
    fun pauseProxy() {
        pauseRequested = true
        scope.launch {
            mutex.withLock {
                pauseProxyInternal()
                pauseRequested = false
            }
        }
    }

    private suspend fun stopProxyInternal() {
        try {
            stopWatchdog()
            commandServer?.let { server ->
                try { server.closeService() } catch (_: Exception) {}
                try { server.close() } catch (_: Exception) {}
            }
            commandServer = null
            cachedJsonConfig = null
            commandClient.disconnect()
            stopForegroundService()
            _state.emit(ProxyState.Idle)
            Log.d(TAG, "Proxy stopped")
        } catch (e: Exception) {
            Log.e(TAG, "Error stopping proxy", e)
            _state.emit(ProxyState.Idle)
        }
        withContext(Dispatchers.Main) {
            connectionListeners.forEach { it.onProxyDisconnected() }
        }
    }

    /** Energy Saving: stop the data plane, keep the command server for a fast foreground resume. */
    private suspend fun pauseProxyInternal() {
        val config = when (val current = _state.value) {
            is ProxyState.Connected -> current.config
            is ProxyState.Connecting -> lastConnectedConfig ?: configRepository.getActive()
            is ProxyState.Paused -> return
            else -> return
        } ?: return

        if (_state.value is ProxyState.Connecting) {
            stopWatchdog()
            commandClient.disconnect()
            commandServer?.let { server ->
                runCatching { server.closeService() }
                runCatching { server.close() }
            }
            commandServer = null
            stopForegroundService()
            lastConnectedConfig = config
            _state.emit(ProxyState.Paused(config))
            Log.d(TAG, "Proxy paused during connect (Energy Saving)")
            withContext(Dispatchers.Main) {
                connectionListeners.forEach { it.onProxyDisconnected() }
            }
            return
        }

        try {
            stopWatchdog()
            commandClient.disconnect()
            runCatching { commandServer?.closeService() }
            stopForegroundService()
            lastConnectedConfig = config
            _state.emit(ProxyState.Paused(config))
            Log.d(TAG, "Proxy paused (Energy Saving)")
        } catch (e: Exception) {
            Log.e(TAG, "Error pausing proxy, full stop", e)
            stopProxyInternal()
            return
        }
        withContext(Dispatchers.Main) {
            connectionListeners.forEach { it.onProxyDisconnected() }
        }
    }

    private suspend fun startProxyLocked(config: VpnConfig) {
        _state.emit(ProxyState.Connecting)
        lastConnectedConfig = config
        try {
            val servers = allServersIncluding(config)
            val jsonConfig = generateValidatedConfig(servers, config)
            cachedJsonConfig = jsonConfig
            startCore(jsonConfig, config)
            _state.emit(ProxyState.Connected(config))
            if (pauseRequested) {
                pauseProxyInternal()
                return
            }
            Log.d(TAG, "Proxy started on $LOCAL_HOST:$LOCAL_PORT")
            withContext(Dispatchers.Main) {
                connectionListeners.forEach {
                    it.onProxyConnected(LOCAL_HOST, LOCAL_PORT, socksUsername, socksPassword)
                }
            }
        } catch (e: Exception) {
            if (e is PauseRequestedException || pauseRequested) {
                pauseProxyInternal()
                return
            }
            Log.e(TAG, "Failed to start proxy", e)
            cachedJsonConfig = null
            _state.emit(ProxyState.Error(e.message ?: "Unknown error"))
            if (autoReconnect) {
                lastConnectedConfig = config
            }
        }
    }

    private suspend fun resumeProxyLocked(config: VpnConfig) {
        val server = commandServer
        val json = cachedJsonConfig
        if (server == null || json == null) {
            startProxyLocked(config)
            return
        }
        _state.emit(ProxyState.Connecting)
        try {
            server.startOrReloadService(json, OverrideOptions())
            commandClient.connect()
            if (!commandClient.awaitConnected()) {
                throw Exception("command client did not connect after resume")
            }
            // Warm reload: the Go runtime is already up, so the SOCKS port opens faster.
            if (!waitForPort(LOCAL_HOST, LOCAL_PORT, timeoutMs = 2000)) {
                throw Exception("sing-box did not reopen SOCKS port $LOCAL_PORT within timeout")
            }
            lastConnectedConfig = config
            _state.emit(ProxyState.Connected(config))
            Log.d(TAG, "Proxy resumed on $LOCAL_HOST:$LOCAL_PORT")
            withContext(Dispatchers.Main) {
                connectionListeners.forEach {
                    it.onProxyConnected(LOCAL_HOST, LOCAL_PORT, socksUsername, socksPassword)
                }
            }
            tryStartForegroundService(config)
            startWatchdog()
        } catch (e: Exception) {
            Log.w(TAG, "Fast resume failed, falling back to full restart", e)
            runCatching { server.close() }
            commandServer = null
            cachedJsonConfig = null
            commandClient.disconnect()
            startProxyLocked(config)
        }
    }

    /**
     * Every stored server, with [selected] guaranteed present — a config can be started
     * before it has been saved (a freshly parsed link), and leaving it out would produce a
     * selector whose default does not exist.
     */
    private fun allServersIncluding(selected: VpnConfig): List<VpnConfig> {
        val stored = runCatching { configRepository.getAll() }.getOrDefault(emptyList())
        return if (stored.any { it.id == selected.id }) stored else stored + selected
    }

    /** Energy Saving should pause while connected or still connecting. */
    fun shouldPauseForEnergySaving(): Boolean = when (_state.value) {
        is ProxyState.Connected, is ProxyState.Connecting -> true
        else -> false
    }

    /**
     * Measures every server through its own protocol. Results land in [latency]; the call
     * returns immediately because the core reports them asynchronously.
     */
    suspend fun measureLatency() {
        if (!isRunning()) return
        if (!commandClient.awaitConnected()) {
            Log.w(TAG, "measureLatency skipped: command client not ready")
            return
        }
        commandClient.urlTest(SingBoxConfigGenerator.GROUP_TAG)
    }

    /** Non-blocking wrapper for Java / UI callers. */
    fun measureLatencyAsync() {
        scope.launch { measureLatency() }
    }

    /**
     * Switches to [config]. While the core is running this is a selector change, which keeps
     * the tunnel up; otherwise it falls back to starting the core on that server.
     */
    fun selectServer(config: VpnConfig) {
        scope.launch {
            mutex.withLock {
                selectServerLocked(config)
            }
        }
    }

    private suspend fun selectServerLocked(config: VpnConfig) {
        if (isRunning()) {
            if (!commandClient.awaitConnected()) {
                Log.w(TAG, "selectOutbound skipped: command client not ready")
                startProxyLocked(config)
                return
            }
            if (commandClient.selectOutbound(SingBoxConfigGenerator.GROUP_TAG, config.id)) {
                _state.emit(ProxyState.Connected(config))
                lastConnectedConfig = config
                return
            }
        }
        when (val current = _state.value) {
            is ProxyState.Connected -> stopProxyInternal()
            is ProxyState.Paused -> {
                if (current.config.id == config.id &&
                    commandServer != null && cachedJsonConfig != null
                ) {
                    resumeProxyLocked(config)
                    return
                }
                stopProxyInternal()
            }
            else -> Unit
        }
        startProxyLocked(config)
    }

    fun isRunning(): Boolean = _state.value is ProxyState.Connected

    fun isPaused(): Boolean = _state.value is ProxyState.Paused

    fun isConnecting(): Boolean = _state.value is ProxyState.Connecting

    fun getProxyHost(): String = LOCAL_HOST

    fun getProxyPort(): Int = LOCAL_PORT

    /** The per-session SOCKS5 credentials generated for the currently running proxy, if any. */
    fun getSocksCredentials(): Pair<String, String> = socksUsername to socksPassword

    fun getCurrentConfig(): VpnConfig? = when (val state = _state.value) {
        is ProxyState.Connected -> state.config
        is ProxyState.Paused -> state.config
        else -> null
    }

    // ───────────────────────── sing-box ──────────────────────────

    /** Per-server check against the core, used to drop servers it would refuse to load. */
    fun serverValidator(): ServerValidator = LibboxServerValidator { ensureCoreSetup() }

    /**
     * Builds the config for [servers], making sure the core accepts it.
     *
     * The core checks a config as a whole, so a single outbound it dislikes (a transport or
     * field from a newer panel) would otherwise stop every server. If the full config is
     * refused, servers are checked one by one, the bad ones are left out and the config is
     * regenerated once. The selected server is the exception: if it is the bad one, starting
     * is pointless and its own error is what the user needs to see.
     */
    private fun generateValidatedConfig(servers: List<VpnConfig>, selected: VpnConfig): String {
        ensureCoreSetup()
        val json = SingBoxConfigGenerator.generate(
            servers, selected.id, LOCAL_PORT, socksUsername, socksPassword
        )
        try {
            Libbox.checkConfig(json)
            return json
        } catch (e: Exception) {
            Log.w(TAG, "Core refused the full config (${e.message?.take(160)}); checking servers one by one")
        }
        val validator = serverValidator()
        validator.validate(selected)?.let { throw Exception(it) }
        val outcome = validator.filter(servers)
        Log.w(TAG, "Starting without ${outcome.rejected.size} server(s) the core rejected")
        val retry = SingBoxConfigGenerator.generate(
            outcome.valid, selected.id, LOCAL_PORT, socksUsername, socksPassword
        )
        Libbox.checkConfig(retry)
        return retry
    }

    /** One-time libbox setup; safe to call repeatedly, only the first call does work. */
    @Synchronized
    private fun ensureCoreSetup() {
        if (coreSetupDone) return
        val base = context.filesDir.resolve("singbox").apply { mkdirs() }
        val work = base.resolve("work").apply { mkdirs() }
        val temp = context.cacheDir.resolve("singbox").apply { mkdirs() }
        Libbox.setup(SetupOptions().apply {
            basePath = base.absolutePath
            workingPath = work.absolutePath
            tempPath = temp.absolutePath
        })
        coreSetupDone = true
    }

    private suspend fun startCore(jsonConfig: String, config: VpnConfig) {
        ensureCoreSetup()

        Libbox.checkConfig(jsonConfig)

        val server = CommandServer(
            TejarCommandServerHandler(onServiceStop = { stopProxy() }),
            TejarPlatformInterface(context)
        )
        server.start()
        try {
            server.startOrReloadService(jsonConfig, OverrideOptions())
        } catch (e: Exception) {
            try { server.close() } catch (_: Exception) {}
            throw e
        }
        commandServer = server
        commandClient.connect()
        if (!commandClient.awaitConnected()) {
            Log.w(TAG, "Command client slow to connect; urlTest/select may retry later")
        }

        if (!waitForPort(LOCAL_HOST, LOCAL_PORT, timeoutMs = 3000)) {
            if (pauseRequested) {
                try { server.closeService() } catch (_: Exception) {}
                try { server.close() } catch (_: Exception) {}
                commandServer = null
                throw PauseRequestedException()
            }
            try { server.closeService() } catch (_: Exception) {}
            try { server.close() } catch (_: Exception) {}
            commandServer = null
            throw Exception("sing-box did not open SOCKS port $LOCAL_PORT within timeout")
        }

        tryStartForegroundService(config)
        startWatchdog()
    }

    private class PauseRequestedException : Exception()

    private fun waitForPort(host: String, port: Int, timeoutMs: Int): Boolean {
        val start = System.currentTimeMillis()
        while (System.currentTimeMillis() - start < timeoutMs) {
            if (pauseRequested) {
                Log.d(TAG, "waitForPort aborted: Energy Saving pause requested")
                return false
            }
            try {
                java.net.Socket().use { socket ->
                    socket.connect(java.net.InetSocketAddress(host, port), 500)
                }
                Log.d(TAG, "Port $port is ready")
                return true
            } catch (_: Exception) {
                Thread.sleep(200)
            }
        }
        Log.w(TAG, "Port $port not ready after ${timeoutMs}ms")
        return false
    }

    private var watchdogJob: Job? = null

    private fun startWatchdog() {
        watchdogJob?.cancel()
        watchdogJob = scope.launch {
            while (isActive) {
                delay(15000)
                if (_state.value !is ProxyState.Connected) continue
                val alive = try {
                    java.net.Socket().use { socket ->
                        socket.connect(java.net.InetSocketAddress(LOCAL_HOST, LOCAL_PORT), 1000)
                    }
                    true
                } catch (_: Exception) {
                    false
                }
                if (!alive && _state.value is ProxyState.Connected) {
                    // A dead local SOCKS port means the in-process xray core crashed. Recover
                    // whenever lastConnectedConfig is set (user hasn't pressed Disconnect) —
                    // NOT only when autoReconnect is on (that flag is about network changes).
                    // Previously a single transient failure with autoReconnect off left the
                    // proxy permanently down. startProxy() stops the stale core under the mutex
                    // and restarts, so we don't stop/emit here (avoids an unlocked-state race).
                    val config = lastConnectedConfig ?: continue
                    Log.w(TAG, "Watchdog: proxy port dead, restarting...")
                    startProxy(config)
                }
            }
        }
    }

    private fun stopWatchdog() {
        watchdogJob?.cancel()
        watchdogJob = null
    }

    // ─────────────────────── Service lifecycle ───────────────────

    private fun tryStartForegroundService(config: VpnConfig) {
        val intent = Intent(context, ProxyForegroundService::class.java).apply {
            action = ProxyForegroundService.ACTION_START
            putExtra(ProxyForegroundService.EXTRA_CONFIG, config)
        }
        // Always attempt to start the FGS, even from background. Skipping it (as before) meant
        // background-initiated starts (boot restore, auto-reconnect on network change, energy
        // resume) ran the in-process xray with NO foreground service, so the OS could kill the
        // process at any time and the proxy died silently. Boot / brief-foreground starts are
        // exempt and will succeed; if the platform genuinely blocks it we catch below.
        try {
            ContextCompat.startForegroundService(context, intent)
        } catch (e: Exception) {
            if (Build.VERSION.SDK_INT >= 31 && e is ForegroundServiceStartNotAllowedException) {
                Log.d(TAG, "ForegroundServiceStartNotAllowed, proxy runs without notification")
            } else {
                Log.e(TAG, "Failed to start foreground service", e)
            }
        }
    }

    private fun stopForegroundService() {
        try {
            val intent = Intent(context, ProxyForegroundService::class.java).apply {
                action = ProxyForegroundService.ACTION_STOP
            }
            context.startService(intent)
        } catch (e: Exception) {
            Log.d(TAG, "Failed to stop foreground service", e)
        }
    }

    fun destroy() {
        unregisterNetworkMonitor()
        scope.launch {
            mutex.withLock {
                stopProxyInternal()
            }
            scope.cancel()
        }
    }
}
