package com.telegram.vpncore

import android.util.Log
import io.nekohasekai.libbox.CommandClient
import io.nekohasekai.libbox.CommandClientHandler
import io.nekohasekai.libbox.CommandClientOptions
import io.nekohasekai.libbox.ConnectionEvents
import io.nekohasekai.libbox.Libbox
import io.nekohasekai.libbox.LogIterator
import io.nekohasekai.libbox.OutboundGroupItemIterator
import io.nekohasekai.libbox.OutboundGroupIterator
import io.nekohasekai.libbox.StatusMessage
import io.nekohasekai.libbox.StringIterator
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * Talks to the running core over libbox's command channel.
 *
 * Two things need it. Switching server is `selectOutbound` on the selector rather than a
 * core restart, and latency is `urlTest` on that same group — the core dials each server
 * over its real protocol, which is the only measurement that means anything for Hysteria2
 * (QUIC behind salamander obfuscation answers nothing else) or NaiveProxy.
 *
 * Results arrive asynchronously through [CommandClientHandler.writeGroups]; [onDelays]
 * is called with outbound tag → the core's own delay value. The core reports an unsigned
 * number, so it never says "-1": 0 means there is no result for that server (the test
 * failed or has not run) and a value above [FAILED_ABOVE] marks a failure. See
 * [SingBoxLatency] for reading them.
 */
internal class SingBoxCommandClient(
    private val scope: CoroutineScope,
    private val onDelays: (Map<String, Int>) -> Unit
) {

    private companion object {
        const val TAG = "SingBoxCommand"
        // The core needs a moment after start before its command socket accepts anyone;
        // the reference client retries on a growing delay rather than failing outright.
        const val CONNECT_ATTEMPTS = 10
    }

    @Volatile
    private var client: CommandClient? = null

    /** Set in [Handler.connected]; cleared in [disconnect]. */
    @Volatile
    private var handlerConnected = false

    fun connect() {
        disconnect()
        val options = CommandClientOptions().apply {
            addCommand(Libbox.CommandGroup)
            statusInterval = 2L * 1000 * 1000 * 1000  // nanoseconds
        }
        val newClient = CommandClient(Handler(), options)
        scope.launch(Dispatchers.IO) {
            for (attempt in 1..CONNECT_ATTEMPTS) {
                delay(100 + attempt * 50L)
                val connected = runCatching { newClient.connect() }.isSuccess
                if (!connected) continue
                if (!isActive) {
                    runCatching { newClient.disconnect() }
                    return@launch
                }
                client = newClient
                return@launch
            }
            Log.w(TAG, "Command client could not reach the core")
            runCatching { newClient.disconnect() }
        }
    }

    /** Blocks until the handler reports connected or [timeoutMs] elapses. */
    suspend fun awaitConnected(timeoutMs: Long = 3000L): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (handlerConnected && client != null) return true
            delay(50)
        }
        return handlerConnected && client != null
    }

    fun disconnect() {
        handlerConnected = false
        val current = client ?: return
        client = null
        runCatching { current.disconnect() }
    }

    /** Asks the core to measure every server in [group]; results arrive via [onDelays]. */
    fun urlTest(group: String) {
        val current = client ?: run {
            Log.w(TAG, "urlTest skipped: no command connection")
            return
        }
        scope.launch(Dispatchers.IO) {
            runCatching { current.urlTest(group) }
                .onFailure { Log.w(TAG, "urlTest failed", it) }
        }
    }

    /** Switches the selector to [outboundTag] without restarting the core. */
    fun selectOutbound(group: String, outboundTag: String): Boolean {
        val current = client ?: return false
        return runCatching { current.selectOutbound(group, outboundTag) }
            .onFailure { Log.w(TAG, "selectOutbound failed", it) }
            .isSuccess
    }

    private inner class Handler : CommandClientHandler {

        override fun writeGroups(groups: OutboundGroupIterator?) {
            if (groups == null) return
            val delays = mutableMapOf<String, Int>()
            while (groups.hasNext()) {
                val group = groups.next()
                val items = group.items
                while (items.hasNext()) {
                    val item = items.next()
                    delays[item.tag] = item.urlTestDelay
                }
            }
            if (delays.isNotEmpty()) onDelays(delays)
        }

        override fun connected() {
            handlerConnected = true
            Log.d(TAG, "Command client connected")
        }

        override fun disconnected(message: String?) {
            handlerConnected = false
            Log.d(TAG, "Command client disconnected: $message")
        }

        // Not subscribed to; the command list only asks for groups.
        override fun clearLogs() = Unit
        override fun writeLogs(messages: LogIterator?) = Unit
        override fun writeStatus(message: StatusMessage?) = Unit
        override fun writeConnectionEvents(message: ConnectionEvents?) = Unit
        override fun setDefaultLogLevel(level: Int) = Unit
        override fun initializeClashMode(modes: StringIterator?, current: String?) = Unit
        override fun updateClashMode(mode: String?) = Unit
        override fun writeOutbounds(message: OutboundGroupItemIterator?) = Unit
    }
}
