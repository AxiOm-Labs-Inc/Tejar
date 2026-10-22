package com.telegram.vpncore

import android.content.Context
import android.system.Os
import android.util.Log
import java.io.File
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.SecureRandom
import java.util.concurrent.TimeUnit

/**
 * Runs the bundled xray binary as a child process.
 *
 * xray cannot live in this process: libbox and libv2ray are both gomobile builds that ship
 * `go/Seq`, so the two would clash in one APK. The binary ships as `libxray.so` (see the
 * `prepareXray` task in build.gradle) so that it lands, executable, in the native library
 * directory. Thin on purpose: the config is built by [XrayConfigBuilder] and tested there.
 */
class XrayProcess(private val context: Context, private val onExit: (Int) -> Unit) {

    companion object {
        private const val TAG = "XrayProcess"
        private const val LIB_NAME = "libxray.so"
        private const val READY_TIMEOUT_MS = 3000L
        private const val TEST_TIMEOUT_S = 15L

        /** The xray executable, or null when it was not shipped for this ABI or cannot be run. */
        fun binary(context: Context): File? =
            File(context.applicationInfo.nativeLibraryDir, LIB_NAME).takeIf { it.isFile && it.canExecute() }

        /** One free local port and fresh credentials per xray server. */
        fun assignEndpoints(servers: List<VpnConfig>): Map<String, XrayEndpoint> {
            val random = SecureRandom()
            fun token() = ByteArray(12).also(random::nextBytes).joinToString("") { "%02x".format(it) }
            return servers.filter(XrayConfigBuilder::isXray).associate { it.id to XrayEndpoint(freePort(), token(), token()) }
        }

        private fun freePort(): Int = ServerSocket(0, 1, java.net.InetAddress.getByName("127.0.0.1")).use { it.localPort }

        /**
         * Checks one xray server's outbound with `xray run -test`. Null = accepted;
         * [ServerValidator.XRAY_UNAVAILABLE] when there is no binary to ask.
         */
        fun check(context: Context, server: VpnConfig): String? {
            val bin = binary(context) ?: return ServerValidator.XRAY_UNAVAILABLE
            val file = newPrivateFile(context, "xray-check")
            return try {
                val config = XrayConfigBuilder.build(
                    listOf(server), mapOf(server.id to XrayEndpoint(1, "check", "check"))
                )
                file.writeText(config)
                val p = ProcessBuilder(bin.absolutePath, "run", "-test", "-c", file.absolutePath)
                    .redirectErrorStream(true).start()
                val out = p.inputStream.bufferedReader().readText()
                if (!p.waitFor(TEST_TIMEOUT_S, TimeUnit.SECONDS)) {
                    p.destroyForcibly()
                    "xray check timed out"
                } else if (p.exitValue() == 0) null
                else out.lineSequence().lastOrNull { it.isNotBlank() }?.take(200) ?: "xray rejected the config"
            } catch (e: Exception) {
                e.message ?: e.javaClass.simpleName
            } finally {
                file.delete()
            }
        }

        /** An empty file only the app can read: the config holds server credentials. */
        private fun newPrivateFile(context: Context, name: String): File {
            val dir = File(context.noBackupFilesDir, "xray").apply { mkdirs() }
            val f = File(dir, name)
            f.delete()
            f.createNewFile()
            Os.chmod(f.absolutePath, 384) // 0600
            return f
        }
    }

    @Volatile
    private var process: Process? = null

    val isAlive: Boolean get() = process?.isAlive == true

    /**
     * Starts xray for [servers] on the given [endpoints] and waits for every port to accept
     * connections. Returns the ids that are ready; the rest failed to come up and must not be
     * handed to sing-box. Throws if the process cannot be started at all.
     */
    fun start(servers: List<VpnConfig>, endpoints: Map<String, XrayEndpoint>): Set<String> {
        stop()
        val bin = binary(context) ?: throw IllegalStateException(ServerValidator.XRAY_UNAVAILABLE)
        val config = newPrivateFile(context, "config.json")
        config.writeText(XrayConfigBuilder.build(servers, endpoints))

        val builder = ProcessBuilder(bin.absolutePath, "run", "-c", config.absolutePath)
            .redirectErrorStream(true)
        // No geoip/geosite files are shipped; point xray somewhere that exists and is ours.
        builder.environment()["XRAY_LOCATION_ASSET"] = config.parentFile!!.absolutePath
        val p = builder.start()
        process = p
        // The output is xray's log; the config itself is never printed.
        Thread({
            try {
                p.inputStream.bufferedReader().forEachLine { Log.w(TAG, it.take(300)) }
            } catch (_: Exception) {}
        }, "xray-log").apply { isDaemon = true }.start()
        Thread({
            val code = try { p.waitFor() } catch (_: InterruptedException) { -1 }
            // stop() clears [process] first, so an exit we asked for is not reported.
            if (process === p) {
                Log.w(TAG, "xray exited with code $code")
                onExit(code)
            }
        }, "xray-wait").apply { isDaemon = true }.start()
        // The file is only needed until xray has read it, but removing it races startup.
        // It is private (0600) and overwritten on every start.

        val deadline = System.currentTimeMillis() + READY_TIMEOUT_MS
        val pending = endpoints.filterKeys { id -> servers.any { it.id == id } }.toMutableMap()
        val ready = HashSet<String>()
        while (pending.isNotEmpty() && System.currentTimeMillis() < deadline && p.isAlive) {
            val it = pending.entries.iterator()
            while (it.hasNext()) {
                val (id, ep) = it.next()
                if (canConnect(ep.port)) { ready.add(id); it.remove() }
            }
            if (pending.isNotEmpty()) Thread.sleep(50)
        }
        if (pending.isNotEmpty()) Log.w(TAG, "${pending.size} xray inbound(s) did not come up")
        return ready
    }

    fun stop() {
        val p = process ?: return
        process = null
        p.destroy()
        try {
            if (!p.waitFor(1500, TimeUnit.MILLISECONDS)) p.destroyForcibly()
        } catch (_: InterruptedException) {
            p.destroyForcibly()
        }
        File(File(context.noBackupFilesDir, "xray"), "config.json").delete()
    }

    private fun canConnect(port: Int): Boolean = try {
        Socket().use { it.connect(InetSocketAddress("127.0.0.1", port), 200); true }
    } catch (_: Exception) {
        false
    }
}
