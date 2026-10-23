package com.telegram.vpncore

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import java.util.concurrent.Executors

/**
 * Restores the active VPN proxy connection after device reboot, but only if the user
 * had it running before shutdown (checked via VpnConfigRepository.isVpnRunning() — a
 * saved config alone is not enough, since it stays saved after the user disconnects).
 *
 * On Android 12+, starting the foreground service directly from BOOT_COMPLETED is
 * disallowed by the platform; VpnProxyManager.tryStartForegroundService() catches that
 * and the in-process xray core keeps running without a notification. ApplicationLoader's
 * restore-on-launch path (which runs with normal foreground privileges) re-attempts the
 * foreground service the next time the app process starts, so the notification recovers
 * without user action.
 */
class VpnBootReceiver : BroadcastReceiver() {

    companion object {
        private const val TAG = "VpnBootReceiver"
        private val bootExecutor = Executors.newSingleThreadExecutor()
    }

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        val appContext = context.applicationContext
        // EncryptedSharedPreferences (repo.isVpnRunning()/getActive()) hits the Android
        // Keystore, which is real I/O — doing that on onReceive's main thread risks an ANR
        // for a broadcast the system already expects to return quickly. goAsync() + a
        // background thread keeps the receiver alive long enough to finish that work.
        val pendingResult = goAsync()
        bootExecutor.execute {
            try {
                val repo = VpnConfigRepository(appContext)
                // With Energy Saving the tunnel waits for the app to come to the foreground.
                if (repo.isVpnRunning() && !repo.isEnergySaving()) {
                    val active = repo.getActive()
                    if (active != null) {
                        val manager = VpnProxyManager.getInstance(appContext)
                        val prefs = appContext.getSharedPreferences("vpn_settings", Context.MODE_PRIVATE)
                        manager.autoReconnect = prefs.getBoolean("auto_reconnect", false)
                        manager.startProxy(active)
                        Log.d(TAG, "Boot restore initiated for ${active.displayName}")
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to restore proxy on boot", e)
            } finally {
                pendingResult.finish()
            }
        }
    }
}
