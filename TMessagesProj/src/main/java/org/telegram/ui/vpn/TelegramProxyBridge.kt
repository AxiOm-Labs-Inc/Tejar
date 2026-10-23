package org.telegram.ui.vpn

import android.util.Log
import org.telegram.messenger.MessagesController
import org.telegram.messenger.NotificationCenter
import org.telegram.messenger.SharedConfig
import org.telegram.tgnet.ConnectionsManager
import org.telegram.utils.proxy.ProxySettings

object TelegramProxyBridge {

    private const val TAG = "TelegramProxyBridge"

    fun enableProxy(host: String, port: Int, username: String, password: String) {
        try {
            SharedConfig.loadProxyList()
            // Drop any previous VPN-proxy entries for this host:port (ignoring creds) so the
            // auto-managed VPN proxy never accumulates duplicates in the proxy list.
            SharedConfig.proxyList.removeAll { it.settings.address == host && it.settings.port == port }

            val settings = ProxySettings.builder()
                .setType(ProxySettings.Type.SOCKS5)
                .setAddress(host)
                .setPort(port)
                .setUser(username)
                .setPassword(password)
                .build()
            SharedConfig.currentProxy = SharedConfig.addProxy(SharedConfig.ProxyInfo(settings))
            SharedConfig.saveConfig()

            // Persist proxy state to "mainconfig" exactly like ProxyListActivity does.
            // ConnectionsManager.init() (per-account, on activation / DC re-init) reads these
            // keys; without proxy_enabled=true + proxy_ip/proxy_port, Telegram drops the proxy
            // on the next reconnect and silently connects direct while xray still listens
            // locally — the intermittent "proxy stops working" symptom.
            val editor = MessagesController.getGlobalMainSettings().edit()
            settings.toSharedPreferences(editor)
            editor.putBoolean("proxy_enabled", true)
            editor.commit()

            ConnectionsManager.setProxySettings(true, settings)

            NotificationCenter.getGlobalInstance()
                .postNotificationName(NotificationCenter.proxySettingsChanged)

            Log.i(TAG, "Proxy enabled: $host:$port")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to enable proxy", e)
        }
    }

    fun disableProxy() {
        try {
            // Clear the persisted flag too, so init() doesn't re-apply a stale proxy.
            val editor = MessagesController.getGlobalMainSettings().edit()
            editor.putBoolean("proxy_enabled", false)
            editor.commit()

            ConnectionsManager.setProxySettings(false, null)
            SharedConfig.saveConfig()

            NotificationCenter.getGlobalInstance()
                .postNotificationName(NotificationCenter.proxySettingsChanged)

            Log.i(TAG, "Proxy disabled")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to disable proxy", e)
        }
    }
}
