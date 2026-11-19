package com.telegram.vpncore

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.util.Log
import io.nekohasekai.libbox.BridgeOptions
import io.nekohasekai.libbox.BridgeSession
import io.nekohasekai.libbox.CommandServerHandler
import io.nekohasekai.libbox.NeighborUpdateListener
import io.nekohasekai.libbox.PlatformUser
import io.nekohasekai.libbox.ShellSession
import io.nekohasekai.libbox.InterfaceUpdateListener
import io.nekohasekai.libbox.LocalDNSTransport
import io.nekohasekai.libbox.NetworkInterface as LibboxNetworkInterface
import io.nekohasekai.libbox.NetworkInterfaceIterator
import io.nekohasekai.libbox.Notification
import io.nekohasekai.libbox.PlatformInterface
import io.nekohasekai.libbox.StringIterator
import io.nekohasekai.libbox.SystemProxyStatus
import io.nekohasekai.libbox.TunOptions
import io.nekohasekai.libbox.WIFIState
import java.net.NetworkInterface as JavaNetworkInterface

/**
 * Platform glue for sing-box.
 *
 * Tejar runs the core as a plain local SOCKS proxy — there is no TUN device and no
 * VPN permission — so most of [PlatformInterface] is deliberately inert. Only the
 * network-interface parts are real: the core needs them to pick an outbound interface
 * and to notice connectivity changes.
 */
internal class TejarPlatformInterface(private val context: Context) : PlatformInterface {

    private val connectivity: ConnectivityManager? =
        context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager

    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    // ── TUN: not used ────────────────────────────────────────────
    // The generated config has no tun inbound, so the core never asks for one. If it
    // ever does, failing loudly beats handing back a bogus fd.
    override fun openTun(options: TunOptions): Int =
        throw UnsupportedOperationException("Tejar runs sing-box as a local SOCKS proxy, without TUN")

    override fun findConnectionOwner(
        ipProtocol: Int, sourceAddress: String, sourcePort: Int,
        destinationAddress: String, destinationPort: Int
    ) = throw UnsupportedOperationException("process lookup is not used")

    override fun usePlatformAutoDetectInterfaceControl(): Boolean = false

    override fun autoDetectInterfaceControl(fd: Int) = Unit

    override fun underNetworkExtension(): Boolean = false

    override fun includeAllNetworks(): Boolean = false

    // Returning null makes the core use the DNS servers from the config instead of
    // the platform resolver — which is what we want, so queries stay in the tunnel.
    override fun localDNSTransport(): LocalDNSTransport? = null

    override fun clearDNSCache() = Unit

    override fun readWIFIState(): WIFIState? = null

    override fun sendNotification(notification: Notification) = Unit

    override fun cancelNotification(identifier: String, typeID: Int) = Unit

    // ── sing-box 1.14 additions: neighbor table, SSH shell, Tailscale, bridges ──
    // None of these are used by a SOCKS-only config; same answers as libbox's own stub.
    override fun startNeighborMonitor(listener: NeighborUpdateListener) =
        throw UnsupportedOperationException("neighbor monitor is not used")

    override fun closeNeighborMonitor(listener: NeighborUpdateListener) = Unit

    override fun registerMyInterface(name: String) = Unit

    override fun usePlatformShell(): Boolean = false

    override fun checkPlatformShell() = throw UnsupportedOperationException("no platform shell")

    override fun openShellSession(
        user: PlatformUser, command: String, environ: StringIterator, term: String, rows: Int, cols: Int
    ): ShellSession = throw UnsupportedOperationException("no platform shell")

    override fun lookupUser(username: String): PlatformUser = throw UnsupportedOperationException("no platform users")

    override fun lookupSFTPServer(): String = throw UnsupportedOperationException("no SFTP server")

    override fun readSystemSSHHostKey(): String = throw UnsupportedOperationException("no SSH host key")

    override fun tailscaleHostname(): String = ""

    override fun usePlatformBridge(): Boolean = false

    override fun createBridge(options: BridgeOptions): BridgeSession =
        throw UnsupportedOperationException("no platform bridge")

    // ── Network interfaces ───────────────────────────────────────

    override fun getInterfaces(): NetworkInterfaceIterator {
        val result = mutableListOf<LibboxNetworkInterface>()
        try {
            for (iface in JavaNetworkInterface.getNetworkInterfaces()) {
                val addresses = iface.interfaceAddresses.mapNotNull { addr ->
                    // Link-local IPv6 comes back as "fe80::.../64%wlan0". Go's netip.ParsePrefix
                    // rejects zones outright and the core panics, so drop the scope suffix.
                    addr.address?.hostAddress
                        ?.substringBefore('%')
                        ?.let { "$it/${addr.networkPrefixLength}" }
                }
                result += LibboxNetworkInterface().apply {
                    name = iface.name
                    index = iface.index
                    mtu = runCatching { iface.mtu }.getOrDefault(1500)
                    setAddresses(StringListIterator(addresses))
                    flags = 0
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to enumerate network interfaces", e)
        }
        return InterfaceListIterator(result)
    }

    override fun startDefaultInterfaceMonitor(listener: InterfaceUpdateListener) {
        val cm = connectivity ?: run {
            // No ConnectivityManager: report "no interface" rather than leaving the core
            // blocked waiting for a first update that will never arrive.
            listener.updateDefaultInterface("", -1, false, false)
            return
        }
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) = notify(network)
            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) = notify(network)
            override fun onLost(network: Network) {
                listener.updateDefaultInterface("", -1, false, false)
            }

            private fun notify(network: Network) {
                try {
                    val linkProperties = cm.getLinkProperties(network) ?: return
                    val name = linkProperties.interfaceName ?: return
                    val index = runCatching {
                        JavaNetworkInterface.getByName(name)?.index ?: -1
                    }.getOrDefault(-1)
                    val caps = cm.getNetworkCapabilities(network)
                    val expensive = caps?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true
                    listener.updateDefaultInterface(name, index, expensive, false)
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to report default interface", e)
                }
            }
        }
        networkCallback = callback
        try {
            cm.registerNetworkCallback(
                NetworkRequest.Builder()
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                    .build(),
                callback
            )
        } catch (e: Exception) {
            Log.w(TAG, "Failed to register network callback", e)
            listener.updateDefaultInterface("", -1, false, false)
        }
    }

    override fun closeDefaultInterfaceMonitor(listener: InterfaceUpdateListener) {
        val callback = networkCallback ?: return
        networkCallback = null
        try {
            connectivity?.unregisterNetworkCallback(callback)
        } catch (e: Exception) {
            Log.w(TAG, "Failed to unregister network callback", e)
        }
    }

    private companion object {
        const val TAG = "TejarPlatform"
    }
}

/**
 * Command-server callbacks. Tejar has no system-proxy toggle and no in-app service
 * controls, so these only need to report "nothing enabled" and log.
 */
internal class TejarCommandServerHandler(
    private val onServiceStop: () -> Unit
) : CommandServerHandler {

    override fun serviceReload() = Unit

    override fun serviceStop() {
        onServiceStop()
    }

    override fun getSystemProxyStatus(): SystemProxyStatus =
        SystemProxyStatus().apply {
            available = false
            enabled = false
        }

    override fun setSystemProxyEnabled(isEnabled: Boolean) = Unit

    override fun writeDebugMessage(message: String) {
        Log.d("SingBox", message)
    }

    override fun triggerNativeCrash() = Unit

    override fun connectSSHAgent(): Int = throw UnsupportedOperationException("no SSH agent")
}

// ── Iterator adapters ────────────────────────────────────────────

private object EmptyStringIterator : StringIterator {
    override fun hasNext(): Boolean = false
    override fun len(): Int = 0
    override fun next(): String = throw NoSuchElementException()
}

private class StringListIterator(private val items: List<String>) : StringIterator {
    private var cursor = 0
    override fun hasNext(): Boolean = cursor < items.size
    override fun len(): Int = items.size
    override fun next(): String = items[cursor++]
}

private class InterfaceListIterator(
    private val items: List<LibboxNetworkInterface>
) : NetworkInterfaceIterator {
    private var cursor = 0
    override fun hasNext(): Boolean = cursor < items.size
    override fun next(): LibboxNetworkInterface = items[cursor++]
}
