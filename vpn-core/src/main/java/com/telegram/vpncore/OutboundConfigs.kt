package com.telegram.vpncore

import org.json.JSONObject
import java.security.MessageDigest

/**
 * Wraps a ready-made sing-box outbound (or endpoint) in a [VpnConfig].
 *
 * Formats that are translated to sing-box JSON (extra link schemes, Clash, xray) all end up
 * here, so they behave like a sing-box subscription: the core gets the object verbatim and the
 * parsed fields exist only for the UI.
 */
object OutboundConfigs {

    /**
     * @param stableIds when given, the id is derived from the server's identity so it survives
     *        a refresh (see [SingBoxSubscriptionParser]); otherwise a random id, as for links.
     */
    fun fromOutbound(
        outbound: JSONObject,
        name: String,
        rawLink: String = "",
        dependencies: String = "",
        stableIds: MutableSet<String>? = null
    ): VpnConfig {
        val type = outbound.getString("type")
        // WireGuard keeps its address inside peers[0].
        val peer = outbound.optJSONArray("peers")?.optJSONObject(0)
        val server = outbound.optString("server").ifBlank { peer?.optString("address").orEmpty() }
        val port = outbound.optInt("server_port").takeIf { it != 0 } ?: peer?.optInt("port") ?: 0
        require(server.isNotBlank() && port in 1..65535) { "outbound without server/port" }
        val displayName = name.ifBlank { "$server:$port" }
        val id = if (stableIds != null) stableId(type, displayName, server, port, stableIds)
        else java.util.UUID.randomUUID().toString()
        return VpnConfig(
            id = id,
            name = displayName,
            protocol = when (type) {
                "vless" -> VpnProtocol.VLESS
                "vmess" -> VpnProtocol.VMESS
                "shadowsocks" -> VpnProtocol.SHADOWSOCKS
                "trojan" -> VpnProtocol.TROJAN
                "hysteria2" -> VpnProtocol.HYSTERIA2
                else -> VpnProtocol.OTHER
            },
            address = server,
            port = port,
            rawLink = rawLink,
            rawOutbound = outbound.toString(),
            rawType = type,
            rawDependencies = dependencies
        )
    }

    fun stableId(type: String, tag: String, server: String, port: Int, usedIds: MutableSet<String>): String {
        val digest = MessageDigest.getInstance("SHA-256")
            .digest("$type|$tag|$server|$port".toByteArray(Charsets.UTF_8))
        val base = "sub-" + digest.take(8).joinToString("") { "%02x".format(it) }
        if (usedIds.add(base)) return base
        var n = 2
        while (!usedIds.add("$base-$n")) n++
        return "$base-$n"
    }
}
