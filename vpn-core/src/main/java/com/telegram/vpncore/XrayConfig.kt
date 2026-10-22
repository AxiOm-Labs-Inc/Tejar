package com.telegram.vpncore

import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest

/** Where sing-box reaches one xray server: a local SOCKS inbound with its own credentials. */
data class XrayEndpoint(val port: Int, val user: String, val pass: String)

/**
 * Builds the config for the single xray process that serves every xray-type server.
 *
 * Each server gets its own SOCKS inbound on 127.0.0.1 routed to exactly its outbound, so
 * sing-box can list, switch and latency-test xray servers like any other.
 */
object XrayConfigBuilder {

    /** DNS used by xray itself; explicit because linux/arm32 builds have no resolv.conf on Android. */
    val DNS_SERVERS = listOf("1.1.1.1", "8.8.8.8", "77.88.8.8")

    fun isXray(config: VpnConfig) = config.rawType == OutboundConfigs.XRAY_TYPE && config.rawOutbound.isNotBlank()

    /** Changes whenever the process would need different inbounds or outbounds. */
    fun signature(servers: List<VpnConfig>): String {
        val digest = MessageDigest.getInstance("SHA-256")
        servers.filter(::isXray).sortedBy { it.id }.forEach {
            digest.update("${it.id}|${it.rawOutbound}\n".toByteArray(Charsets.UTF_8))
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    /** [endpoints] by server id; servers without one are left out. */
    fun build(servers: List<VpnConfig>, endpoints: Map<String, XrayEndpoint>): String {
        val inbounds = JSONArray()
        val outbounds = JSONArray()
        val rules = JSONArray()
        servers.filter(::isXray).forEach { server ->
            val ep = endpoints[server.id] ?: return@forEach
            val n = inbounds.length()
            inbounds.put(JSONObject().apply {
                put("tag", "in-$n")
                put("listen", "127.0.0.1")
                put("port", ep.port)
                put("protocol", "socks")
                put("settings", JSONObject().apply {
                    put("auth", "password")
                    put("accounts", JSONArray().put(JSONObject().put("user", ep.user).put("pass", ep.pass)))
                    put("udp", true)
                    put("ip", "127.0.0.1")
                })
            })
            outbounds.put(outboundFor(server, "out-$n"))
            rules.put(
                JSONObject().put("type", "field")
                    .put("inboundTag", JSONArray().put("in-$n")).put("outboundTag", "out-$n")
            )
        }
        require(inbounds.length() > 0) { "No xray servers to run" }
        return JSONObject().apply {
            put("log", JSONObject().put("loglevel", "warning"))
            put("dns", JSONObject().put("servers", JSONArray(DNS_SERVERS)))
            put("inbounds", inbounds)
            put("outbounds", outbounds)
            put("routing", JSONObject().put("domainStrategy", "AsIs").put("rules", rules))
        }.toString(2)
    }

    /** The server's xray outbound with our tag and IPv4-only name resolution. */
    fun outboundFor(server: VpnConfig, tag: String): JSONObject {
        val o = JSONObject(server.rawOutbound)
        o.put("tag", tag)
        val stream = o.optJSONObject("streamSettings") ?: JSONObject().also { o.put("streamSettings", it) }
        val sockopt = stream.optJSONObject("sockopt") ?: JSONObject().also { stream.put("sockopt", it) }
        sockopt.put("domainStrategy", "UseIPv4")
        return o
    }

    /** sing-box outbound that dials this server through its local xray inbound. */
    fun socksOutbound(tag: String, endpoint: XrayEndpoint): JSONObject = JSONObject().apply {
        put("type", "socks")
        put("tag", tag)
        put("server", "127.0.0.1")
        put("server_port", endpoint.port)
        put("version", "5")
        put("username", endpoint.user)
        put("password", endpoint.pass)
    }
}
