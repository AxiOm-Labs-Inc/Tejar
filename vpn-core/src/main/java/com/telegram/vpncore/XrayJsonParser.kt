package com.telegram.vpncore

import android.util.Log
import org.json.JSONArray
import org.json.JSONObject

/**
 * Reads xray-format JSON subscriptions: one xray config (`{"outbounds":[...]}`) or an array of
 * full configs, one per server, with a `remarks` name each (the "v2ray-json" layout Marzban
 * and Remnawave serve). Proxy outbounds are translated to sing-box outbounds.
 *
 * Xray features the core lacks (xhttp, mKCP, TCP HTTP obfuscation, dialerProxy chains) are
 * skipped as xray-capable with the original outbound JSON kept, for a later xray stage.
 */
object XrayJsonParser {

    private const val TAG = "XrayJsonParser"
    private val PROXY_PROTOCOLS = setOf("vless", "vmess", "trojan", "shadowsocks", "socks", "http")

    /** Xray configs name outbounds by `protocol`; sing-box ones by `type`. */
    fun looksLikeXray(text: String): Boolean {
        val trimmed = text.trimStart()
        return try {
            when {
                trimmed.startsWith("[") -> JSONArray(trimmed).optJSONObject(0)?.let { hasXrayOutbounds(it) } ?: false
                trimmed.startsWith("{") -> hasXrayOutbounds(JSONObject(trimmed))
                else -> false
            }
        } catch (_: Exception) {
            false
        }
    }

    private fun hasXrayOutbounds(config: JSONObject): Boolean {
        val outbounds = config.optJSONArray("outbounds") ?: return false
        for (i in 0 until outbounds.length()) {
            val o = outbounds.optJSONObject(i) ?: continue
            if (o.has("protocol") && !o.has("type")) return true
        }
        return false
    }

    fun parse(text: String): ParseResult {
        val trimmed = text.trim()
        val configs = if (trimmed.startsWith("[")) {
            val arr = JSONArray(trimmed)
            (0 until arr.length()).mapNotNull { arr.optJSONObject(it) }
        } else listOf(JSONObject(trimmed))

        val results = ArrayList<VpnConfig>()
        val skipped = ArrayList<SkippedEntry>()
        val usedIds = HashSet<String>()
        for (config in configs) {
            val outbounds = config.optJSONArray("outbounds") ?: continue
            val candidates = (0 until outbounds.length()).mapNotNull { outbounds.optJSONObject(it) }
                .filter { it.optString("protocol") in PROXY_PROTOCOLS }
            val remarks = config.optString("remarks")
            for (ob in candidates) {
                val name = if (candidates.size == 1 && remarks.isNotBlank()) remarks
                else ob.optString("tag").takeIf { it.isNotBlank() && it != "proxy" } ?: remarks
                try {
                    results.add(OutboundConfigs.fromOutbound(toOutbound(ob), name, stableIds = usedIds))
                } catch (e: UnsupportedEntryException) {
                    Log.w(TAG, "Skipping xray outbound: ${e.reason}")
                    skipped.add(
                        SkippedEntry(
                            e.reason, raw = if (e.xrayCapable) ob.toString() else "",
                            xrayCapable = e.xrayCapable, source = SkipSource.XRAY_OUTBOUND, name = name
                        )
                    )
                } catch (e: Exception) {
                    Log.w(TAG, "Skipping invalid xray outbound: ${e.message}")
                    skipped.add(SkippedEntry(SkippedEntry.INVALID_LINK, name = name))
                }
            }
        }
        return ParseResult(results, skipped)
    }

    private fun toOutbound(ob: JSONObject): JSONObject {
        val protocol = ob.getString("protocol")
        val settings = ob.optJSONObject("settings") ?: JSONObject()
        val stream = ob.optJSONObject("streamSettings") ?: JSONObject()
        if (stream.optJSONObject("sockopt")?.optString("dialerProxy").orEmpty().isNotBlank()) {
            throw UnsupportedEntryException(SkippedEntry.needsXray("dialerProxy"), xrayCapable = true)
        }

        val o = JSONObject()
        when (protocol) {
            "vless", "vmess" -> {
                val hop = settings.optJSONArray("vnext")?.optJSONObject(0) ?: settings
                val user = hop.optJSONArray("users")?.optJSONObject(0) ?: hop
                o.put("type", protocol)
                endpoint(o, hop)
                o.put("uuid", user.getString("id"))
                if (protocol == "vless") {
                    user.optString("flow").takeIf { it.isNotBlank() }?.let { o.put("flow", it) }
                    user.optString("encryption").takeIf { it.isNotBlank() && it != "none" }?.let {
                        throw UnsupportedEntryException(SkippedEntry.needsXray("vless-encryption"), xrayCapable = true)
                    }
                } else {
                    o.put("alter_id", user.optInt("alterId", 0))
                    o.put("security", user.optString("security").ifBlank { "auto" })
                }
            }
            "trojan", "shadowsocks" -> {
                val hop = settings.optJSONArray("servers")?.optJSONObject(0) ?: settings
                o.put("type", protocol)
                endpoint(o, hop)
                o.put("password", hop.getString("password"))
                if (protocol == "shadowsocks") o.put("method", hop.getString("method"))
            }
            "socks", "http" -> {
                val hop = settings.optJSONArray("servers")?.optJSONObject(0) ?: settings
                o.put("type", protocol)
                endpoint(o, hop)
                if (protocol == "socks") o.put("version", "5")
                hop.optJSONArray("users")?.optJSONObject(0)?.let { u ->
                    u.optString("user").takeIf { it.isNotBlank() }?.let { o.put("username", it) }
                    u.optString("pass").takeIf { it.isNotBlank() }?.let { o.put("password", it) }
                }
            }
            else -> throw UnsupportedEntryException("unsupported type ${protocol.take(24)}")
        }
        applyStream(stream, o, trojanDefaultsToTls = protocol == "trojan")
        return o
    }

    private fun endpoint(o: JSONObject, hop: JSONObject) {
        o.put("server", hop.getString("address"))
        val port = hop.optInt("port")
        require(port in 1..65535) { "bad port" }
        o.put("server_port", port)
    }

    private fun applyStream(stream: JSONObject, o: JSONObject, trojanDefaultsToTls: Boolean) {
        val network = stream.optString("network").ifBlank { "tcp" }.lowercase()
        val security = stream.optString("security").ifBlank { if (trojanDefaultsToTls) "tls" else "none" }.lowercase()

        // TLS / REALITY
        if (security == "tls" || security == "reality") {
            val tls = JSONObject().put("enabled", true)
            val s = stream.optJSONObject(if (security == "tls") "tlsSettings" else "realitySettings") ?: JSONObject()
            s.optString("serverName").takeIf { it.isNotBlank() }?.let { tls.put("server_name", it) }
            if (s.optBoolean("allowInsecure", false)) tls.put("insecure", true)
            s.optJSONArray("alpn")?.takeIf { it.length() > 0 }?.let { tls.put("alpn", it) }
            val fp = s.optString("fingerprint")
            if (security == "reality") {
                tls.put("reality", JSONObject().apply {
                    put("enabled", true)
                    put("public_key", s.optString("publicKey"))
                    s.optString("shortId").takeIf { it.isNotBlank() }?.let { put("short_id", it) }
                })
                tls.put("utls", JSONObject().put("enabled", true).put("fingerprint", fp.ifBlank { "chrome" }))
            } else if (fp.isNotBlank()) {
                tls.put("utls", JSONObject().put("enabled", true).put("fingerprint", fp))
            }
            o.put("tls", tls)
        } else if (security != "none") {
            throw UnsupportedEntryException(SkippedEntry.needsXray("security-$security".take(32)), xrayCapable = true)
        }

        // Transport
        val transport: JSONObject? = when (network) {
            "tcp", "raw" -> {
                val header = stream.optJSONObject("tcpSettings")?.optJSONObject("header")
                    ?: stream.optJSONObject("rawSettings")?.optJSONObject("header")
                if (header?.optString("type").equals("http", ignoreCase = true)) {
                    throw UnsupportedEntryException(SkippedEntry.needsXray("tcp-http"), xrayCapable = true)
                }
                null
            }
            "ws" -> {
                val ws = stream.optJSONObject("wsSettings") ?: JSONObject()
                JSONObject().put("type", "ws").apply {
                    ws.optString("path").takeIf { it.isNotBlank() }?.let { put("path", it) }
                    val host = ws.optJSONObject("headers")?.optString("Host").orEmpty().ifBlank { ws.optString("host") }
                    if (host.isNotBlank()) put("headers", JSONObject().put("Host", host))
                }
            }
            "grpc" -> JSONObject().put("type", "grpc").apply {
                stream.optJSONObject("grpcSettings")?.optString("serviceName")?.takeIf { it.isNotBlank() }
                    ?.let { put("service_name", it) }
            }
            "httpupgrade" -> {
                val hu = stream.optJSONObject("httpupgradeSettings") ?: JSONObject()
                JSONObject().put("type", "httpupgrade").apply {
                    hu.optString("path").takeIf { it.isNotBlank() }?.let { put("path", it) }
                    hu.optString("host").takeIf { it.isNotBlank() }?.let { put("host", it) }
                }
            }
            "h2", "http" -> {
                val h = stream.optJSONObject("httpSettings") ?: JSONObject()
                JSONObject().put("type", "http").apply {
                    h.optJSONArray("host")?.let { put("host", it) }
                    h.optString("path").takeIf { it.isNotBlank() }?.let { put("path", it) }
                }
            }
            "quic" -> JSONObject().put("type", "quic")
            else -> throw UnsupportedEntryException(SkippedEntry.needsXray(network.take(24)), xrayCapable = true)
        }
        transport?.let { o.put("transport", it) }
    }
}
