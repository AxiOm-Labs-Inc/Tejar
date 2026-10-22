package com.telegram.vpncore

import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import org.yaml.snakeyaml.LoaderOptions
import org.yaml.snakeyaml.Yaml
import org.yaml.snakeyaml.constructor.SafeConstructor

/**
 * Reads a Clash / Mihomo YAML profile and translates its `proxies:` into sing-box outbounds.
 *
 * Only `proxies` matter: groups and rules belong to the client the profile was written for.
 * Entries the core cannot serve are reported, not guessed at; transports only xray has are
 * kept (as JSON of the original entry) for a later xray stage.
 */
object ClashSubscriptionParser {

    private const val TAG = "ClashSubParser"
    private val PROXIES_KEY = Regex("""(?m)^proxies\s*:""")

    fun looksLikeClash(text: String): Boolean = PROXIES_KEY.containsMatchIn(text)

    fun parse(text: String): ParseResult {
        val root = load(text) as? Map<*, *> ?: return ParseResult.EMPTY
        val proxies = root["proxies"] as? List<*> ?: return ParseResult.EMPTY

        val results = ArrayList<VpnConfig>()
        val skipped = ArrayList<SkippedEntry>()
        val usedIds = HashSet<String>()
        for (entry in proxies) {
            val proxy = entry as? Map<*, *>
            if (proxy == null) {
                skipped.add(SkippedEntry(SkippedEntry.INVALID_LINK))
                continue
            }
            val name = proxy.str("name")
            try {
                val outbound = toOutbound(proxy)
                results.add(OutboundConfigs.fromOutbound(outbound, name, stableIds = usedIds))
            } catch (e: UnsupportedEntryException) {
                Log.w(TAG, "Skipping Clash proxy: ${e.reason}")
                skipped.add(
                    SkippedEntry(
                        e.reason, raw = if (e.xrayCapable) toJson(proxy).toString() else "",
                        xrayCapable = e.xrayCapable, source = SkipSource.CLASH_PROXY, name = name
                    )
                )
            } catch (e: Exception) {
                Log.w(TAG, "Skipping invalid Clash proxy: ${e.message}")
                skipped.add(SkippedEntry(SkippedEntry.INVALID_LINK, name = name))
            }
        }
        return ParseResult(results, skipped)
    }

    private fun load(text: String): Any? {
        val options = LoaderOptions().apply {
            // A subscription is untrusted input: bound aliases (billion-laughs), depth and size.
            maxAliasesForCollections = 20
            nestingDepthLimit = 30
            codePointLimit = 8 * 1024 * 1024
            isAllowDuplicateKeys = true
        }
        return Yaml(SafeConstructor(options)).load(text)
    }

    // ─────────────────────────── mapping ───────────────────────────

    private fun toOutbound(p: Map<*, *>): JSONObject {
        val type = p.str("type").lowercase()
        val server = p.str("server")
        val port = p.int("port")
        if (server.isBlank() || port !in 1..65535) throw IllegalArgumentException("no server/port")

        val o = JSONObject()
        o.put("server", server)
        o.put("server_port", port)
        when (type) {
            "ss" -> {
                o.put("type", "shadowsocks")
                o.put("method", p.str("cipher"))
                o.put("password", p.str("password"))
                ssPlugin(p, o)
            }
            "vmess" -> {
                o.put("type", "vmess")
                o.put("uuid", p.str("uuid"))
                o.put("alter_id", p.int("alterId"))
                o.put("security", p.str("cipher").ifBlank { "auto" })
                tls(p, o, enabledByDefault = false)
                transport(p, o)
            }
            "vless" -> {
                o.put("type", "vless")
                o.put("uuid", p.str("uuid"))
                p.str("flow").takeIf { it.isNotBlank() }?.let { o.put("flow", it) }
                p.str("encryption").takeIf { it.isNotBlank() && it != "none" }?.let {
                    throw UnsupportedEntryException(SkippedEntry.needsXray("vless-encryption"), xrayCapable = true)
                }
                p.str("packet-encoding").takeIf { it.isNotBlank() }?.let { o.put("packet_encoding", it) }
                tls(p, o, enabledByDefault = false)
                transport(p, o)
            }
            "trojan" -> {
                o.put("type", "trojan")
                o.put("password", p.str("password"))
                tls(p, o, enabledByDefault = true)
                transport(p, o)
            }
            "hysteria" -> {
                o.put("type", "hysteria")
                val proto = p.str("protocol")
                if (proto.isNotBlank() && !proto.equals("udp", true)) {
                    throw UnsupportedEntryException("unsupported hysteria protocol ${proto.take(16)}")
                }
                p.str("auth-str").ifBlank { p.str("auth_str") }.takeIf { it.isNotBlank() }
                    ?.let { o.put("auth_str", it) }
                p.str("auth").takeIf { it.isNotBlank() }?.let { o.put("auth", it) }
                o.put("up_mbps", mbps(p["up"]))
                o.put("down_mbps", mbps(p["down"]))
                p.str("obfs").takeIf { it.isNotBlank() }?.let { o.put("obfs", it) }
                tls(p, o, enabledByDefault = true, defaultAlpn = listOf("h3"))
            }
            "hysteria2", "hy2" -> {
                o.put("type", "hysteria2")
                o.put("password", p.str("password"))
                val up = mbps(p["up"], 0)
                val down = mbps(p["down"], 0)
                if (up > 0) o.put("up_mbps", up)
                if (down > 0) o.put("down_mbps", down)
                p.str("obfs").takeIf { it.isNotBlank() }?.let {
                    if (it != "salamander") throw UnsupportedEntryException("unsupported hysteria2 obfs ${it.take(16)}")
                    o.put("obfs", JSONObject().put("type", it).put("password", p.str("obfs-password")))
                }
                tls(p, o, enabledByDefault = true)
                // Port hopping: sing-box takes ranges as "20000:30000".
                hopPorts(p.str("ports"))?.let { o.put("server_ports", it) }
                p.str("hop-interval").toIntOrNull()?.takeIf { it > 0 }?.let { o.put("hop_interval", "${it}s") }
            }
            "tuic" -> {
                o.put("type", "tuic")
                if (p.str("uuid").isBlank() || p.str("password").isBlank()) {
                    throw UnsupportedEntryException("unsupported tuic v4")
                }
                o.put("uuid", p.str("uuid"))
                o.put("password", p.str("password"))
                p.str("congestion-controller").ifBlank { p.str("congestion_control") }
                    .takeIf { it.isNotBlank() }?.let { o.put("congestion_control", it) }
                p.str("udp-relay-mode").takeIf { it.isNotBlank() }?.let { o.put("udp_relay_mode", it) }
                if (p.bool("reduce-rtt")) o.put("zero_rtt_handshake", true)
                tls(p, o, enabledByDefault = true, defaultAlpn = listOf("h3"))
            }
            "anytls" -> {
                o.put("type", "anytls")
                o.put("password", p.str("password"))
                tls(p, o, enabledByDefault = true)
            }
            "socks5", "socks" -> {
                if (p.bool("tls")) throw UnsupportedEntryException("unsupported socks5 over tls")
                o.put("type", "socks")
                o.put("version", "5")
                p.str("username").takeIf { it.isNotBlank() }?.let { o.put("username", it) }
                p.str("password").takeIf { it.isNotBlank() }?.let { o.put("password", it) }
            }
            "http" -> {
                o.put("type", "http")
                p.str("username").takeIf { it.isNotBlank() }?.let { o.put("username", it) }
                p.str("password").takeIf { it.isNotBlank() }?.let { o.put("password", it) }
                tls(p, o, enabledByDefault = false)
            }
            "ssh" -> {
                o.put("type", "ssh")
                o.put("user", p.str("username").ifBlank { "root" })
                p.str("password").takeIf { it.isNotBlank() }?.let { o.put("password", it) }
                p.str("private-key").takeIf { it.isNotBlank() }?.let { o.put("private_key", it) }
                p.str("private-key-passphrase").takeIf { it.isNotBlank() }
                    ?.let { o.put("private_key_passphrase", it) }
                (p["host-key"] as? List<*>)?.let { o.put("host_key", JSONArray(it.map { k -> k.toString() })) }
            }
            "wireguard" -> return wireguard(p, server, port)
            else -> throw UnsupportedEntryException("unsupported type ${type.take(24)}")
        }
        return o
    }

    /** "20000-30000,40000" -> ["20000:30000", "40000:40000"]; null when empty. */
    private fun hopPorts(raw: String): JSONArray? = LinkParser.hopPorts(raw)

    private fun ssPlugin(p: Map<*, *>, o: JSONObject) {
        val plugin = p.str("plugin")
        if (plugin.isBlank()) return
        val opts = p.map("plugin-opts")
        val flat = when (plugin) {
            "obfs", "obfs-local", "simple-obfs" -> {
                val parts = mutableListOf<String>()
                opts.str("mode").takeIf { it.isNotBlank() }?.let { parts.add("obfs=$it") }
                opts.str("host").takeIf { it.isNotBlank() }?.let { parts.add("obfs-host=$it") }
                "obfs-local" to parts.joinToString(";")
            }
            "v2ray-plugin" -> {
                val mode = opts.str("mode").ifBlank { "websocket" }
                if (mode != "websocket") throw UnsupportedEntryException("unsupported v2ray-plugin mode ${mode.take(16)}")
                val parts = mutableListOf<String>()
                if (opts.bool("tls")) parts.add("tls")
                opts.str("host").takeIf { it.isNotBlank() }?.let { parts.add("host=$it") }
                opts.str("path").takeIf { it.isNotBlank() }?.let { parts.add("path=$it") }
                if (opts.bool("mux")) parts.add("mux=1")
                "v2ray-plugin" to parts.joinToString(";")
            }
            else -> throw UnsupportedEntryException("unsupported ss plugin ${plugin.take(24)}")
        }
        o.put("plugin", flat.first)
        if (flat.second.isNotEmpty()) o.put("plugin_opts", flat.second)
    }

    private fun tls(p: Map<*, *>, o: JSONObject, enabledByDefault: Boolean, defaultAlpn: List<String> = emptyList()) {
        val enabled = if (p.containsKey("tls")) p.bool("tls") else enabledByDefault
        val reality = p.map("reality-opts")
        val isReality = reality.isNotEmpty()
        if (!enabled && !isReality) return
        val tls = JSONObject().put("enabled", true)
        val sni = p.str("servername").ifBlank { p.str("sni") }
        if (sni.isNotBlank()) tls.put("server_name", sni)
        if (p.bool("skip-cert-verify")) tls.put("insecure", true)
        val alpn = (p["alpn"] as? List<*>)?.map { it.toString() }.orEmpty().ifEmpty { defaultAlpn }
        if (alpn.isNotEmpty()) tls.put("alpn", JSONArray(alpn))
        val fp = p.str("client-fingerprint")
        if (isReality) {
            tls.put("reality", JSONObject().apply {
                put("enabled", true)
                put("public_key", reality.str("public-key"))
                reality.str("short-id").takeIf { it.isNotBlank() }?.let { put("short_id", it) }
            })
            // REALITY needs uTLS; same default the link parser uses.
            tls.put("utls", JSONObject().put("enabled", true).put("fingerprint", fp.ifBlank { "chrome" }))
        } else if (fp.isNotBlank()) {
            tls.put("utls", JSONObject().put("enabled", true).put("fingerprint", fp))
        }
        o.put("tls", tls)
    }

    private fun transport(p: Map<*, *>, o: JSONObject) {
        val network = p.str("network").lowercase()
        val t: JSONObject = when (network) {
            "", "tcp", "raw" -> return
            "ws" -> {
                val ws = p.map("ws-opts")
                if (ws.bool("v2ray-http-upgrade")) {
                    JSONObject().put("type", "httpupgrade").apply {
                        ws.str("path").takeIf { it.isNotBlank() }?.let { put("path", it) }
                        ws.map("headers").str("Host").takeIf { it.isNotBlank() }?.let { put("host", it) }
                    }
                } else JSONObject().put("type", "ws").apply {
                    ws.str("path").takeIf { it.isNotBlank() }?.let { put("path", it) }
                    val headers = ws.map("headers")
                    if (headers.isNotEmpty()) {
                        put("headers", JSONObject().apply { headers.forEach { (k, v) -> put(k.toString(), v.toString()) } })
                    }
                    ws.int("max-early-data").takeIf { it > 0 }?.let { put("max_early_data", it) }
                    ws.str("early-data-header-name").takeIf { it.isNotBlank() }?.let { put("early_data_header_name", it) }
                }
            }
            "grpc" -> JSONObject().put("type", "grpc").apply {
                p.map("grpc-opts").str("grpc-service-name").takeIf { it.isNotBlank() }?.let { put("service_name", it) }
            }
            "h2" -> {
                val h2 = p.map("h2-opts")
                JSONObject().put("type", "http").apply {
                    val hosts = (h2["host"] as? List<*>)?.map { it.toString() }
                        ?: h2.str("host").takeIf { it.isNotBlank() }?.let { listOf(it) }
                    hosts?.let { put("host", JSONArray(it)) }
                    h2.str("path").takeIf { it.isNotBlank() }?.let { put("path", it) }
                }
            }
            // Clash "http" is HTTP header obfuscation over TCP (xray: tcp + headerType=http),
            // not sing-box's "http" transport, which is a different wire format. "h2" below is.
            "http" -> throw UnsupportedEntryException(
                SkippedEntry.needsXray("tcp-http"), xrayCapable = true
            )
            "httpupgrade" -> JSONObject().put("type", "httpupgrade")
            "quic" -> JSONObject().put("type", "quic")
            else -> throw UnsupportedEntryException(
                SkippedEntry.needsXray(network.take(24)), xrayCapable = true
            )
        }
        o.put("transport", t)
    }

    private fun wireguard(p: Map<*, *>, server: String, port: Int): JSONObject {
        val peers = p["peers"] as? List<*>
        val peerSrc = (peers?.firstOrNull() as? Map<*, *>) ?: p
        val addresses = listOf(p.str("ip"), p.str("ipv6")).filter { it.isNotBlank() }.map {
            if (it.contains('/')) it else if (it.contains(':')) "$it/128" else "$it/32"
        }
        require(addresses.isNotEmpty()) { "wireguard without ip" }
        val peer = JSONObject().apply {
            put("address", peerSrc.str("server").ifBlank { server })
            put("port", peerSrc.int("port").takeIf { it > 0 } ?: port)
            put("public_key", peerSrc.str("public-key"))
            peerSrc.str("pre-shared-key").takeIf { it.isNotBlank() }?.let { put("pre_shared_key", it) }
            val allowed = (peerSrc["allowed-ips"] as? List<*>)?.map { it.toString() }
                ?: listOf("0.0.0.0/0", "::/0")
            put("allowed_ips", JSONArray(allowed))
            reserved(peerSrc["reserved"] ?: p["reserved"])?.let { put("reserved", it) }
        }
        return JSONObject().apply {
            put("type", "wireguard")
            put("address", JSONArray(addresses))
            put("private_key", p.str("private-key"))
            p.int("mtu").takeIf { it > 0 }?.let { put("mtu", it) }
            put("peers", JSONArray().put(peer))
        }
    }

    private fun reserved(v: Any?): JSONArray? = when (v) {
        is List<*> -> JSONArray(v.map { (it as? Number)?.toInt() ?: it.toString().toInt() })
        is String -> v.split(',').map { it.trim().toInt() }.let { JSONArray(it) }
        else -> null
    }

    /** "100 Mbps", 100 or "100" -> 100; falls back to [default] when absent. */
    private fun mbps(v: Any?, default: Int = 100): Int {
        val n = when (v) {
            is Number -> v.toInt()
            is String -> Regex("""\d+""").find(v)?.value?.toIntOrNull() ?: 0
            else -> 0
        }
        return if (n > 0) n else default
    }

    // ─────────────────────────── helpers ───────────────────────────

    private fun Map<*, *>.str(key: String): String = this[key]?.toString().orEmpty()
    private fun Map<*, *>.int(key: String): Int = when (val v = this[key]) {
        is Number -> v.toInt()
        is String -> v.trim().toIntOrNull() ?: 0
        else -> 0
    }
    private fun Map<*, *>.bool(key: String): Boolean = when (val v = this[key]) {
        is Boolean -> v
        is String -> v.equals("true", true) || v == "1"
        is Number -> v.toInt() != 0
        else -> false
    }
    private fun Map<*, *>.map(key: String): Map<*, *> = this[key] as? Map<*, *> ?: emptyMap<Any, Any>()

    private fun toJson(v: Any?): Any = when (v) {
        is Map<*, *> -> JSONObject().also { j -> v.forEach { (k, x) -> j.put(k.toString(), toJson(x)) } }
        is List<*> -> JSONArray().also { a -> v.forEach { a.put(toJson(it)) } }
        null -> JSONObject.NULL
        else -> v
    }
}
