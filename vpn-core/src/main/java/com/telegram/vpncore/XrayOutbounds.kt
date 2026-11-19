package com.telegram.vpncore

import org.json.JSONArray
import org.json.JSONObject

/**
 * Builds xray outbound objects for entries sing-box cannot serve (xhttp, mKCP, TCP HTTP
 * header obfuscation, VLESS encryption...). They are run by the bundled xray process (see
 * [XrayProcess]); sing-box reaches each through a local SOCKS inbound.
 *
 * Sources are share links, Clash proxy entries (as JSON) and xray outbounds from xray-format
 * subscriptions. Every function throws on input it cannot express; the caller then keeps the
 * entry skipped.
 */
object XrayOutbounds {

    private val XHTTP_MODES = setOf("auto", "packet-up", "stream-up", "stream-one")

    // ───────────────────────────── links ─────────────────────────────

    fun fromLink(link: String): JSONObject {
        val trimmed = link.trim()
        return when {
            trimmed.startsWith("vless://", true) -> fromUriLink("vless", ParsedLink.parse(trimmed))
            trimmed.startsWith("trojan://", true) -> fromUriLink("trojan", ParsedLink.parse(trimmed))
            trimmed.startsWith("vmess://", true) -> fromVmessLink(trimmed)
            else -> throw IllegalArgumentException("no xray mapping for this scheme")
        }
    }

    private fun fromUriLink(protocol: String, uri: ParsedLink): JSONObject {
        val secret = uri.userInfo ?: throw IllegalArgumentException("missing credentials")
        val host = uri.host ?: throw IllegalArgumentException("missing host")
        val port = uri.port.takeIf { it in 1..65535 } ?: throw IllegalArgumentException("invalid port")
        fun q(name: String) = uri.queryParam(name)?.takeIf { it.isNotEmpty() }

        val security = q("security")?.lowercase() ?: if (protocol == "trojan") "tls" else "none"
        val stream = stream(
            network = q("type") ?: "tcp", security = security,
            sni = q("sni") ?: q("peer"), host = q("host"), path = q("path"),
            fingerprint = q("fp"), alpn = q("alpn"), pinnedCertSha256 = q("pcs"), verifyCertByName = q("vcn"),
            publicKey = q("pbk"), shortId = q("sid"), spiderX = q("spx"),
            serviceName = q("serviceName"), headerType = q("headerType"), seed = q("seed"),
            mode = q("mode"), extra = q("extra"),
            finalmask = q("fm"), mtu = q("mtu"), tti = q("tti")
        )
        val settings = JSONObject()
        if (protocol == "vless") {
            val user = JSONObject().put("id", secret).put("encryption", q("encryption") ?: "none")
            q("flow")?.let { user.put("flow", it) }
            settings.put("vnext", JSONArray().put(vnext(host, port, user)))
        } else {
            settings.put("servers", JSONArray().put(
                JSONObject().put("address", host).put("port", port).put("password", secret)
            ))
        }
        return JSONObject().put("protocol", protocol).put("settings", settings).put("streamSettings", stream)
    }

    private fun fromVmessLink(link: String): JSONObject {
        val encoded = link.substring("vmess://".length).substringBefore('#')
        val j = JSONObject(LenientBase64.decodeToString(encoded) ?: throw IllegalArgumentException("not base64"))
        fun s(name: String) = j.optString(name).takeIf { it.isNotEmpty() }
        val host = s("add") ?: throw IllegalArgumentException("missing add")
        val port = (j.optString("port").toIntOrNull() ?: j.optInt("port")).takeIf { it in 1..65535 }
            ?: throw IllegalArgumentException("invalid port")
        val net = s("net") ?: "tcp"
        val stream = stream(
            network = net, security = if (s("tls") == "tls") "tls" else "none",
            sni = s("sni") ?: s("host"), host = s("host"), path = s("path"),
            fingerprint = s("fp"), alpn = s("alpn"),
            pinnedCertSha256 = s("pcs"), verifyCertByName = s("vcn"),
            publicKey = null, shortId = null, spiderX = null,
            serviceName = if (net == "grpc") s("path") else null,
            headerType = s("type"), seed = if (net == "kcp") s("path") else null,
            mode = if (net == "xhttp" || net == "splithttp") s("type") else null, extra = null
        )
        val user = JSONObject().put("id", s("id") ?: throw IllegalArgumentException("missing id"))
            .put("alterId", j.optString("aid").toIntOrNull() ?: j.optInt("aid", 0))
            .put("security", s("scy") ?: "auto")
        return JSONObject().put("protocol", "vmess")
            .put("settings", JSONObject().put("vnext", JSONArray().put(vnext(host, port, user))))
            .put("streamSettings", stream)
    }

    /** The display name a link carries (vmess keeps it in the JSON, the rest in the fragment). */
    fun nameOfLink(link: String): String {
        val t = link.trim()
        if (t.startsWith("vmess://", true)) {
            return runCatching {
                JSONObject(LenientBase64.decodeToString(t.substring(8).substringBefore('#')) ?: "").optString("ps")
            }.getOrDefault("")
        }
        return ParsedLink.parse(t).fragment.orEmpty()
    }

    // ───────────────────────────── Clash ─────────────────────────────

    /** [proxy] is the Clash entry converted to JSON (as kept in [SkippedEntry.raw]). */
    fun fromClash(proxy: JSONObject): JSONObject {
        val type = proxy.optString("type").lowercase()
        val host = proxy.optString("server").takeIf { it.isNotEmpty() } ?: throw IllegalArgumentException("server")
        val port = proxy.optString("port").toIntOrNull()?.takeIf { it in 1..65535 }
            ?: throw IllegalArgumentException("port")
        fun s(name: String) = proxy.optString(name).takeIf { it.isNotEmpty() }
        val network = (s("network") ?: "tcp").lowercase()
        val reality = proxy.optJSONObject("reality-opts")
        val tls = proxy.optBoolean("tls", type == "trojan") || reality != null

        val ws = proxy.optJSONObject("ws-opts")
        val xhttp = proxy.optJSONObject("xhttp-opts")
        val http = proxy.optJSONObject("http-opts")
        val h2 = proxy.optJSONObject("h2-opts")
        val path = when (network) {
            "ws" -> ws?.optString("path")
            "xhttp", "splithttp" -> xhttp?.optString("path")
            "h2" -> h2?.optString("path")
            "http" -> http?.optJSONArray("path")?.optString(0) ?: http?.optString("path")
            else -> null
        }?.takeIf { it.isNotEmpty() }
        val hostHeader = when (network) {
            "ws" -> ws?.optJSONObject("headers")?.optString("Host")
            "xhttp", "splithttp" -> xhttp?.optString("host")
            "h2" -> h2?.optJSONArray("host")?.optString(0) ?: h2?.optString("host")
            "http" -> http?.optJSONObject("headers")?.optJSONArray("Host")?.optString(0)
            else -> null
        }?.takeIf { it.isNotEmpty() }

        val stream = stream(
            network = if (network == "http") "tcp" else network,
            security = if (reality != null) "reality" else if (tls) "tls" else "none",
            sni = s("servername") ?: s("sni"), host = hostHeader, path = path,
            fingerprint = s("client-fingerprint"),
            alpn = proxy.optJSONArray("alpn")?.let { a -> (0 until a.length()).joinToString(",") { a.getString(it) } },
            publicKey = reality?.optString("public-key"), shortId = reality?.optString("short-id"),
            spiderX = null,
            serviceName = proxy.optJSONObject("grpc-opts")?.optString("grpc-service-name"),
            headerType = if (network == "http") "http" else null, seed = null,
            mode = xhttp?.optString("mode")?.takeIf { it.isNotEmpty() },
            extra = xhttp?.optJSONObject("extra")?.toString()
        )
        val settings = JSONObject()
        when (type) {
            "vless" -> {
                val user = JSONObject().put("id", s("uuid") ?: throw IllegalArgumentException("uuid"))
                    .put("encryption", s("encryption") ?: "none")
                s("flow")?.let { user.put("flow", it) }
                settings.put("vnext", JSONArray().put(vnext(host, port, user)))
            }
            "vmess" -> {
                val user = JSONObject().put("id", s("uuid") ?: throw IllegalArgumentException("uuid"))
                    .put("alterId", proxy.optInt("alterId", 0)).put("security", s("cipher") ?: "auto")
                settings.put("vnext", JSONArray().put(vnext(host, port, user)))
            }
            "trojan" -> settings.put("servers", JSONArray().put(
                JSONObject().put("address", host).put("port", port)
                    .put("password", s("password") ?: throw IllegalArgumentException("password"))
            ))
            else -> throw IllegalArgumentException("no xray mapping for Clash type")
        }
        return JSONObject().put("protocol", type).put("settings", settings).put("streamSettings", stream)
    }

    // ───────────────────────── xray subscriptions ─────────────────────────

    /**
     * An outbound taken from an xray-format subscription, made standalone: the tag, source
     * address and mux are dropped. Chains through another outbound (dialerProxy, proxySettings)
     * cannot be reproduced here, so they are refused rather than silently sent direct.
     */
    fun sanitize(outbound: JSONObject): JSONObject {
        val o = JSONObject(outbound.toString())
        if (o.has("proxySettings") ||
            o.optJSONObject("streamSettings")?.optJSONObject("sockopt")?.optString("dialerProxy").orEmpty().isNotEmpty()
        ) throw IllegalArgumentException("chained outbound")
        o.remove("tag"); o.remove("sendThrough"); o.remove("mux")
        // Panels still serving the pre-26 mKCP layout: header/seed moved to finalmask.
        o.optJSONObject("streamSettings")?.let { st ->
            val kcp = st.optJSONObject("kcpSettings")
            if (kcp != null && (kcp.has("header") || kcp.has("seed")) && !st.has("finalmask")) {
                st.put("finalmask", kcpFinalmask(
                    kcp.optJSONObject("header")?.optString("type")?.takeIf { it.isNotEmpty() },
                    kcp.optString("seed").takeIf { it.isNotEmpty() },
                    kcp.optJSONObject("header")?.optString("domain")?.takeIf { it.isNotEmpty() }
                ))
            }
            kcp?.remove("header"); kcp?.remove("seed")
        }
        o.optJSONObject("streamSettings")?.optJSONObject("sockopt")?.let {
            it.remove("dialerProxy")
        }
        return migrate(o)
    }

    /**
     * Brings an outbound written for an older xray up to date, in place: mKCP mask ids and
     * "allowInsecure" (see [migrateFinalmask], [migrateTls]). Also applied to stored servers
     * when the process config is built, so servers saved by earlier versions keep working.
     */
    fun migrate(outbound: JSONObject): JSONObject {
        outbound.optJSONObject("streamSettings")?.let { st ->
            st.optJSONObject("finalmask")?.let { migrateFinalmask(it) }
            st.optJSONObject("tlsSettings")?.let { migrateTls(it) }
        }
        return outbound
    }

    /**
     * xray refuses VLESS (without VLESS encryption) and Trojan without TLS/REALITY to a public
     * address, and one such outbound fails the whole process config. Mirrors xray's
     * `validateOutboundTransportSecurity` so such servers can be left out individually.
     */
    fun refusesPlaintext(outbound: JSONObject): Boolean {
        val protocol = outbound.optString("protocol").lowercase()
        if (protocol != "vless" && protocol != "trojan") return false
        val security = outbound.optJSONObject("streamSettings")?.optString("security").orEmpty().lowercase()
        if (security.isNotEmpty() && security != "none") return false
        if (protocol == "vless") {
            val settings = outbound.optJSONObject("settings") ?: JSONObject()
            val encryption = settings.optJSONArray("vnext")?.optJSONObject(0)?.optJSONArray("users")
                ?.optJSONObject(0)?.optString("encryption") ?: settings.optString("encryption")
            if (encryption.isNotEmpty() && encryption != "none") return false
        }
        val address = runCatching { endpointOf(outbound).first }.getOrNull() ?: return true
        return !isPrivateAddress(address)
    }

    private val PRIVATE_SUFFIXES = listOf("lan", "localdomain", "example", "invalid", "localhost", "test", "local", "home.arpa", "internal")

    /** xray's private IP / domain test, for literals and names only (no DNS lookup). */
    internal fun isPrivateAddress(address: String): Boolean {
        val a = address.trim().trimEnd('.').removePrefix("[").removeSuffix("]").lowercase()
        val v4 = a.split('.').takeIf { p -> p.size == 4 && p.all { it.toIntOrNull() in 0..255 } }?.map { it.toInt() }
        if (v4 != null) {
            return v4[0] == 10 || v4[0] == 127 || (v4[0] == 172 && v4[1] in 16..31) ||
                (v4[0] == 192 && v4[1] == 168) || (v4[0] == 169 && v4[1] == 254)
        }
        if (':' in a) {
            val ip = runCatching { java.net.InetAddress.getByName(a) }.getOrNull() ?: return false
            val first = ip.address[0].toInt() and 0xff
            return ip.isLoopbackAddress || ip.isLinkLocalAddress || (first and 0xfe) == 0xfc
        }
        if ('.' !in a) return true // dotless names are local
        return PRIVATE_SUFFIXES.any { a == it || a.endsWith(".$it") }
    }

    // ───────────────────────────── shared ─────────────────────────────

    /** The server's address and port, wherever the outbound's settings keep them. */
    fun endpointOf(outbound: JSONObject): Pair<String, Int> {
        val settings = outbound.optJSONObject("settings") ?: JSONObject()
        val hop = settings.optJSONArray("vnext")?.optJSONObject(0)
            ?: settings.optJSONArray("servers")?.optJSONObject(0) ?: settings
        val address = hop.optString("address")
        val port = hop.optInt("port")
        require(address.isNotBlank() && port in 1..65535) { "outbound without address/port" }
        return address to port
    }

    /**
     * mKCP header and seed as UDP finalmask layers. Since xray 26.10 they are both
     * "mkcp-legacy" masks: the header next to the wire, then the cipher (the old default
     * "original", or AES-GCM when a seed was set) around the KCP payload.
     */
    private fun kcpFinalmask(headerType: String?, seed: String?, domain: String?): JSONObject {
        val masks = JSONArray()
        when (val h = headerType?.lowercase() ?: "none") {
            "none" -> {}
            "srtp", "utp", "dtls", "wireguard" -> masks.put(legacyMask(h, null))
            "wechat-video" -> masks.put(legacyMask("wechat", null))
            "dns" -> masks.put(legacyMask("dns", domain))
            else -> throw IllegalArgumentException("unknown mKCP header")
        }
        masks.put(legacyMask(null, seed))
        return JSONObject().put("udp", masks)
    }

    private fun legacyMask(header: String?, value: String?) = JSONObject().put("type", "mkcp-legacy")
        .put("settings", JSONObject().apply {
            header?.let { put("header", it) }
            value?.let { put("value", it) }
        })

    /**
     * Rewrites xray 26.3–26.9 mKCP mask ids (header-*, mkcp-original, mkcp-aes128gcm), which
     * newer xray rejects, as the equivalent "mkcp-legacy" masks. The wire format is the same.
     */
    private fun migrateFinalmask(finalmask: JSONObject): JSONObject {
        val udp = finalmask.optJSONArray("udp") ?: return finalmask
        for (i in 0 until udp.length()) {
            val mask = udp.optJSONObject(i) ?: continue
            val settings = mask.optJSONObject("settings")
            val replacement = when (val type = mask.optString("type").lowercase()) {
                "mkcp-original" -> legacyMask(null, null)
                "mkcp-aes128gcm" -> legacyMask(null, settings?.optString("password")?.takeIf { it.isNotEmpty() })
                "header-dns" -> legacyMask("dns", settings?.optString("domain")?.takeIf { it.isNotEmpty() })
                "header-dtls", "header-srtp", "header-utp", "header-wechat", "header-wireguard" ->
                    legacyMask(type.removePrefix("header-"), null)
                else -> null
            }
            replacement?.let { udp.put(i, it) }
        }
        return finalmask
    }

    /**
     * xray removed "allowInsecure" (a config holding it fails to load, taking every xray
     * server down with it). The replacements are pinning the certificate hash ("pcs") or
     * accepting another name ("vcn"); without them the server gets normal verification.
     */
    private fun migrateTls(tls: JSONObject) {
        tls.remove("allowInsecure")
    }

    private fun vnext(host: String, port: Int, user: JSONObject) =
        JSONObject().put("address", host).put("port", port).put("users", JSONArray().put(user))

    private fun isTrue(v: String?) = v == "1" || v.equals("true", ignoreCase = true)

    private fun stream(
        network: String, security: String, sni: String?, host: String?, path: String?,
        fingerprint: String?, alpn: String?, pinnedCertSha256: String? = null, verifyCertByName: String? = null,
        publicKey: String?, shortId: String?, spiderX: String?,
        serviceName: String?, headerType: String?, seed: String?, mode: String?, extra: String?,
        finalmask: String? = null, mtu: String? = null, tti: String? = null
    ): JSONObject {
        val s = JSONObject()
        val net = when (val n = network.lowercase()) {
            "", "tcp", "raw" -> "tcp"
            "kcp", "mkcp" -> "kcp"
            "ws", "grpc", "httpupgrade" -> n
            "h2", "http" -> "h2"
            "xhttp", "splithttp" -> "xhttp"
            else -> throw IllegalArgumentException("no xray mapping for transport")
        }
        s.put("network", net)
        s.put("security", security)

        when (security) {
            "tls" -> s.put("tlsSettings", JSONObject().apply {
                sni?.let { put("serverName", it) }
                pinnedCertSha256?.let { put("pinnedPeerCertSha256", it) }
                verifyCertByName?.let { put("verifyPeerCertByName", it) }
                alpn?.split(',')?.map { it.trim() }?.filter { it.isNotEmpty() }?.takeIf { it.isNotEmpty() }
                    ?.let { put("alpn", JSONArray(it)) }
                fingerprint?.let { put("fingerprint", it) }
            })
            "reality" -> s.put("realitySettings", JSONObject().apply {
                sni?.let { put("serverName", it) }
                put("fingerprint", fingerprint ?: "chrome")
                put("publicKey", publicKey.orEmpty())
                shortId?.takeIf { it.isNotEmpty() }?.let { put("shortId", it) }
                spiderX?.takeIf { it.isNotEmpty() }?.let { put("spiderX", it) }
            })
            "none" -> {}
            else -> throw IllegalArgumentException("unsupported security")
        }

        when (net) {
            "tcp" -> if (headerType.equals("http", ignoreCase = true)) {
                val request = JSONObject().put("version", "1.1").put("method", "GET")
                    .put("path", JSONArray(listOf(path ?: "/")))
                host?.let { request.put("headers", JSONObject().put("Host", JSONArray(it.split(',').map(String::trim)))) }
                s.put("tcpSettings", JSONObject().put("header", JSONObject().put("type", "http").put("request", request)))
            }
            "ws" -> s.put("wsSettings", JSONObject().apply {
                path?.let { put("path", it) }
                host?.let { put("headers", JSONObject().put("Host", it)) }
            })
            "grpc" -> s.put("grpcSettings", JSONObject().apply {
                serviceName?.let { put("serviceName", it) }
                if (mode == "multi") put("multiMode", true)
            })
            "httpupgrade" -> s.put("httpupgradeSettings", JSONObject().apply {
                path?.let { put("path", it) }
                host?.let { put("host", it) }
            })
            "h2" -> s.put("httpSettings", JSONObject().apply {
                path?.let { put("path", it) }
                host?.let { put("host", JSONArray(it.split(',').map(String::trim))) }
            })
            "xhttp" -> s.put("xhttpSettings", JSONObject().apply {
                path?.let { put("path", it) }
                host?.let { put("host", it) }
                put("mode", mode?.takeIf { it in XHTTP_MODES } ?: "auto")
                extra?.let { put("extra", JSONObject(it)) }
            })
            "kcp" -> {
                s.put("kcpSettings", JSONObject().apply {
                    mtu?.toIntOrNull()?.let { put("mtu", it) }
                    tti?.toIntOrNull()?.let { put("tti", it) }
                })
                // Since xray 26.x the mKCP header and seed are UDP "finalmask" layers: the header
                // sits next to the wire, the cipher (the old default "original", or AES-GCM
                // when a seed was set) wraps the KCP payload.
                if (finalmask == null) s.put("finalmask", kcpFinalmask(headerType, seed, host))
            }
        }
        // `fm` share-link parameter: the finalmask object, as JSON.
        finalmask?.let { s.put("finalmask", migrateFinalmask(JSONObject(it))) }
        return s
    }
}
