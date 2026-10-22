package com.telegram.vpncore

import org.json.JSONArray
import org.json.JSONObject

/**
 * Parses VPN share links into VpnConfig objects.
 *
 * Splitting and base64 are done by [ParsedLink] and [LenientBase64] rather than the platform
 * classes: real-world links break strict URI parsers, and the parsers stay JVM-testable.
 *
 * Supported formats:
 *  - VLESS:  vless://UUID@host:port?type=...&security=...#name
 *  - VMess:  vmess://BASE64(json) — v2rayN format
 *  - SS:     ss://BASE64(method:password)@host:port#name
 *             or ss://BASE64(method:password@host:port)#name (legacy)
 *  - Trojan: trojan://password@host:port?sni=...#name
 *  - Hy2:    hysteria2://password@host:port?obfs=salamander&obfs-password=...&sni=...#name
 *             (hy2:// is accepted as an alias)
 *  - TUIC, Hysteria v1, AnyTLS, WireGuard, SOCKS: translated straight into a sing-box
 *             outbound (see [OutboundConfigs]) — they have no dedicated [VpnConfig] fields.
 *  - Naive:  https://user:password@host:port?sni=...#name  (the panel emits a plain
 *             http/https scheme, not naive+https; "naive+https://" is also accepted)
 */
object LinkParser {

    /**
     * Parse any supported VPN link. Throws [IllegalArgumentException] on failure;
     * [UnsupportedEntryException] (a subclass) when the link is well-formed but cannot be served,
     * so callers can report why instead of just "invalid".
     */
    fun parse(rawLink: String): VpnConfig {
        val trimmed = rawLink.trim()
        return when {
            trimmed.startsWith("vless://", ignoreCase = true) -> parseVless(trimmed)
            trimmed.startsWith("vmess://", ignoreCase = true) -> parseVmess(trimmed)
            trimmed.startsWith("ss://", ignoreCase = true) -> parseShadowsocks(trimmed)
            trimmed.startsWith("trojan://", ignoreCase = true) -> parseTrojan(trimmed)
            trimmed.startsWith("hysteria2://", ignoreCase = true) -> parseHysteria2(trimmed)
            trimmed.startsWith("hy2://", ignoreCase = true) -> parseHysteria2(trimmed)
            trimmed.startsWith("naive+https://", ignoreCase = true) -> parseNaive(trimmed)
            isHttpProxyLink(trimmed) -> parseNaive(trimmed)
            trimmed.startsWith("tuic://", ignoreCase = true) -> parseTuic(trimmed)
            trimmed.startsWith("hysteria://", ignoreCase = true) -> parseHysteria1(trimmed)
            trimmed.startsWith("anytls://", ignoreCase = true) -> parseAnyTls(trimmed)
            trimmed.startsWith("wireguard://", ignoreCase = true) ||
                trimmed.startsWith("wg://", ignoreCase = true) -> parseWireGuard(trimmed)
            SOCKS_SCHEMES.any { trimmed.startsWith("$it://", ignoreCase = true) } -> parseSocks(trimmed)
            else -> {
                // Only a short, scheme-shaped prefix is echoed: the rest of the link is secret.
                val scheme = trimmed.substringBefore("://").take(16).lowercase()
                    .filter { it.isLetterOrDigit() || it in "+.-" }
                throw UnsupportedEntryException("unsupported scheme $scheme", message = "Unsupported protocol scheme: $scheme")
            }
        }
    }

    private val SOCKS_SCHEMES = listOf("socks", "socks5", "socks5h", "socks4", "socks4a")

    /** True when [s] starts with a scheme [parse] handles (http/https only with credentials). */
    fun looksLikeShareLink(s: String): Boolean =
        listOf("vless", "vmess", "ss", "trojan", "hysteria2", "hy2", "naive+https", "tuic",
            "hysteria", "anytls", "wireguard", "wg").plus(SOCKS_SCHEMES)
            .any { s.startsWith("$it://", ignoreCase = true) } || isHttpProxyLink(s)

    // ─────────────────────────── VLESS ───────────────────────────

    private fun parseVless(link: String): VpnConfig {
        // vless://UUID@host:port?params#name
        val uri = ParsedLink.parse(link)
        val uuid = uri.userInfo ?: throw IllegalArgumentException("VLESS: missing UUID")
        val host = uri.host ?: throw IllegalArgumentException("VLESS: missing host")
        val port = uri.port.takeIf { it in 1..65535 } ?: throw IllegalArgumentException("VLESS: invalid port")
        // ParsedLink already URL-decodes fragment/query values — decoding again here corrupted any
        // value containing a literal '%' (e.g. a path segment or name with percent-encoding).
        val name = uri.fragment ?: ""

        val networkStr = uri.queryParam("type") ?: "tcp"
        val securityStr = uri.queryParam("security") ?: "none"
        val flow = uri.queryParam("flow") ?: ""
        val sni = uri.queryParam("sni") ?: uri.queryParam("host") ?: ""
        val fingerprint = uri.queryParam("fp") ?: "chrome"
        val publicKey = uri.queryParam("pbk") ?: ""
        val shortId = uri.queryParam("sid") ?: ""
        val spiderX = uri.queryParam("spx") ?: ""
        val path = uri.queryParam("path") ?: ""
        val wsHost = uri.queryParam("host") ?: sni
        val serviceName = uri.queryParam("serviceName") ?: ""
        // VLESS "encryption" other than none is xray's post-quantum layer; the core has no such thing.
        uri.queryParam("encryption")?.takeIf { it.isNotBlank() && it != "none" }?.let {
            throw UnsupportedEntryException(SkippedEntry.needsXray("vless-encryption"), xrayCapable = true)
        }
        val network = networkStr.toNetworkType(uri.queryParam("headerType"))

        return VpnConfig(
            name = name,
            protocol = VpnProtocol.VLESS,
            address = host,
            port = port,
            uuid = uuid,
            flow = flow,
            encryption = "none",
            network = network,
            path = path,
            host = wsHost,
            serviceName = serviceName,
            security = securityStr.toSecurityType(),
            sni = sni,
            alpn = uri.queryParam("alpn") ?: "",
            allowInsecure = uri.isInsecure(),
            fingerprint = fingerprint,
            publicKey = publicKey,
            shortId = shortId,
            spiderX = spiderX,
            rawLink = link
        )
    }

    // ─────────────────────────── VMess ───────────────────────────

    private fun parseVmess(link: String): VpnConfig {
        // vmess://BASE64(json)
        val encoded = link.removePrefix("vmess://")
            .substringBefore("#") // fragment is inside json usually
        val json = JSONObject(
            LenientBase64.decodeToString(encoded) ?: throw IllegalArgumentException("VMess: not base64")
        )

        val host = json.optString("add").ifBlank { throw IllegalArgumentException("VMess: missing add") }
        val port = (json.optString("port").toIntOrNull() ?: json.optInt("port"))
            .takeIf { it in 1..65535 } ?: throw IllegalArgumentException("VMess: invalid port")
        val uuid = json.optString("id").ifBlank { throw IllegalArgumentException("VMess: missing id") }
        val name = json.optString("ps").ifBlank { "$host:$port" }
        val alterId = json.optString("aid").toIntOrNull() ?: json.optInt("aid", 0)
        val networkStr = json.optString("net", "tcp")
        val tls = json.optString("tls", "none")
        val sni = json.optString("sni").ifBlank { json.optString("host") }
        val path = json.optString("path", "")
        val wsHost = json.optString("host", sni)
        val fingerprint = json.optString("fp").ifBlank { "chrome" }
        // gRPC serviceName uses "path" field; for other transports it's empty
        val serviceName = if (networkStr == "grpc") json.optString("path", "") else ""
        // In v2rayN JSON "type" is the header type; "http" on tcp is xray's HTTP obfuscation.
        val network = networkStr.toNetworkType(json.optString("type"))
        val insecure = json.optString("allowInsecure").let { it == "1" || it.equals("true", true) } ||
            json.optString("insecure").let { it == "1" || it.equals("true", true) }

        return VpnConfig(
            name = name,
            protocol = VpnProtocol.VMESS,
            address = host,
            port = port,
            uuid = uuid,
            alterId = alterId,
            encryption = json.optString("scy", "auto").ifBlank { "auto" },
            network = network,
            path = path,
            host = wsHost,
            serviceName = serviceName,
            security = if (tls == "tls") SecurityType.TLS else SecurityType.NONE,
            sni = sni,
            alpn = json.optString("alpn"),
            allowInsecure = insecure,
            fingerprint = fingerprint,
            rawLink = link
        )
    }

    // ──────────────────────── Shadowsocks ────────────────────────

    private fun parseShadowsocks(link: String): VpnConfig {
        // Modern: ss://BASE64(method:password)@host:port#name
        // Legacy: ss://BASE64(method:password@host:port)#name
        val withoutScheme = link.removePrefix("ss://")
        val name = ParsedLink.parse(link).fragment ?: ""

        return if (withoutScheme.contains("@")) {
            // Modern SIP002 format — userinfo is usually base64(method:password), but the spec
            // also allows it to be sent as plaintext "method:password" directly.
            val uri = ParsedLink.parse(link)
            val rawUserInfo = uri.userInfo ?: ""
            // Plaintext "method:password" can never decode (':' is outside the alphabet), and a
            // decoded blob without ':' is not credentials, so fall back to the raw text.
            val userInfoDecoded = LenientBase64.decodeToString(rawUserInfo)
                ?.takeIf { it.contains(':') } ?: rawUserInfo
            val (method, password) = userInfoDecoded.split(":", limit = 2)
                .let { it[0] to it.getOrElse(1) { "" } }
            val host = uri.host ?: throw IllegalArgumentException("SS: missing host")
            val port = uri.port.takeIf { it in 1..65535 } ?: throw IllegalArgumentException("SS: invalid port")
            val (plugin, pluginOpts) = parseSsPlugin(uri.queryParam("plugin"))

            VpnConfig(
                name = name,
                protocol = VpnProtocol.SHADOWSOCKS,
                address = host,
                port = port,
                password = password,
                ssMethod = method,
                ssPlugin = plugin,
                ssPluginOpts = pluginOpts,
                rawLink = link
            )
        } else {
            // Legacy base64 format
            val encoded = withoutScheme.substringBefore("#")
            val decoded = LenientBase64.decodeToString(encoded)
                ?: throw IllegalArgumentException("SS: not base64")
            // format: method:password@host:port
            val atIdx = decoded.lastIndexOf("@")
            if (atIdx < 0) throw IllegalArgumentException("SS: invalid legacy format")
            val methodPassword = decoded.substring(0, atIdx)
            val hostPort = decoded.substring(atIdx + 1)
            val (method, password) = methodPassword.split(":", limit = 2)
                .let { it[0] to it.getOrElse(1) { "" } }
            val host = hostPort.substringBeforeLast(":")
            val port = hostPort.substringAfterLast(":").toIntOrNull()?.takeIf { it in 1..65535 }
                ?: throw IllegalArgumentException("SS: invalid port")

            VpnConfig(
                name = name,
                protocol = VpnProtocol.SHADOWSOCKS,
                address = host,
                port = port,
                password = password,
                ssMethod = method,
                rawLink = link
            )
        }
    }

    /**
     * `plugin=name;opt=v;opt2=v2` (SIP003). The core implements only obfs-local and
     * v2ray-plugin; a server behind any other plugin would just not answer, so it is skipped.
     */
    private fun parseSsPlugin(raw: String?): Pair<String, String> {
        if (raw.isNullOrBlank()) return "" to ""
        return mapSsPlugin(raw.substringBefore(';'), raw.substringAfter(';', ""))
    }

    /** Core-side plugin name and options for a SIP003 plugin; throws for plugins it lacks. */
    fun mapSsPlugin(name: String, opts: String): Pair<String, String> {
        if (name.isBlank()) return "" to ""
        return when (name) {
            "obfs-local", "simple-obfs" -> "obfs-local" to opts
            "v2ray-plugin" -> "v2ray-plugin" to opts
            else -> throw UnsupportedEntryException(
                "unsupported ss plugin ${name.take(24)}", message = "Unsupported shadowsocks plugin"
            )
        }
    }

    // ─────────────────────────── Trojan ───────────────────────────

    private fun parseTrojan(link: String): VpnConfig {
        // trojan://password@host:port?sni=...&security=tls&fp=...#name
        val uri = ParsedLink.parse(link)
        val password = uri.userInfo ?: throw IllegalArgumentException("Trojan: missing password")
        val host = uri.host ?: throw IllegalArgumentException("Trojan: missing host")
        val port = uri.port.takeIf { it in 1..65535 } ?: throw IllegalArgumentException("Trojan: invalid port")
        val name = uri.fragment ?: ""

        val sni = uri.queryParam("sni") ?: uri.queryParam("peer") ?: host
        val fingerprint = uri.queryParam("fp") ?: "chrome"
        val secStr = uri.queryParam("security") ?: "tls"
        val networkStr = uri.queryParam("type") ?: "tcp"
        val path = uri.queryParam("path") ?: ""
        val wsHost = uri.queryParam("host") ?: sni

        return VpnConfig(
            name = name,
            protocol = VpnProtocol.TROJAN,
            address = host,
            port = port,
            password = password,
            alpn = uri.queryParam("alpn") ?: "",
            allowInsecure = uri.isInsecure(),
            network = networkStr.toNetworkType(uri.queryParam("headerType")),
            path = path,
            host = wsHost,
            security = secStr.toSecurityType(),
            sni = sni,
            fingerprint = fingerprint,
            rawLink = link
        )
    }

    // ───────────────────────── Hysteria2 ──────────────────────────

    private fun parseHysteria2(link: String): VpnConfig {
        // hysteria2://password@host:port?params#name
        val uri = ParsedLink.parse(link)
        val password = uri.userInfo ?: throw IllegalArgumentException("Hysteria2: missing password")
        val host = uri.host ?: throw IllegalArgumentException("Hysteria2: missing host")
        // Hysteria2 defaults to 443 when the link omits the port.
        val port = uri.port.takeIf { it in 1..65535 } ?: 443
        val name = uri.fragment ?: ""

        // Obfuscation is optional and only "salamander" exists today; an obfs password
        // without obfs=salamander is meaningless, so both must be present.
        val obfsType = uri.queryParam("obfs") ?: ""
        val obfsPassword = if (obfsType.equals("salamander", ignoreCase = true)) {
            uri.queryParam("obfs-password") ?: ""
        } else ""

        return VpnConfig(
            name = name,
            protocol = VpnProtocol.HYSTERIA2,
            address = host,
            port = port,
            password = password,
            obfsPassword = obfsPassword,
            upMbps = uri.queryParam("up")?.toIntOrNull() ?: 0,
            downMbps = uri.queryParam("down")?.toIntOrNull() ?: 0,
            security = SecurityType.TLS,
            sni = uri.queryParam("sni") ?: "",
            allowInsecure = uri.isInsecure(),
            rawLink = link
        )
    }

    // ─────────────────────────── Naive ────────────────────────────

    /**
     * True for an http/https link carrying `user:password@` — that's how the panel ships
     * NaiveProxy (http-CONNECT) entries. Requiring credentials keeps a bare subscription
     * URL from being mistaken for a proxy.
     */
    private fun isHttpProxyLink(link: String): Boolean {
        if (!link.startsWith("http://", true) && !link.startsWith("https://", true)) return false
        val authority = link.substringAfter("://").substringBefore('/').substringBefore('?')
        val userInfo = authority.substringBefore('@', "")
        return authority.contains('@') && userInfo.contains(':')
    }

    private fun parseNaive(link: String): VpnConfig {
        // https://user:password@host:port?sni=...#name  (or naive+https:// / http://)
        // The '+' in the scheme is not a valid URI scheme character; normalise it away first.
        val body = link.substring(link.indexOf("://") + 3)
        val plaintext = link.startsWith("http://", ignoreCase = true)
        val uri = ParsedLink.parse("https://" + body)
        val host = uri.host ?: throw IllegalArgumentException("Naive: missing host")
        val port = uri.port.takeIf { it in 1..65535 } ?: 443
        val userInfo = uri.userInfo ?: throw IllegalArgumentException("Naive: missing credentials")
        val username = userInfo.substringBefore(':')
        val password = userInfo.substringAfter(':', "")
        if (password.isEmpty()) throw IllegalArgumentException("Naive: missing password")

        return VpnConfig(
            name = uri.fragment ?: "",
            protocol = VpnProtocol.NAIVE,
            address = host,
            port = port,
            username = username,
            password = password,
            // Plain http:// means the panel has TLS off for this host.
            security = if (plaintext) SecurityType.NONE else SecurityType.TLS,
            sni = uri.queryParam("sni") ?: "",
            allowInsecure = uri.isInsecure(),
            rawLink = link
        )
    }

    // ───────────── schemes translated to sing-box outbounds ─────────────

    private fun csv(s: String?): List<String> =
        s.orEmpty().split(',').map { it.trim() }.filter { it.isNotEmpty() }

    /** The `tls` object shared by tuic / hysteria / anytls links. */
    private fun tlsBlock(uri: ParsedLink, sni: String?, defaultAlpn: List<String> = emptyList()): JSONObject =
        JSONObject().apply {
            put("enabled", true)
            if (!sni.isNullOrBlank()) put("server_name", sni)
            val alpn = csv(uri.queryParam("alpn")).ifEmpty { defaultAlpn }
            if (alpn.isNotEmpty()) put("alpn", JSONArray(alpn))
            if (uri.isInsecure()) put("insecure", true)
        }

    private fun outboundConfig(type: String, uri: ParsedLink, host: String, port: Int, link: String, build: JSONObject.() -> Unit): VpnConfig {
        val outbound = JSONObject().apply {
            put("type", type)
            put("tag", "proxy")
            put("server", host)
            put("server_port", port)
            build()
        }
        return OutboundConfigs.fromOutbound(outbound, uri.fragment.orEmpty(), rawLink = link)
    }

    private fun parseTuic(link: String): VpnConfig {
        // tuic://UUID:PASSWORD@host:port?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=...#name
        val uri = ParsedLink.parse(link)
        val userInfo = uri.userInfo ?: throw IllegalArgumentException("TUIC: missing credentials")
        val uuid = userInfo.substringBefore(':')
        val password = userInfo.substringAfter(':', "")
        if (uuid.isBlank() || password.isEmpty()) throw IllegalArgumentException("TUIC: needs uuid and password")
        val host = uri.host ?: throw IllegalArgumentException("TUIC: missing host")
        val port = uri.port.takeIf { it in 1..65535 } ?: throw IllegalArgumentException("TUIC: invalid port")
        return outboundConfig("tuic", uri, host, port, link) {
            put("uuid", uuid)
            put("password", password)
            uri.queryParam("congestion_control")?.takeIf { it.isNotBlank() }?.let { put("congestion_control", it) }
            uri.queryParam("udp_relay_mode")?.takeIf { it.isNotBlank() }?.let { put("udp_relay_mode", it) }
            put("tls", tlsBlock(uri, uri.queryParam("sni"), listOf("h3")))
        }
    }

    private fun parseHysteria1(link: String): VpnConfig {
        // hysteria://host:port?auth=...&peer=sni&insecure=1&upmbps=50&downmbps=100&alpn=h3&obfs=xplus&obfsParam=...
        val uri = ParsedLink.parse(link)
        val host = uri.host ?: throw IllegalArgumentException("Hysteria: missing host")
        val port = uri.port.takeIf { it in 1..65535 } ?: throw IllegalArgumentException("Hysteria: invalid port")
        val protocol = uri.queryParam("protocol")
        if (!protocol.isNullOrBlank() && !protocol.equals("udp", ignoreCase = true)) {
            throw UnsupportedEntryException("unsupported hysteria protocol ${protocol.take(16)}")
        }
        return outboundConfig("hysteria", uri, host, port, link) {
            val authStr = uri.queryParam("auth_str") ?: uri.queryParam("auth-str") ?: uri.queryParam("authstr")
                ?: uri.userInfo
            if (authStr != null) put("auth_str", authStr)
            else uri.queryParam("auth")?.let { put("auth_str", it) }
            // The core insists on a bandwidth for the congestion controller; links often omit it.
            put("up_mbps", uri.queryParam("upmbps")?.toIntOrNull()?.takeIf { it > 0 } ?: 100)
            put("down_mbps", uri.queryParam("downmbps")?.toIntOrNull()?.takeIf { it > 0 } ?: 100)
            val obfs = uri.queryParam("obfsParam") ?: uri.queryParam("obfs")
            if (!obfs.isNullOrBlank() && !obfs.equals("none", true)) put("obfs", obfs)
            put("tls", tlsBlock(uri, uri.queryParam("peer") ?: uri.queryParam("sni"), listOf("h3")))
        }
    }

    private fun parseAnyTls(link: String): VpnConfig {
        // anytls://PASSWORD@host:port?sni=...&insecure=1&alpn=...#name
        val uri = ParsedLink.parse(link)
        val password = uri.userInfo ?: throw IllegalArgumentException("AnyTLS: missing password")
        val host = uri.host ?: throw IllegalArgumentException("AnyTLS: missing host")
        val port = uri.port.takeIf { it in 1..65535 } ?: 443
        return outboundConfig("anytls", uri, host, port, link) {
            put("password", password)
            put("tls", tlsBlock(uri, uri.queryParam("sni")).apply {
                uri.queryParam("fp")?.takeIf { it.isNotBlank() }?.let {
                    put("utls", JSONObject().put("enabled", true).put("fingerprint", it))
                }
            })
        }
    }

    /**
     * WireGuard links are not standardised; the common shape is
     * `wireguard://PRIVATE_KEY@host:port?publickey=..&address=10.0.0.2/32&reserved=1,2,3&mtu=1280#name`.
     * Since sing-box 1.13 WireGuard is an *endpoint*, not an outbound; the generator places it
     * accordingly (see SingBoxConfigGenerator), so the JSON here is the endpoint object.
     */
    private fun parseWireGuard(link: String): VpnConfig {
        val uri = ParsedLink.parse(link)
        val privateKey = (uri.userInfo ?: uri.queryParam("privatekey") ?: uri.queryParam("private_key"))
            ?.takeIf { it.isNotBlank() } ?: throw IllegalArgumentException("WireGuard: missing private key")
        val host = uri.host ?: throw IllegalArgumentException("WireGuard: missing host")
        val port = uri.port.takeIf { it in 1..65535 } ?: throw IllegalArgumentException("WireGuard: invalid port")
        fun q(vararg names: String) = names.firstNotNullOfOrNull { uri.queryParam(it)?.takeIf { v -> v.isNotBlank() } }
        val publicKey = q("publickey", "public_key", "peer_public_key", "pbk")
            ?: throw IllegalArgumentException("WireGuard: missing peer public key")
        val addresses = csv(q("address", "ip", "local_address")).map {
            if (it.contains('/')) it else if (it.contains(':')) "$it/128" else "$it/32"
        }
        if (addresses.isEmpty()) throw IllegalArgumentException("WireGuard: missing interface address")
        val reserved = csv(q("reserved")).map { it.toIntOrNull() ?: throw IllegalArgumentException("WireGuard: bad reserved") }
        if (reserved.isNotEmpty() && reserved.size != 3) throw IllegalArgumentException("WireGuard: bad reserved")

        val endpoint = JSONObject().apply {
            put("type", "wireguard")
            put("tag", "proxy")
            put("address", JSONArray(addresses))
            put("private_key", privateKey)
            q("mtu")?.toIntOrNull()?.let { put("mtu", it) }
            put("peers", JSONArray().put(JSONObject().apply {
                put("address", host)
                put("port", port)
                put("public_key", publicKey)
                q("presharedkey", "preshared_key", "pre_shared_key", "psk")?.let { put("pre_shared_key", it) }
                put("allowed_ips", JSONArray(csv(q("allowedips", "allowed_ips")).ifEmpty { listOf("0.0.0.0/0", "::/0") }))
                if (reserved.isNotEmpty()) put("reserved", JSONArray(reserved))
            }))
        }
        return OutboundConfigs.fromOutbound(endpoint, uri.fragment.orEmpty(), rawLink = link)
    }

    private fun parseSocks(link: String): VpnConfig {
        // socks5://user:pass@host:port#name, or socks://BASE64(user:pass)@host:port#name
        val uri = ParsedLink.parse(link)
        val host = uri.host ?: throw IllegalArgumentException("SOCKS: missing host")
        val port = uri.port.takeIf { it in 1..65535 } ?: throw IllegalArgumentException("SOCKS: invalid port")
        val raw = uri.userInfo.orEmpty()
        val credentials = if (raw.contains(':')) raw
        else LenientBase64.decodeToString(raw)?.takeIf { it.contains(':') } ?: raw
        val version = if (uri.scheme.lowercase().startsWith("socks4")) "4" else "5"
        return outboundConfig("socks", uri, host, port, link) {
            put("version", version)
            if (credentials.isNotEmpty()) {
                put("username", credentials.substringBefore(':'))
                credentials.substringAfter(':', "").takeIf { it.isNotEmpty() }?.let { put("password", it) }
            }
        }
    }

    // ───────────────────────── Helpers ────────────────────────────

    /** True only when the link explicitly asks to skip certificate validation. */
    private fun ParsedLink.isInsecure(): Boolean {
        val raw = queryParam("insecure") ?: queryParam("allowInsecure") ?: queryParam("allow_insecure")
            ?: return false
        return raw == "1" || raw.equals("true", ignoreCase = true)
    }

    /**
     * Transport names sing-box has. Anything else (xhttp/splithttp, kcp, ...) used to fall
     * through to plain TCP, producing a server that connects to nothing; now it is reported as
     * something only xray can serve.
     */
    private fun String.toNetworkType(headerType: String? = null): NetworkType = when (val t = lowercase()) {
        "", "tcp", "raw", "none" ->
            // tcp + HTTP header obfuscation is an xray feature; plain tcp would just fail.
            if (headerType.equals("http", ignoreCase = true)) {
                throw UnsupportedEntryException(
                    SkippedEntry.needsXray("tcp-http"), xrayCapable = true, message = "Unsupported transport: tcp-http"
                )
            } else NetworkType.TCP
        "ws" -> NetworkType.WS
        "grpc" -> NetworkType.GRPC
        "h2", "http" -> NetworkType.H2
        "httpupgrade" -> NetworkType.HTTPUPGRADE
        "quic" -> NetworkType.QUIC
        else -> throw UnsupportedEntryException(
            SkippedEntry.needsXray(t.take(24)), xrayCapable = true, message = "Unsupported transport: ${t.take(24)}"
        )
    }

    private fun String.toSecurityType(): SecurityType = when (lowercase()) {
        "tls" -> SecurityType.TLS
        "reality" -> SecurityType.REALITY
        else -> SecurityType.NONE
    }
}
