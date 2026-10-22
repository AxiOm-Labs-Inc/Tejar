package com.telegram.vpncore

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
            else -> {
                // Only a short, scheme-shaped prefix is echoed: the rest of the link is secret.
                val scheme = trimmed.substringBefore("://").take(16).lowercase()
                    .filter { it.isLetterOrDigit() || it in "+.-" }
                throw UnsupportedEntryException("unsupported scheme $scheme", message = "Unsupported protocol scheme: $scheme")
            }
        }
    }

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

        return VpnConfig(
            name = name,
            protocol = VpnProtocol.VLESS,
            address = host,
            port = port,
            uuid = uuid,
            flow = flow,
            encryption = "none",
            network = networkStr.toNetworkType(),
            path = path,
            host = wsHost,
            serviceName = serviceName,
            security = securityStr.toSecurityType(),
            sni = sni,
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
        val fingerprint = json.optString("fp", "chrome")
        // gRPC serviceName uses "path" field; for other transports it's empty
        val serviceName = if (networkStr == "grpc") json.optString("path", "") else ""

        return VpnConfig(
            name = name,
            protocol = VpnProtocol.VMESS,
            address = host,
            port = port,
            uuid = uuid,
            alterId = alterId,
            encryption = json.optString("scy", "auto"),
            network = networkStr.toNetworkType(),
            path = path,
            host = wsHost,
            serviceName = serviceName,
            security = if (tls == "tls") SecurityType.TLS else SecurityType.NONE,
            sni = sni,
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

            VpnConfig(
                name = name,
                protocol = VpnProtocol.SHADOWSOCKS,
                address = host,
                port = port,
                password = password,
                ssMethod = method,
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
            network = networkStr.toNetworkType(),
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

    // ───────────────────────── Helpers ────────────────────────────

    /** True only when the link explicitly asks to skip certificate validation. */
    private fun ParsedLink.isInsecure(): Boolean {
        val raw = queryParam("insecure") ?: queryParam("allowInsecure") ?: return false
        return raw == "1" || raw.equals("true", ignoreCase = true)
    }

    /**
     * Transport names sing-box has. Anything else (xhttp/splithttp, kcp, ...) used to fall
     * through to plain TCP, producing a server that connects to nothing; now it is reported as
     * something only xray can serve.
     */
    private fun String.toNetworkType(): NetworkType = when (val t = lowercase()) {
        "", "tcp", "raw", "none" -> NetworkType.TCP
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
