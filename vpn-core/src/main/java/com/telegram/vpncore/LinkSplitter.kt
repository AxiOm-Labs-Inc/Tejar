package com.telegram.vpncore

import java.io.ByteArrayOutputStream

/**
 * A share link taken apart without any URI library.
 *
 * Real subscriptions carry links that RFC 3986 parsers reject: unencoded spaces, emoji and `|`
 * in the `#name`, bare IPv6 hosts, `+` in schemes. `java.net.URI` throws on those and
 * `android.net.Uri` is unavailable on the JVM (so the parsers could not be unit-tested), so
 * this splits leniently and never throws. Semantics follow `android.net.Uri` where links used
 * to go through it: userinfo/fragment/query values are percent-decoded, a query `+` is a space,
 * and the first occurrence of a repeated query key wins.
 */
class ParsedLink(
    val scheme: String,
    val userInfo: String?,
    /** Host without IPv6 brackets, or null when the authority has none. */
    val host: String?,
    /** -1 when absent or not a number, like `Uri.getPort`. */
    val port: Int,
    val path: String,
    val fragment: String?,
    private val query: List<Pair<String, String>>
) {
    fun queryParam(name: String): String? = query.firstOrNull { it.first == name }?.second

    companion object {
        fun parse(link: String): ParsedLink {
            val schemeEnd = link.indexOf("://")
            val scheme = if (schemeEnd >= 0) link.substring(0, schemeEnd) else ""
            var rest = if (schemeEnd >= 0) link.substring(schemeEnd + 3) else link

            var fragment: String? = null
            rest.indexOf('#').let { i ->
                if (i >= 0) {
                    fragment = percentDecode(rest.substring(i + 1), plusIsSpace = false)
                    rest = rest.substring(0, i)
                }
            }
            var queryRaw = ""
            rest.indexOf('?').let { i ->
                if (i >= 0) {
                    queryRaw = rest.substring(i + 1)
                    rest = rest.substring(0, i)
                }
            }
            val slash = rest.indexOf('/')
            val authority = if (slash >= 0) rest.substring(0, slash) else rest
            val path = if (slash >= 0) rest.substring(slash) else ""

            // The LAST '@' separates credentials: passwords may contain a literal '@'.
            val at = authority.lastIndexOf('@')
            val userInfo = if (at >= 0) percentDecode(authority.substring(0, at), plusIsSpace = false) else null
            val hostPort = if (at >= 0) authority.substring(at + 1) else authority

            val host: String
            var portText = ""
            if (hostPort.startsWith("[")) {
                val close = hostPort.indexOf(']')
                if (close >= 0) {
                    host = hostPort.substring(1, close)
                    portText = hostPort.substring(close + 1).removePrefix(":")
                } else {
                    host = hostPort.substring(1)
                }
            } else {
                val colon = hostPort.indexOf(':')
                host = if (colon >= 0) hostPort.substring(0, colon) else hostPort
                if (colon >= 0) portText = hostPort.substring(colon + 1)
            }

            val params = ArrayList<Pair<String, String>>()
            for (pair in queryRaw.split('&')) {
                if (pair.isEmpty()) continue
                val eq = pair.indexOf('=')
                val key = if (eq >= 0) pair.substring(0, eq) else pair
                val value = if (eq >= 0) pair.substring(eq + 1) else ""
                params.add(percentDecode(key, plusIsSpace = true) to percentDecode(value, plusIsSpace = true))
            }

            return ParsedLink(
                scheme = scheme,
                userInfo = userInfo,
                host = host.ifBlank { null },
                port = portText.toIntOrNull() ?: -1,
                path = path,
                fragment = fragment,
                query = params
            )
        }

        /** Decodes `%XX` as UTF-8; a malformed escape is kept literally instead of failing. */
        fun percentDecode(s: String, plusIsSpace: Boolean): String {
            if (s.indexOf('%') < 0 && !(plusIsSpace && s.indexOf('+') >= 0)) return s
            val out = ByteArrayOutputStream(s.length)
            var i = 0
            while (i < s.length) {
                val c = s[i]
                if (c == '%' && i + 2 < s.length && hexVal(s[i + 1]) >= 0 && hexVal(s[i + 2]) >= 0) {
                    out.write(hexVal(s[i + 1]) * 16 + hexVal(s[i + 2]))
                    i += 3
                } else if (c == '+' && plusIsSpace) {
                    out.write(' '.code)
                    i++
                } else {
                    // Whole code points: emoji are surrogate pairs and must not be split.
                    val cp = s.codePointAt(i)
                    out.write(String(Character.toChars(cp)).toByteArray(Charsets.UTF_8))
                    i += Character.charCount(cp)
                }
            }
            return out.toString("UTF-8")
        }

        private fun hexVal(c: Char): Int = when (c) {
            in '0'..'9' -> c - '0'
            in 'a'..'f' -> c - 'a' + 10
            in 'A'..'F' -> c - 'A' + 10
            else -> -1
        }
    }
}
