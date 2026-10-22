package com.telegram.vpncore

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URL

/**
 * Downloads a subscription URL and parses it into a list of [VpnConfig].
 *
 * Supported response formats:
 *  1. sing-box config document — outbounds are taken verbatim (see [SingBoxSubscriptionParser])
 *  2. Base64-encoded text (one VPN link per line after decode) — standard v2ray/Marzban
 *  3. Plain text (one VPN link per line) — some panels
 *  4. HTML page (Marzban web UI) — extracts vless/vmess/ss/trojan links from HTML
 */
object SubscriptionFetcher {

    private const val TAG = "SubscriptionFetcher"
    private const val TIMEOUT_MS = 15_000
    private const val MAX_REDIRECTS = 5

    // User-Agents to try in order — the panel picks the response format from the UA.
    // "SFA/" comes first deliberately: it selects the sing-box format, which is the one the
    // panel generates most completely. Its links format silently omits whole protocols
    // (Naive among them), so a v2rayNG UA gets a subscription missing servers that exist.
    // The version is the bundled core's: the panel picks the sing-box template (field names,
    // layout) from it, and claiming an older client got a layout the newer core may reject.
    // The rest stay as fallbacks for panels that don't speak sing-box.
    private val USER_AGENTS = listOf(
        "SFA/${SingBoxCore.VERSION}",
        "v2rayNG/1.8.0",
        "clash/1.18.0",
        "Mozilla/5.0"   // fallback: get HTML, then extract links
    )

    /**
     * Fetches and parses [url]. Throws when no usable server came out; the message then says
     * what was skipped and why (never the entries themselves).
     */
    suspend fun fetch(inputUrl: String): ParseResult = withContext(Dispatchers.IO) {
        // An Outline dynamic access key is an https URL under another scheme.
        val url = ssconfToHttps(inputUrl) ?: inputUrl
        require(url.startsWith("https://", ignoreCase = true)) {
            "Subscription URL must use HTTPS: $url"
        }
        var lastError: Exception? = null
        var onlySkipped: ParseResult? = null
        for (ua in USER_AGENTS) {
            try {
                val raw = downloadText(url, ua)
                if (raw.isBlank()) continue
                val results = parseSubscription(raw) { ssconfUrl ->
                    // Same https-only rules as the subscription itself; null = unreachable.
                    try { downloadText(ssconfUrl, USER_AGENTS.last()) } catch (e: Exception) { null }
                }
                if (results.servers.isNotEmpty()) {
                    Log.d(TAG, "Fetched ${results.servers.size} configs with UA=$ua, " +
                        "skipped ${results.skipped.size}")
                    return@withContext results
                }
                if (results.skipped.isNotEmpty()) onlySkipped = results
            } catch (e: Exception) {
                Log.w(TAG, "Fetch attempt failed with UA=$ua: ${e.message}")
                lastError = e
            }
        }
        onlySkipped?.let {
            throw Exception("No usable servers (skipped ${it.skipped.size}: ${ParseResult.describe(it.skipped)})")
        }
        throw lastError ?: Exception("No servers found in subscription")
    }

    // ─────────────────────── Download ────────────────────────────

    private fun downloadText(url: String, userAgent: String): String {
        // Follow redirects manually so we can reject any hop that downgrades to plain HTTP
        // (java.net's instanceFollowRedirects silently follows https->http, opening it up to MITM).
        var currentUrl = url
        repeat(MAX_REDIRECTS + 1) { attempt ->
            require(currentUrl.startsWith("https://", ignoreCase = true)) {
                "Refusing non-HTTPS subscription URL: $currentUrl"
            }
            val conn = URL(currentUrl).openConnection() as HttpURLConnection
            conn.connectTimeout = TIMEOUT_MS
            conn.readTimeout = TIMEOUT_MS
            conn.setRequestProperty("User-Agent", userAgent)
            conn.setRequestProperty("Accept", "*/*")
            conn.instanceFollowRedirects = false
            try {
                val code = conn.responseCode
                when (code) {
                    200 -> return conn.inputStream.bufferedReader().readText()
                    in 300..399 -> {
                        val location = conn.getHeaderField("Location")
                            ?: throw Exception("HTTP $code without Location")
                        currentUrl = URL(URL(currentUrl), location).toString()
                        if (attempt == MAX_REDIRECTS) throw Exception("Too many redirects")
                    }
                    else -> throw Exception("HTTP $code")
                }
            } finally {
                conn.disconnect()
            }
        }
        throw Exception("Too many redirects")
    }

    // ─────────────────────── Parse ────────────────────────────────

    /** Maps `ssconf://host/path` to its https URL, or null for any other input. */
    internal fun ssconfToHttps(link: String): String? =
        if (link.startsWith("ssconf://", ignoreCase = true)) "https://" + link.substring(9).substringBefore('#') else null

    /**
     * @param fetchText downloads a URL for `ssconf://` entries inside the body (null = cannot).
     */
    internal fun parseSubscription(raw: String, fetchText: ((String) -> String?)? = null): ParseResult {
        val trimmed = raw.trim()

        // 0. sing-box config document — use the panel's own outbounds instead of re-deriving them
        if (SingBoxSubscriptionParser.looksLikeSingBoxConfig(trimmed)) {
            val results = SingBoxSubscriptionParser.parse(trimmed)
            if (!results.isEmpty) return results
        }

        // 0b. xray JSON (one config or an array of them), SIP008 / Outline JSON, Clash YAML.
        // After sing-box: both xray and sing-box documents have "outbounds", and the sing-box
        // check above already ruled out the ones with "type".
        if (XrayJsonParser.looksLikeXray(trimmed)) {
            runCatching { XrayJsonParser.parse(trimmed) }.getOrNull()?.takeIf { !it.isEmpty }?.let { return it }
        }
        if (Sip008Parser.looksLikeSip008(trimmed)) {
            runCatching { Sip008Parser.parse(trimmed) }.getOrNull()?.takeIf { !it.isEmpty }?.let { return it }
        }
        if (ClashSubscriptionParser.looksLikeClash(trimmed)) {
            runCatching { ClashSubscriptionParser.parse(trimmed) }
                .onFailure { Log.w(TAG, "Clash YAML did not parse: ${it.javaClass.simpleName}") }
                .getOrNull()?.takeIf { !it.isEmpty }?.let { return it }
        }

        // 1. Try base64 decode first (standard Marzban/v2ray subscription)
        tryBase64Decode(trimmed)?.let { decoded ->
            val results = extractLinksFromText(decoded, fetchText)
            if (!results.isEmpty) return results
        }

        // 2. Try plain text (one link per line)
        val plainResults = extractLinksFromText(trimmed, fetchText)
        if (!plainResults.isEmpty) return plainResults

        // 3. Try HTML extraction (Marzban web UI or other panels)
        if (trimmed.contains("<html", ignoreCase = true) ||
            trimmed.contains("<!DOCTYPE", ignoreCase = true)) {
            return extractLinksFromHtml(trimmed, fetchText)
        }

        return ParseResult.EMPTY
    }

    private val SCHEME_PREFIX = Regex("""^([A-Za-z][A-Za-z0-9+.-]{0,15})://""")

    private fun extractLinksFromText(text: String, fetchText: ((String) -> String?)?): ParseResult {
        val results = mutableListOf<VpnConfig>()
        val skipped = mutableListOf<SkippedEntry>()
        for (line in text.lines()) {
            val trimmed = line.trim()
            if (trimmed.startsWith("ssconf://", ignoreCase = true)) {
                parseLink(trimmed, results, skipped, fetchText)
                continue
            }
            if (!looksLikeVpnLink(trimmed)) {
                // Unrecognised schemes used to vanish without a trace, which is how the
                // subscription could carry servers that simply never appeared in the list.
                // Log the scheme only — everything after "://" is credentials.
                // Plain web URLs (a profile page, a support link) are not servers.
                val scheme = SCHEME_PREFIX.find(trimmed)?.groupValues?.get(1)?.lowercase()
                if (scheme != null && scheme != "http" && scheme != "https") {
                    Log.w(TAG, "Unsupported scheme in subscription: $scheme")
                    skipped.add(SkippedEntry("unsupported scheme $scheme"))
                }
                continue
            }
            parseLink(trimmed, results, skipped, fetchText)
        }
        return ParseResult(results, skipped)
    }

    private fun parseLink(
        link: String,
        results: MutableList<VpnConfig>,
        skipped: MutableList<SkippedEntry>,
        fetchText: ((String) -> String?)?
    ) {
        if (link.startsWith("ssconf://", ignoreCase = true)) {
            parseSsconf(link, results, skipped, fetchText)
            return
        }
        try {
            results.add(LinkParser.parse(link))
        } catch (e: UnsupportedEntryException) {
            Log.w(TAG, "Skipping link: ${e.reason}")
            skipped.add(SkippedEntry(e.reason, raw = link, xrayCapable = e.xrayCapable))
        } catch (e: Exception) {
            Log.w(TAG, "Skipping invalid link: ${redactCredentials(link).take(60)} — ${e.message}")
            skipped.add(SkippedEntry(SkippedEntry.INVALID_LINK))
        }
    }

    /** Outline `ssconf://` entry: the shadowsocks server lives at the https URL behind it. */
    private fun parseSsconf(
        link: String,
        results: MutableList<VpnConfig>,
        skipped: MutableList<SkippedEntry>,
        fetchText: ((String) -> String?)?
    ) {
        val body = fetchText?.let { it(ssconfToHttps(link)!!) }
        if (body == null) {
            skipped.add(SkippedEntry("ssconf unreachable"))
            return
        }
        try {
            val name = ParsedLink.parse(link).fragment.orEmpty()
            val parsed = Sip008Parser.parse(body, name)
            results.addAll(parsed.servers)
            skipped.addAll(parsed.skipped)
        } catch (e: Exception) {
            skipped.add(SkippedEntry(SkippedEntry.INVALID_LINK))
        }
    }

    /**
     * Strips secrets before a link preview hits logcat: the userinfo portion (uuid/password
     * before '@') for vless/trojan/ss, or the whole opaque payload for vmess (it's a single
     * base64 blob with no '@' separator, so there's no safe prefix to show).
     */
    private fun redactCredentials(link: String): String {
        if (link.startsWith("vmess://", ignoreCase = true)) return "vmess://***"
        return link.replaceFirst(Regex("""^(\w+://)[^@/\s]+@"""), "$1***@")
    }

    /**
     * Extracts share links embedded in HTML (e.g. a Marzban web page): everything from the
     * scheme to the next whitespace, quote or tag, with HTML entities (`&amp;` separating query
     * parameters) decoded. Truncating at '&' used to cut links down to their first parameter.
     */
    private fun extractLinksFromHtml(html: String, fetchText: ((String) -> String?)?): ParseResult {
        val found = HTML_LINK.findAll(html).map { unescapeHtml(it.value) }.toList()
        Log.d(TAG, "HTML extraction found ${found.size} raw links")

        val results = mutableListOf<VpnConfig>()
        val skipped = mutableListOf<SkippedEntry>()
        for (link in found) parseLink(link, results, skipped, fetchText)
        return ParseResult(results, skipped)
    }

    // Longest alternatives first: "hysteria2" before "hysteria", "socks5h" before "socks".
    private val HTML_LINK = Regex(
        """(?<![A-Za-z0-9+.-])(vless|vmess|ss|trojan|hysteria2|hysteria|hy2|tuic|anytls|wireguard|wg|socks5h|socks5|socks4a|socks4|socks|ssconf)://[^\s"'<>]+""",
        RegexOption.IGNORE_CASE
    )

    private fun unescapeHtml(s: String): String =
        s.replace("&amp;", "&").replace("&#38;", "&").replace("&#x26;", "&", ignoreCase = true)

    private fun tryBase64Decode(input: String): String? = try {
        // LenientBase64 ignores line breaks and accepts either alphabet, with or without padding.
        val text = LenientBase64.decodeToString(input)
        if (text != null && (looksLikeVpnLink(text) || text.contains("\n"))) text else null
    } catch (_: Exception) {
        null
    }

    private fun looksLikeVpnLink(s: String): Boolean = LinkParser.looksLikeShareLink(s)
}
