package com.telegram.vpncore

/**
 * Turns what a user pastes into a subscription URL.
 *
 * Services hand out "add to app" deep links (`sing-box://import-remote-profile?url=...`,
 * `v2rayng://install-sub?url=...`, `hiddify://import/<url>`, ...). Each wraps the same https
 * subscription URL, so unwrap them instead of asking the user to dig the URL out.
 * Only https subscriptions are accepted: a plain-http URL would leak the per-user token.
 */
object SubscriptionImport {

    sealed class Result {
        data class Subscription(val url: String, val name: String) : Result()
        /** Recognised as a subscription link, but unusable; [message] is user-facing. */
        data class Rejected(val message: String) : Result()
        /** Not a subscription link (a proxy link, or anything else). */
        object NotSubscription : Result()
    }

    /** Wrappers carrying the URL in a `url=` query parameter. */
    private val QUERY_WRAPPERS = setOf("sing-box", "v2rayng", "clash", "clashmeta", "clash-meta", "stash")

    /** Wrappers carrying the URL as the path: scheme://<verb>/<url>. */
    private val PATH_WRAPPERS = setOf("hiddify", "streisand", "happ", "v2raytun")

    fun unwrap(input: String): Result {
        val text = input.trim()
        if (text.isEmpty() || text.any { it.isWhitespace() }) return Result.NotSubscription
        val scheme = text.substringBefore("://", "").lowercase()
        if (scheme.isEmpty()) return Result.NotSubscription

        return when {
            scheme == "https" || scheme == "http" -> plainUrl(text)
            scheme == "ssconf" -> Result.Subscription(text.substringBefore('#'), fragmentName(text))
            scheme in QUERY_WRAPPERS -> {
                val link = ParsedLink.parse(text)
                val url = link.queryParam("url")
                    ?: return Result.Rejected("No subscription URL in the link")
                val name = link.queryParam("name")?.takeIf { it.isNotBlank() } ?: link.fragment.orEmpty()
                checked(url, name)
            }
            scheme in PATH_WRAPPERS -> {
                val rest = text.substring(scheme.length + 3)
                if (scheme == "happ" && rest.startsWith("crypt", ignoreCase = true)) {
                    return Result.Rejected("Encrypted Happ links are not supported")
                }
                // scheme://<verb>/<url>[#name]; the URL may be percent-encoded as a whole.
                val body = rest.substringAfter('/', "")
                val fragment = ParsedLink.percentDecode(body.substringAfter('#', ""), false)
                var url = body.substringBefore('#')
                if (Regex("^https?%3A", RegexOption.IGNORE_CASE).containsMatchIn(url)) {
                    url = ParsedLink.percentDecode(url, plusIsSpace = false)
                }
                checked(url, fragment)
            }
            else -> Result.NotSubscription
        }
    }

    private fun plainUrl(text: String): Result {
        // https://user:pass@host is a NaiveProxy server link, not a subscription.
        if (LinkParser.looksLikeShareLink(text)) return Result.NotSubscription
        return checked(text.substringBefore('#'), fragmentName(text))
    }

    private fun fragmentName(text: String) =
        ParsedLink.percentDecode(text.substringAfter('#', ""), plusIsSpace = false)

    private fun checked(url: String, name: String): Result = when {
        url.startsWith("https://", ignoreCase = true) && url.length > 8 -> Result.Subscription(url, name.trim())
        url.startsWith("http://", ignoreCase = true) -> Result.Rejected("Subscription URL must use HTTPS")
        else -> Result.Rejected("No subscription URL in the link")
    }
}
