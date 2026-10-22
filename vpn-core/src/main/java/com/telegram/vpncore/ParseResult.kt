package com.telegram.vpncore

/** Where a skipped entry came from, so a later stage knows how to re-read [SkippedEntry.raw]. */
enum class SkipSource { LINK, SINGBOX_OUTBOUND, XRAY_OUTBOUND, CLASH_PROXY }

/**
 * One subscription entry that did not become a server.
 *
 * [raw] is the original share link or sing-box outbound JSON, kept in memory only (it carries
 * credentials: never log or toast it; [SkipSource.XRAY_OUTBOUND] and [SkipSource.CLASH_PROXY]
 * hold JSON of the original xray outbound / Clash proxy entry). It exists for entries with [xrayCapable] set: they are
 * well-formed but need a transport only xray has, so a later stage can hand them to an xray
 * process without re-parsing the subscription.
 */
data class SkippedEntry(
    val reason: String,
    val raw: String = "",
    val xrayCapable: Boolean = false,
    val source: SkipSource = SkipSource.LINK,
    /** Display name from the subscription (a remark or tag), for the stage that picks this up. */
    val name: String = ""
) {
    companion object {
        const val REJECTED_BY_CORE = "rejected by core"
        const val INVALID_LINK = "invalid link"
        fun needsXray(transport: String) = "needs xray: $transport"
    }
}

/** Servers parsed from a subscription plus everything that was left out, and why. */
data class ParseResult(
    val servers: List<VpnConfig>,
    val skipped: List<SkippedEntry> = emptyList(),
    /** Response-header metadata of the fetch that produced this result; null when parsed from text. */
    val info: SubscriptionInfo? = null
) {
    val isEmpty: Boolean get() = servers.isEmpty() && skipped.isEmpty()

    /** Skip count per reason, in first-seen order. */
    val skipCounts: Map<String, Int> get() = skipped.groupingBy { it.reason }.eachCount()

    /** Entries an xray-based stage could still serve. */
    val xrayCapable: List<SkippedEntry> get() = skipped.filter { it.xrayCapable }

    companion object {
        val EMPTY = ParseResult(emptyList())

        /** "needs xray: xhttp x2, invalid link" — never contains link contents. */
        fun describe(skipped: List<SkippedEntry>): String =
            skipped.groupingBy { it.reason }.eachCount().entries
                .joinToString(", ") { (reason, n) -> if (n > 1) "$reason x$n" else reason }
    }
}

/** Link or outbound that is understood but cannot be served; carries the skip reason. */
class UnsupportedEntryException(
    val reason: String,
    val xrayCapable: Boolean = false,
    message: String = reason
) : IllegalArgumentException(message)
