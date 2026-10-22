package com.telegram.vpncore

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/**
 * What a panel says about a subscription in its response headers (the de-facto convention of
 * v2rayN/Hiddify/Happ: `profile-title`, `subscription-userinfo`, ...). Every field is optional;
 * absent means "the panel did not say".
 */
data class SubscriptionInfo(
    val title: String? = null,
    /** True when a `subscription-userinfo` header was present (so zeros below are real zeros). */
    val hasUsage: Boolean = false,
    val uploadBytes: Long = 0,
    val downloadBytes: Long = 0,
    /** 0 = unlimited. */
    val totalBytes: Long = 0,
    /** Unix seconds; 0 = never expires. */
    val expireAt: Long = 0,
    /** Hours the panel asks clients to wait between refreshes; null when absent or below 1. */
    val updateIntervalHours: Int? = null,
    val webPageUrl: String? = null,
    val supportUrl: String? = null
) {
    companion object {
        /** [header] looks a response header up by name, case-insensitively. */
        fun fromHeaders(header: (String) -> String?): SubscriptionInfo {
            val usage = header("subscription-userinfo")?.takeIf { it.isNotBlank() }
            val fields = usage?.split(';')?.mapNotNull {
                val eq = it.indexOf('=')
                if (eq < 0) null else it.substring(0, eq).trim().lowercase() to it.substring(eq + 1).trim()
            }?.toMap().orEmpty()
            // Counters can arrive as "1.5e9" or "12.0" from some panels.
            fun num(key: String): Long = fields[key]?.let { it.toLongOrNull() ?: it.toDoubleOrNull()?.toLong() }
                ?.takeIf { it > 0 } ?: 0
            return SubscriptionInfo(
                title = header("profile-title")?.let(::decodeTitle)?.takeIf { it.isNotBlank() },
                hasUsage = fields.isNotEmpty(),
                uploadBytes = num("upload"),
                downloadBytes = num("download"),
                totalBytes = num("total"),
                expireAt = num("expire"),
                updateIntervalHours = header("profile-update-interval")?.trim()?.toDoubleOrNull()
                    ?.toInt()?.takeIf { it >= 1 },
                webPageUrl = header("profile-web-page-url")?.let(::httpsOnly),
                supportUrl = header("support-url")?.let(::httpsOnly)
            )
        }

        /** `base64:...` or plain text; some panels percent-encode non-ASCII titles. */
        fun decodeTitle(raw: String): String {
            val t = raw.trim().trim('"')
            if (t.startsWith("base64:", ignoreCase = true)) {
                return LenientBase64.decodeToString(t.substring(7))?.trim().orEmpty()
            }
            return ParsedLink.percentDecode(t, plusIsSpace = false).trim()
        }

        private fun httpsOnly(raw: String): String? =
            raw.trim().takeIf { it.startsWith("https://", ignoreCase = true) && !it.any(Char::isWhitespace) }

        /**
         * "Used 12.3 / 100 GB · expires 05.11.2026", or null when there is nothing to show.
         * Without a limit only the usage is shown; without an expiry only the quota.
         */
        fun describeQuota(
            usedBytes: Long, totalBytes: Long, expireAt: Long, hasUsage: Boolean,
            timeZone: TimeZone = TimeZone.getDefault()
        ): String? {
            val parts = ArrayList<String>()
            if (hasUsage) {
                if (totalBytes > 0) {
                    val unit = if (totalBytes >= GB) GB else MB
                    val name = if (unit == GB) "GB" else "MB"
                    parts.add("Used ${one(usedBytes, unit)} / ${one(totalBytes, unit)} $name")
                } else {
                    parts.add("Used ${if (usedBytes >= GB) one(usedBytes, GB) + " GB" else one(usedBytes, MB) + " MB"}")
                }
            }
            if (expireAt > 0) {
                val fmt = SimpleDateFormat("dd.MM.yyyy", Locale.US).apply { this.timeZone = timeZone }
                parts.add("expires ${fmt.format(Date(expireAt * 1000))}")
            }
            return parts.takeIf { it.isNotEmpty() }?.joinToString(" · ")
        }

        private const val MB = 1024L * 1024
        private const val GB = 1024L * 1024 * 1024
        private fun one(bytes: Long, unit: Long) = String.format(Locale.US, "%.1f", bytes.toDouble() / unit)
            .removeSuffix(".0")
    }
}
