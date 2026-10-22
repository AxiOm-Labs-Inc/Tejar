package com.telegram.vpncore

/**
 * Represents a VPN subscription — a remote URL that returns a list of server configs.
 *
 * The optional fields below come from the panel's response headers (see [SubscriptionInfo]);
 * they default to "unknown" so subscriptions saved by older versions load unchanged.
 */
data class VpnSubscription(
    val id: String = java.util.UUID.randomUUID().toString(),
    val name: String,
    val url: String,
    val lastUpdated: Long = 0L,     // epoch ms
    val configIds: List<String> = emptyList(),  // IDs of configs fetched from this sub
    val hasUsage: Boolean = false,
    val uploadBytes: Long = 0L,
    val downloadBytes: Long = 0L,
    val totalBytes: Long = 0L,      // 0 = unlimited
    val expireAt: Long = 0L,        // unix seconds, 0 = never
    val updateIntervalHours: Int = 0, // panel's request, 0 = none
    val webPageUrl: String = "",
    val supportUrl: String = ""
) {
    /**
     * How long to wait between automatic refreshes: never longer than [DEFAULT_REFRESH_MS]
     * (the owner's choice), shorter only when the panel asks for it.
     */
    fun refreshIntervalMs(): Long =
        if (updateIntervalHours >= 1) minOf(DEFAULT_REFRESH_MS, updateIntervalHours * 3_600_000L)
        else DEFAULT_REFRESH_MS

    /** "Used 12.3 / 100 GB · expires 05.11.2026", or null when the panel reported nothing. */
    fun quotaText(): String? =
        SubscriptionInfo.describeQuota(uploadBytes + downloadBytes, totalBytes, expireAt, hasUsage)

    /** This subscription updated with what the panel just reported; null info changes nothing. */
    fun withInfo(info: SubscriptionInfo?): VpnSubscription {
        if (info == null) return this
        return copy(
            // A name the user chose is theirs; the panel's title only replaces the placeholder.
            name = if (name.isBlank() || name == DEFAULT_NAME) info.title ?: name else name,
            hasUsage = if (info.hasUsage) true else hasUsage,
            uploadBytes = if (info.hasUsage) info.uploadBytes else uploadBytes,
            downloadBytes = if (info.hasUsage) info.downloadBytes else downloadBytes,
            totalBytes = if (info.hasUsage) info.totalBytes else totalBytes,
            expireAt = if (info.hasUsage) info.expireAt else expireAt,
            updateIntervalHours = info.updateIntervalHours ?: updateIntervalHours,
            webPageUrl = info.webPageUrl ?: webPageUrl,
            supportUrl = info.supportUrl ?: supportUrl
        )
    }

    companion object {
        const val DEFAULT_NAME = "Subscription"
        const val DEFAULT_REFRESH_MS = 6L * 60 * 60 * 1000
    }
}
