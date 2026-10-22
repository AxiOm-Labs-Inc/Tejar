package com.telegram.vpncore

import com.telegram.vpncore.SubscriptionImport.Result
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.TimeZone

class SubscriptionMetaTest {

    private fun info(vararg h: Pair<String, String>): SubscriptionInfo {
        val map = h.associate { it.first.lowercase() to it.second }
        return SubscriptionInfo.fromHeaders { map[it.lowercase()] }
    }

    private fun b64(s: String) = java.util.Base64.getEncoder().encodeToString(s.toByteArray())

    // ───────────── headers ─────────────

    @Test fun titlePlainBase64AndEncoded() {
        assertEquals("My VPN", info("profile-title" to "My VPN").title)
        assertEquals("Мой VPN 🚀", info("profile-title" to "base64:" + b64("Мой VPN 🚀")).title)
        assertEquals("Мой VPN", info("profile-title" to "%D0%9C%D0%BE%D0%B9%20VPN").title)
        assertNull(info("profile-title" to "  ").title)
        assertNull(info().title)
    }

    @Test fun userinfoFull() {
        val i = info("Subscription-Userinfo" to "upload=1073741824; download=2147483648; total=107374182400; expire=1793000000")
        assertTrue(i.hasUsage)
        assertEquals(1073741824L, i.uploadBytes)
        assertEquals(2147483648L, i.downloadBytes)
        assertEquals(107374182400L, i.totalBytes)
        assertEquals(1793000000L, i.expireAt)
    }

    @Test fun userinfoMissingFieldsAndJunk() {
        val i = info("subscription-userinfo" to "download=500;total=0;expire=0;foo;bar=x")
        assertTrue(i.hasUsage)
        assertEquals(0L, i.uploadBytes)
        assertEquals(500L, i.downloadBytes)
        assertEquals(0L, i.totalBytes)
        assertEquals(0L, i.expireAt)
        assertFalse(info().hasUsage)
        assertEquals(1500000000L, info("subscription-userinfo" to "total=1.5e9").totalBytes)
    }

    @Test fun updateIntervalOnlyAtLeastOneHour() {
        assertEquals(12, info("profile-update-interval" to "12").updateIntervalHours)
        assertEquals(1, info("profile-update-interval" to "1").updateIntervalHours)
        assertNull(info("profile-update-interval" to "0").updateIntervalHours)
        assertNull(info("profile-update-interval" to "0.5").updateIntervalHours)
        assertNull(info("profile-update-interval" to "soon").updateIntervalHours)
    }

    @Test fun pageLinksAreHttpsOnly() {
        val i = info("profile-web-page-url" to "https://panel.example.com/me", "support-url" to "http://insecure.example.com")
        assertEquals("https://panel.example.com/me", i.webPageUrl)
        assertNull(i.supportUrl)
        assertNull(info("support-url" to "javascript:alert(1)").supportUrl)
    }

    // ───────────── quota text and subscription updates ─────────────

    @Test fun quotaText() {
        val utc = TimeZone.getTimeZone("UTC")
        val gb = 1024L * 1024 * 1024
        assertEquals(
            "Used 12.3 / 100 GB · expires 05.11.2026",
            SubscriptionInfo.describeQuota((12.3 * gb).toLong(), 100 * gb, 1793836800L, true, utc)
        )
        assertEquals("Used 5 GB", SubscriptionInfo.describeQuota(5 * gb, 0, 0, true, utc))
        assertEquals("expires 05.11.2026", SubscriptionInfo.describeQuota(0, 0, 1793836800L, false, utc))
        assertNull(SubscriptionInfo.describeQuota(0, 0, 0, false, utc))
        assertEquals("Used 0 / 100 GB", SubscriptionInfo.describeQuota(0, 100 * gb, 0, true, utc))
    }

    @Test fun titleReplacesOnlyPlaceholderName() {
        val i = info("profile-title" to "Panel Name")
        assertEquals("Panel Name", VpnSubscription(name = "Subscription", url = "u").withInfo(i).name)
        assertEquals("Panel Name", VpnSubscription(name = "", url = "u").withInfo(i).name)
        assertEquals("Mine", VpnSubscription(name = "Mine", url = "u").withInfo(i).name)
        assertEquals("Subscription", VpnSubscription(name = "Subscription", url = "u").withInfo(info()).name)
    }

    @Test fun infoKeepsOldValuesWhenHeadersAreAbsent() {
        val sub = VpnSubscription(name = "n", url = "u").withInfo(
            info("subscription-userinfo" to "download=10;total=100;expire=5", "profile-update-interval" to "3")
        )
        assertEquals(100L, sub.totalBytes)
        assertEquals(3, sub.updateIntervalHours)
        val again = sub.withInfo(info()) // a later response without the headers
        assertEquals(sub, again)
        assertEquals(sub, sub.withInfo(null))
        // A new userinfo header replaces all counters, missing ones becoming 0 (e.g. unlimited).
        assertEquals(0L, sub.withInfo(info("subscription-userinfo" to "download=20")).totalBytes)
    }

    @Test fun refreshIntervalNeverLongerThanSixHours() {
        val h = 3_600_000L
        fun sub(hours: Int) = VpnSubscription(name = "n", url = "u", updateIntervalHours = hours)
        assertEquals(6 * h, sub(0).refreshIntervalMs())
        assertEquals(6 * h, sub(24).refreshIntervalMs())
        assertEquals(6 * h, sub(6).refreshIntervalMs())
        assertEquals(2 * h, sub(2).refreshIntervalMs())
        assertEquals(h, sub(1).refreshIntervalMs())
    }

    // ───────────── import links ─────────────

    private val sub = "https://panel.example.com/sub/abc123?x=1"
    private fun enc(s: String) = java.net.URLEncoder.encode(s, "UTF-8")
    private fun assertSub(expectedName: String, r: Result, url: String = sub) {
        assertEquals(Result.Subscription(url, expectedName), r)
    }

    @Test fun plainHttpsStaysAsIs() {
        assertSub("", SubscriptionImport.unwrap(sub))
        assertSub("My Sub", SubscriptionImport.unwrap("$sub#My%20Sub"))
        assertSub("", SubscriptionImport.unwrap("  $sub \n"))
    }

    @Test fun singBox() =
        assertSub("My Sub", SubscriptionImport.unwrap("sing-box://import-remote-profile?url=${enc(sub)}#My%20Sub"))

    @Test fun v2rayNg() =
        assertSub("Work", SubscriptionImport.unwrap("v2rayng://install-sub?url=${enc(sub)}&name=Work"))

    @Test fun clashAndClashMeta() {
        assertSub("C", SubscriptionImport.unwrap("clash://install-config?url=${enc(sub)}&name=C"))
        assertSub("", SubscriptionImport.unwrap("clashmeta://install-config?url=${enc(sub)}"))
    }

    @Test fun hiddifyStreisandV2raytun() {
        assertSub("H", SubscriptionImport.unwrap("hiddify://import/$sub#H"))
        assertSub("", SubscriptionImport.unwrap("streisand://import/$sub"))
        assertSub("", SubscriptionImport.unwrap("v2raytun://import/$sub"))
        assertSub("", SubscriptionImport.unwrap("hiddify://import/${enc(sub)}"))
    }

    @Test fun happPlainAndEncrypted() {
        assertSub("", SubscriptionImport.unwrap("happ://add/$sub"))
        for (s in listOf("happ://crypt/AbCd1234", "happ://crypt3/AbCd", "happ://crypt4/xyz")) {
            assertEquals(Result.Rejected("Encrypted Happ links are not supported"), SubscriptionImport.unwrap(s))
        }
    }

    @Test fun schemeIsCaseInsensitive() =
        assertSub("", SubscriptionImport.unwrap("V2RayNG://install-sub?url=${enc(sub)}"))

    @Test fun httpIsRejectedEverywhere() {
        val http = "http://panel.example.com/sub/abc"
        val msg = Result.Rejected("Subscription URL must use HTTPS")
        assertEquals(msg, SubscriptionImport.unwrap(http))
        assertEquals(msg, SubscriptionImport.unwrap("sing-box://import-remote-profile?url=${enc(http)}"))
        assertEquals(msg, SubscriptionImport.unwrap("hiddify://import/$http"))
        assertEquals(msg, SubscriptionImport.unwrap("happ://add/$http"))
    }

    @Test fun wrapperWithoutUrlIsRejected() {
        assertTrue(SubscriptionImport.unwrap("v2rayng://install-sub?name=x") is Result.Rejected)
        assertTrue(SubscriptionImport.unwrap("hiddify://import/") is Result.Rejected)
        assertTrue(SubscriptionImport.unwrap("clash://install-config?url=ftp%3A%2F%2Fx") is Result.Rejected)
    }

    @Test fun proxyLinksAndOtherTextAreNotSubscriptions() {
        for (s in listOf(
            "vless://uuid@h.example.com:443?type=tcp#n", "trojan://pw@h.example.com:443",
            "https://user:pass@naive.example.com:443", "hello world", "", "ssh://x@y"
        )) assertEquals(s, Result.NotSubscription, SubscriptionImport.unwrap(s))
    }

    @Test fun ssconfIsKept() =
        assertSub("Out", SubscriptionImport.unwrap("ssconf://keys.example.com/a.json#Out"), "ssconf://keys.example.com/a.json")
}
