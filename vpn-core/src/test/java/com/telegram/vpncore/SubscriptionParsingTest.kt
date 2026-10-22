package com.telegram.vpncore

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** End-to-end parsing of realistic (synthetic) subscription bodies from `resources/subscriptions`. */
class SubscriptionParsingTest {

    private fun fixture(name: String): String =
        javaClass.getResourceAsStream("/subscriptions/$name")!!.bufferedReader(Charsets.UTF_8).readText()

    private fun parse(name: String) = SubscriptionFetcher.parseSubscription(fixture(name))

    private fun ParseResult.byName(name: String) = servers.first { it.name == name }

    private fun assertLinkList(r: ParseResult) {
        assertEquals(12, r.servers.size)
        assertEquals(
            mapOf(
                "needs xray: xhttp" to 1,
                "needs xray: kcp" to 2,
                "unsupported scheme ssh" to 1,
                "invalid link" to 1
            ),
            r.skipCounts
        )
        // The plain https support URL and the "#profile-title" line are not counted as anything.
        assertEquals(5, r.skipped.size)

        val reality = r.byName("🇩🇪 Germany | Reality")
        assertEquals(SecurityType.REALITY, reality.security)
        assertEquals("PUBKEY_abc-_123", reality.publicKey)
        assertEquals("ab12", reality.shortId)
        assertEquals("xtls-rprx-vision", reality.flow)

        val ws = r.byName("WS node 1")
        assertEquals(NetworkType.WS, ws.network)
        assertEquals("/chat?ed=2048", ws.path)
        assertEquals("cdn.example.com", ws.host)

        assertEquals(NetworkType.GRPC, r.byName("gRPC").network)
        assertEquals("svc", r.byName("gRPC").serviceName)
        assertEquals(NetworkType.HTTPUPGRADE, r.byName("HTTPUpgrade").network)

        assertEquals("2001:db8::1", r.byName("IPv6 vless").address)
        assertEquals(8443, r.byName("IPv6 vless").port)
        assertEquals("2001:db8::2", r.byName("IPv6 trojan").address)

        assertEquals(NetworkType.WS, r.byName("Trojan WS").network)

        val vmess = r.byName("VMess WS 🚀")
        assertEquals(VpnProtocol.VMESS, vmess.protocol)
        assertEquals(NetworkType.WS, vmess.network)
        assertEquals(SecurityType.TLS, vmess.security)

        val ss = r.byName("SS base64 userinfo")
        assertEquals("aes-256-gcm", ss.ssMethod)
        assertEquals("pass123", ss.password)
        val ssPlain = r.byName("SS plain userinfo")
        assertEquals("chacha20-ietf-poly1305", ssPlain.ssMethod)
        assertEquals("plain+pass", ssPlain.password)

        val hy2 = r.byName("Hy2 ⚡")
        assertEquals(VpnProtocol.HYSTERIA2, hy2.protocol)
        assertEquals("obfspw", hy2.obfsPassword)
        assertTrue(hy2.allowInsecure)

        // Entries stage E (xray) can pick up keep their original link and are tagged.
        val xray = r.xrayCapable
        assertEquals(3, xray.size)
        assertTrue(xray.all { it.source == SkipSource.LINK && it.raw.contains("://") })
        assertTrue(xray.any { it.raw.startsWith("vless://") && it.raw.contains("type=xhttp") })
        assertFalse(r.skipped.first { it.reason.startsWith("unsupported scheme") }.xrayCapable)
    }

    @Test fun plainListWithEmojiSpacesAndIpv6() = assertLinkList(parse("links_plain.txt"))

    @Test fun base64StandardWrapped() = assertLinkList(parse("links_b64_standard.txt"))

    @Test fun base64UrlSafeWithoutPadding() {
        val raw = fixture("links_b64_urlsafe_nopad.txt")
        assertTrue(raw.contains('-') || raw.contains('_'))
        assertFalse(raw.endsWith("="))
        assertLinkList(SubscriptionFetcher.parseSubscription(raw))
    }

    @Test fun htmlPageLinks() {
        val r = parse("page.html")
        assertEquals(listOf("Page node", "Page trojan", "Page ss", "VMess WS 🚀"), r.servers.map { it.name })
        assertEquals(mapOf("needs xray: xhttp" to 1), r.skipCounts)
        assertEquals(NetworkType.WS, r.servers[0].network)
    }

    @Test fun singBoxJsonFromMarzban() {
        val r = parse("singbox_marzban.json")
        assertEquals(
            listOf("DE Reality", "NL WS", "DE ShadowTLS", "SE Bogus", "PL Hy2"),
            r.servers.map { it.name }
        )
        // selector/direct/block are constructs; the shadowtls link is folded into its server.
        val stls = r.byName("DE ShadowTLS")
        assertEquals(VpnProtocol.SHADOWSOCKS, stls.protocol)
        assertEquals(1, org.json.JSONArray(stls.rawDependencies).length())
        assertEquals("shadowtls", org.json.JSONArray(stls.rawDependencies).getJSONObject(0).getString("type"))

        assertEquals(
            mapOf("needs xray: xhttp" to 1, "incomplete detour chain" to 1),
            r.skipCounts
        )
        val xray = r.xrayCapable.single()
        assertEquals(SkipSource.SINGBOX_OUTBOUND, xray.source)
        assertEquals("xhttp", org.json.JSONObject(xray.raw).getJSONObject("transport").getString("type"))
        // Ids are stable across parses (they key latency and the active server).
        assertEquals(r.servers.map { it.id }, parse("singbox_marzban.json").servers.map { it.id })
    }

    @Test fun validatorFakeDropsTheBogusOutbound() {
        val r = parse("singbox_marzban.json")
        val validator = object : ServerValidator {
            override fun validate(config: VpnConfig) =
                if (config.rawOutbound.contains("bogus_field")) "unknown field" else null
        }
        val out = validator.filter(r.servers)
        assertEquals(4, out.valid.size)
        assertFalse(out.valid.any { it.name == "SE Bogus" })
        val all = r.skipped + out.rejected
        assertEquals(3, all.size)
        assertEquals("rejected by core", ParseResult.describe(out.rejected))
        assertEquals("needs xray: xhttp, incomplete detour chain, rejected by core", ParseResult.describe(all))
    }

    @Test fun describeCountsRepeatedReasons() {
        val r = parse("links_plain.txt")
        assertEquals(
            "needs xray: xhttp, needs xray: kcp x2, unsupported scheme ssh, invalid link",
            ParseResult.describe(r.skipped)
        )
    }

    @Test fun onlyUnusableEntriesStillReportReasons() {
        val r = SubscriptionFetcher.parseSubscription("ssh://u:p@h:1\nvless://nope\n")
        assertTrue(r.servers.isEmpty())
        assertNotNull(r.skipped)
        assertEquals(2, r.skipped.size)
    }

    @Test fun garbageYieldsNothing() = assertTrue(SubscriptionFetcher.parseSubscription("hello\nworld").isEmpty)

    @Test fun userAgentFollowsBundledCore() = assertEquals("1.13.19", SingBoxCore.VERSION)
}
