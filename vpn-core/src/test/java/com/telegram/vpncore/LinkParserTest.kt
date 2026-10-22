package com.telegram.vpncore

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/** Pins the behaviour of every scheme [LinkParser] supports, plus the new skip reasons. */
class LinkParserTest {

    private val uuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

    private fun vmessLink(json: String) =
        "vmess://" + java.util.Base64.getEncoder().encodeToString(json.toByteArray())

    // ───────────── existing behaviour ─────────────

    @Test fun vlessReality() {
        val link = "vless://$uuid@example.com:443?type=tcp&security=reality&flow=xtls-rprx-vision" +
            "&sni=www.example.org&fp=firefox&pbk=PUB&sid=ab12&spx=%2F#Node%201"
        val c = LinkParser.parse(link)
        assertEquals(VpnProtocol.VLESS, c.protocol)
        assertEquals(uuid, c.uuid)
        assertEquals("example.com", c.address)
        assertEquals(443, c.port)
        assertEquals("Node 1", c.name)
        assertEquals(NetworkType.TCP, c.network)
        assertEquals(SecurityType.REALITY, c.security)
        assertEquals("xtls-rprx-vision", c.flow)
        assertEquals("www.example.org", c.sni)
        assertEquals("firefox", c.fingerprint)
        assertEquals("PUB", c.publicKey)
        assertEquals("ab12", c.shortId)
        assertEquals("/", c.spiderX)
        assertEquals(link, c.rawLink)
    }

    @Test fun vlessDefaultsAndWsHost() {
        val c = LinkParser.parse("vless://$uuid@h.example.com:8443?type=ws&path=%2Fws&host=cdn.example.com")
        assertEquals(NetworkType.WS, c.network)
        assertEquals("/ws", c.path)
        assertEquals("cdn.example.com", c.host)
        assertEquals("cdn.example.com", c.sni) // sni falls back to host
        assertEquals("chrome", c.fingerprint)
        assertEquals(SecurityType.NONE, c.security)
        assertEquals("", c.name)
    }

    @Test fun vlessGrpcHttpupgradeH2() {
        assertEquals("svc", LinkParser.parse("vless://$uuid@h:1?type=grpc&serviceName=svc").serviceName)
        assertEquals(NetworkType.GRPC, LinkParser.parse("vless://$uuid@h:1?type=grpc").network)
        assertEquals(NetworkType.HTTPUPGRADE, LinkParser.parse("vless://$uuid@h:1?type=httpupgrade").network)
        assertEquals(NetworkType.H2, LinkParser.parse("vless://$uuid@h:1?type=h2").network)
    }

    @Test fun vlessMissingPartsFail() {
        assertThrows(IllegalArgumentException::class.java) { LinkParser.parse("vless://h:443") }
        assertThrows(IllegalArgumentException::class.java) { LinkParser.parse("vless://$uuid@h") }
        assertThrows(IllegalArgumentException::class.java) { LinkParser.parse("vless://$uuid@h:99999") }
    }

    @Test fun vmessStandardAndUrlSafeNoPadding() {
        val json = """{"v":"2","ps":"VM","add":"vm.example.com","port":"443","id":"$uuid","aid":"2","scy":"aes-128-gcm",""" +
            """"net":"ws","host":"cdn.example.com","path":"/vm","tls":"tls","sni":"vm.example.com"}"""
        for (link in listOf(
            vmessLink(json),
            "vmess://" + java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(json.toByteArray())
        )) {
            val c = LinkParser.parse(link)
            assertEquals(VpnProtocol.VMESS, c.protocol)
            assertEquals("VM", c.name)
            assertEquals("vm.example.com", c.address)
            assertEquals(443, c.port)
            assertEquals(2, c.alterId)
            assertEquals("aes-128-gcm", c.encryption)
            assertEquals(NetworkType.WS, c.network)
            assertEquals("/vm", c.path)
            assertEquals("cdn.example.com", c.host)
            assertEquals(SecurityType.TLS, c.security)
        }
    }

    @Test fun vmessNameFallsBackToHostPortAndGrpcServiceName() {
        val c = LinkParser.parse(vmessLink("""{"add":"a.example.com","port":8080,"id":"$uuid","net":"grpc","path":"svc"}"""))
        assertEquals("a.example.com:8080", c.name)
        assertEquals("svc", c.serviceName)
        assertEquals(SecurityType.NONE, c.security)
    }

    @Test fun ssModernBase64UserInfo() {
        val ui = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString("aes-256-gcm:p@ss:word".toByteArray())
        val c = LinkParser.parse("ss://$ui@ss.example.com:8388#SS%20name")
        assertEquals(VpnProtocol.SHADOWSOCKS, c.protocol)
        assertEquals("aes-256-gcm", c.ssMethod)
        assertEquals("p@ss:word", c.password)
        assertEquals("ss.example.com", c.address)
        assertEquals(8388, c.port)
        assertEquals("SS name", c.name)
    }

    @Test fun ssModernPlaintextUserInfo() {
        val c = LinkParser.parse("ss://chacha20-ietf-poly1305:secret@ss.example.com:8388#n")
        assertEquals("chacha20-ietf-poly1305", c.ssMethod)
        assertEquals("secret", c.password)
    }

    @Test fun ssLegacy() {
        val body = java.util.Base64.getEncoder().encodeToString("aes-128-gcm:pw@legacy.example.com:1234".toByteArray())
        val c = LinkParser.parse("ss://$body#Legacy")
        assertEquals("aes-128-gcm", c.ssMethod)
        assertEquals("pw", c.password)
        assertEquals("legacy.example.com", c.address)
        assertEquals(1234, c.port)
        assertEquals("Legacy", c.name)
    }

    @Test fun trojanDefaults() {
        val c = LinkParser.parse("trojan://pw@t.example.com:443#T")
        assertEquals(VpnProtocol.TROJAN, c.protocol)
        assertEquals("pw", c.password)
        assertEquals("t.example.com", c.sni) // sni falls back to host
        assertEquals(SecurityType.TLS, c.security)
        assertEquals(NetworkType.TCP, c.network)
    }

    @Test fun trojanWsWithPeerAlias() {
        val c = LinkParser.parse("trojan://pw@t.example.com:443?type=ws&path=%2Ft&peer=p.example.com")
        assertEquals(NetworkType.WS, c.network)
        assertEquals("/t", c.path)
        assertEquals("p.example.com", c.sni)
        assertEquals("p.example.com", c.host)
    }

    @Test fun hysteria2WithObfs() {
        val c = LinkParser.parse("hysteria2://pw@hy.example.com:8443?sni=s.example.com&obfs=salamander&obfs-password=op&up=50&down=100&insecure=1#Hy")
        assertEquals(VpnProtocol.HYSTERIA2, c.protocol)
        assertEquals("pw", c.password)
        assertEquals(8443, c.port)
        assertEquals("op", c.obfsPassword)
        assertEquals(50, c.upMbps)
        assertEquals(100, c.downMbps)
        assertEquals("s.example.com", c.sni)
        assertTrue(c.allowInsecure)
        assertEquals(SecurityType.TLS, c.security)
    }

    @Test fun hysteria2AliasDefaultPortAndObfsPasswordNeedsType() {
        val c = LinkParser.parse("hy2://pw@hy.example.com?obfs-password=ignored")
        assertEquals(443, c.port)
        assertEquals("", c.obfsPassword)
        assertFalse(c.allowInsecure)
    }

    @Test fun naiveHttpsAndPlainHttpAndPrefixed() {
        val a = LinkParser.parse("https://user:pw@n.example.com:8443?sni=s.example.com#N")
        assertEquals(VpnProtocol.NAIVE, a.protocol)
        assertEquals("user", a.username)
        assertEquals("pw", a.password)
        assertEquals(8443, a.port)
        assertEquals(SecurityType.TLS, a.security)
        assertEquals("N", a.name)

        val b = LinkParser.parse("http://user:pw@n.example.com")
        assertEquals(SecurityType.NONE, b.security)
        assertEquals(443, b.port)

        assertEquals(VpnProtocol.NAIVE, LinkParser.parse("naive+https://user:pw@n.example.com:444").protocol)
    }

    @Test fun bareHttpUrlIsNotAProxy() {
        assertThrows(IllegalArgumentException::class.java) { LinkParser.parse("https://example.com/sub/token") }
    }

    // ───────────── new: reporting ─────────────

    @Test fun unsupportedSchemeCarriesReason() {
        val e = assertThrows(UnsupportedEntryException::class.java) {
            LinkParser.parse("tuic://uuid:secret@t.example.com:443")
        }
        assertEquals("unsupported scheme tuic", e.reason)
        assertFalse(e.xrayCapable)
        assertFalse(e.message!!.contains("secret"))
    }

    @Test fun xrayOnlyTransportsAreFlagged() {
        for (t in listOf("xhttp", "splithttp", "kcp")) {
            val e = assertThrows(UnsupportedEntryException::class.java) {
                LinkParser.parse("vless://$uuid@h.example.com:443?type=$t&security=tls")
            }
            assertEquals("needs xray: $t", e.reason)
            assertTrue(e.xrayCapable)
        }
        assertEquals("needs xray: kcp", assertThrows(UnsupportedEntryException::class.java) {
            LinkParser.parse("trojan://pw@h.example.com:443?type=kcp")
        }.reason)
        assertEquals("needs xray: xhttp", assertThrows(UnsupportedEntryException::class.java) {
            LinkParser.parse(vmessLink("""{"add":"h","port":"443","id":"$uuid","net":"xhttp"}"""))
        }.reason)
    }

    @Test fun xrayNameForPlainTcpIsAccepted() {
        assertEquals(NetworkType.TCP, LinkParser.parse("vless://$uuid@h:443?type=raw").network)
    }

    @Test fun ipv6HostHasNoBrackets() {
        val c = LinkParser.parse("vless://$uuid@[2001:db8::1]:8443?type=tcp#v6")
        assertEquals("2001:db8::1", c.address)
        assertEquals(8443, c.port)
    }

    @Test fun jsonHelperSanity() {
        assertEquals("x", JSONObject("""{"a":"x"}""").getString("a"))
    }
}
