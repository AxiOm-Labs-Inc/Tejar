package com.telegram.vpncore

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/** Link/Clash -> xray outbound, the process config, and how sing-box reaches xray servers. */
class XrayTest {

    private val uuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    private fun stream(o: JSONObject) = o.getJSONObject("streamSettings")

    // ───────────── links ─────────────

    @Test fun vlessXhttpRealityWithModeAndExtra() {
        val extra = java.net.URLEncoder.encode("""{"xPaddingBytes":"100-1000","noGRPCHeader":false}""", "UTF-8")
        val o = XrayOutbounds.fromLink(
            "vless://$uuid@x.example.com:443?type=xhttp&security=reality&sni=www.example.org&fp=chrome&pbk=PUB&sid=ab&spx=%2F" +
                "&path=%2Fx&host=cdn.example.com&mode=stream-up&extra=$extra&flow=xtls-rprx-vision#N"
        )
        assertEquals("vless", o.getString("protocol"))
        val user = o.getJSONObject("settings").getJSONArray("vnext").getJSONObject(0).getJSONArray("users").getJSONObject(0)
        assertEquals(uuid, user.getString("id"))
        assertEquals("none", user.getString("encryption"))
        assertEquals("xtls-rprx-vision", user.getString("flow"))
        val s = stream(o)
        assertEquals("xhttp", s.getString("network"))
        assertEquals("reality", s.getString("security"))
        assertEquals("PUB", s.getJSONObject("realitySettings").getString("publicKey"))
        assertEquals("www.example.org", s.getJSONObject("realitySettings").getString("serverName"))
        val x = s.getJSONObject("xhttpSettings")
        assertEquals("/x", x.getString("path"))
        assertEquals("cdn.example.com", x.getString("host"))
        assertEquals("stream-up", x.getString("mode"))
        assertEquals("100-1000", x.getJSONObject("extra").getString("xPaddingBytes"))
    }

    @Test fun xhttpModeDefaultsToAutoAndSplithttpIsAnAlias() {
        val o = XrayOutbounds.fromLink("vless://$uuid@x.example.com:443?type=splithttp&security=tls&sni=x.example.com")
        assertEquals("xhttp", stream(o).getString("network"))
        assertEquals("auto", stream(o).getJSONObject("xhttpSettings").getString("mode"))
        assertEquals("x.example.com", stream(o).getJSONObject("tlsSettings").getString("serverName"))
    }

    @Test fun trojanKcp() {
        val o = XrayOutbounds.fromLink("trojan://pw@k.example.com:4000?type=kcp&headerType=wechat-video&seed=abc&sni=k.example.com&allowInsecure=1&alpn=h2,http/1.1")
        assertEquals("trojan", o.getString("protocol"))
        assertEquals("pw", o.getJSONObject("settings").getJSONArray("servers").getJSONObject(0).getString("password"))
        val s = stream(o)
        assertEquals("kcp", s.getString("network"))
        // xray 26.x: header and seed are UDP finalmask layers, header next to the wire.
        val masks = s.getJSONObject("finalmask").getJSONArray("udp")
        assertEquals("header-wechat", masks.getJSONObject(0).getString("type"))
        assertEquals("mkcp-aes128gcm", masks.getJSONObject(1).getString("type"))
        assertEquals("abc", masks.getJSONObject(1).getJSONObject("settings").getString("password"))
        assertTrue(s.getJSONObject("tlsSettings").getBoolean("allowInsecure"))
        assertEquals(2, s.getJSONObject("tlsSettings").getJSONArray("alpn").length())
    }

    @Test fun kcpWithoutSeedUsesOriginalAndFmIsPassedThrough() {
        val plain = XrayOutbounds.fromLink("vless://$uuid@k.example.com:4000?type=kcp&mtu=1200&tti=20")
        val masks = stream(plain).getJSONObject("finalmask").getJSONArray("udp")
        assertEquals(1, masks.length())
        assertEquals("mkcp-original", masks.getJSONObject(0).getString("type"))
        assertEquals(1200, stream(plain).getJSONObject("kcpSettings").getInt("mtu"))
        val fm = java.net.URLEncoder.encode("""{"udp":[{"type":"header-dtls"}]}""", "UTF-8")
        val custom = XrayOutbounds.fromLink("vless://$uuid@k.example.com:4000?type=kcp&fm=$fm")
        assertEquals("header-dtls", stream(custom).getJSONObject("finalmask").getJSONArray("udp").getJSONObject(0).getString("type"))
    }

    @Test fun tcpHttpHeaderObfuscation() {
        val o = XrayOutbounds.fromLink("vless://$uuid@t.example.com:80?type=tcp&headerType=http&host=a.example.com,b.example.com&path=%2Fp")
        val req = stream(o).getJSONObject("tcpSettings").getJSONObject("header").getJSONObject("request")
        assertEquals("/p", req.getJSONArray("path").getString(0))
        assertEquals(2, req.getJSONObject("headers").getJSONArray("Host").length())
        assertEquals("none", stream(o).getString("security"))
    }

    @Test fun vmessKcpFromJsonLink() {
        val json = """{"v":"2","ps":"V","add":"v.example.com","port":"4000","id":"$uuid","aid":"0","scy":"auto","net":"kcp","type":"srtp","path":"seedx","tls":""}"""
        val link = "vmess://" + java.util.Base64.getEncoder().encodeToString(json.toByteArray())
        val o = XrayOutbounds.fromLink(link)
        assertEquals("vmess", o.getString("protocol"))
        val masks = stream(o).getJSONObject("finalmask").getJSONArray("udp")
        assertEquals("header-srtp", masks.getJSONObject(0).getString("type"))
        assertEquals("seedx", masks.getJSONObject(1).getJSONObject("settings").getString("password"))
        assertEquals("V", XrayOutbounds.nameOfLink(link))
    }

    @Test fun linksWeCannotExpressAreRejected() {
        assertThrows(IllegalArgumentException::class.java) { XrayOutbounds.fromLink("tuic://a:b@h:1") }
        assertThrows(IllegalArgumentException::class.java) { XrayOutbounds.fromLink("vless://$uuid@h:443?type=weird") }
    }

    // ───────────── Clash ─────────────

    @Test fun clashXhttpAndHttpHeader() {
        val x = XrayOutbounds.fromClash(JSONObject("""{"type":"vless","server":"x.example.com","port":443,"uuid":"$uuid","network":"xhttp","tls":true,
            "servername":"x.example.com","client-fingerprint":"chrome","xhttp-opts":{"path":"/x","host":"h.example.com","mode":"packet-up"}}"""))
        assertEquals("xhttp", stream(x).getString("network"))
        assertEquals("packet-up", stream(x).getJSONObject("xhttpSettings").getString("mode"))
        assertEquals("h.example.com", stream(x).getJSONObject("xhttpSettings").getString("host"))
        assertEquals("chrome", stream(x).getJSONObject("tlsSettings").getString("fingerprint"))

        val h = XrayOutbounds.fromClash(JSONObject("""{"type":"trojan","server":"t.example.com","port":"80","password":"pw","network":"http",
            "http-opts":{"path":["/a"],"headers":{"Host":["a.example.com"]}}}"""))
        assertEquals("tcp", stream(h).getString("network"))
        assertEquals("http", stream(h).getJSONObject("tcpSettings").getJSONObject("header").getString("type"))
        assertEquals("a.example.com", stream(h).getJSONObject("tcpSettings").getJSONObject("header")
            .getJSONObject("request").getJSONObject("headers").getJSONArray("Host").getString(0))
    }

    // ───────────── xray subscriptions ─────────────

    @Test fun sanitizeStripsTagAndSourceAddressButRefusesChains() {
        val ob = JSONObject("""{"tag":"proxy","sendThrough":"1.2.3.4","protocol":"vless","mux":{"enabled":true},
            "settings":{"vnext":[{"address":"a.example.com","port":443,"users":[{"id":"u"}]}]}}""")
        val clean = XrayOutbounds.sanitize(ob)
        assertFalse(clean.has("tag")); assertFalse(clean.has("sendThrough")); assertFalse(clean.has("mux"))
        assertEquals("a.example.com" to 443, XrayOutbounds.endpointOf(clean))
        assertThrows(IllegalArgumentException::class.java) {
            XrayOutbounds.sanitize(JSONObject("""{"protocol":"vless","proxySettings":{"tag":"x"}}"""))
        }
    }

    // ───────────── process config ─────────────

    private fun server(link: String, name: String = "s") =
        OutboundConfigs.xrayServer(XrayOutbounds.fromLink(link), name, link)

    @Test fun processConfigHasInboundPerServerRoutingDnsAndIpv4() {
        val a = server("vless://$uuid@a.example.com:443?type=xhttp&security=tls&sni=a.example.com", "A")
        val b = server("trojan://pw@b.example.com:4000?type=kcp", "B")
        val eps = mapOf(a.id to XrayEndpoint(41001, "ua", "pa"), b.id to XrayEndpoint(41002, "ub", "pb"))
        val cfg = JSONObject(XrayConfigBuilder.build(listOf(a, b), eps))

        assertEquals("warning", cfg.getJSONObject("log").getString("loglevel"))
        assertEquals(listOf("1.1.1.1", "8.8.8.8", "77.88.8.8"),
            (0 until 3).map { cfg.getJSONObject("dns").getJSONArray("servers").getString(it) })

        val inbounds = cfg.getJSONArray("inbounds")
        assertEquals(2, inbounds.length())
        val in0 = inbounds.getJSONObject(0)
        assertEquals("127.0.0.1", in0.getString("listen"))
        assertEquals(41001, in0.getInt("port"))
        assertEquals("socks", in0.getString("protocol"))
        assertEquals("password", in0.getJSONObject("settings").getString("auth"))
        assertTrue(in0.getJSONObject("settings").getBoolean("udp"))
        assertEquals("ua", in0.getJSONObject("settings").getJSONArray("accounts").getJSONObject(0).getString("user"))

        val outbounds = cfg.getJSONArray("outbounds")
        assertEquals("out-0", outbounds.getJSONObject(0).getString("tag"))
        assertEquals("UseIPv4", outbounds.getJSONObject(1).getJSONObject("streamSettings")
            .getJSONObject("sockopt").getString("domainStrategy"))

        val rules = cfg.getJSONObject("routing").getJSONArray("rules")
        assertEquals("in-1", rules.getJSONObject(1).getJSONArray("inboundTag").getString(0))
        assertEquals("out-1", rules.getJSONObject(1).getString("outboundTag"))
    }

    @Test fun serversWithoutEndpointAreLeftOutAndEmptyIsRefused() {
        val a = server("trojan://pw@a.example.com:4000?type=kcp", "A")
        val b = server("trojan://pw@b.example.com:4000?type=kcp", "B")
        val cfg = JSONObject(XrayConfigBuilder.build(listOf(a, b), mapOf(b.id to XrayEndpoint(5, "u", "p"))))
        assertEquals(1, cfg.getJSONArray("inbounds").length())
        assertThrows(IllegalArgumentException::class.java) { XrayConfigBuilder.build(listOf(a), emptyMap()) }
    }

    @Test fun signatureTracksXrayServersOnly() {
        val a = server("trojan://pw@a.example.com:4000?type=kcp", "A")
        val plain = LinkParser.parse("trojan://pw@t.example.com:443")
        assertEquals(XrayConfigBuilder.signature(listOf(a)), XrayConfigBuilder.signature(listOf(plain, a)))
        val changed = server("trojan://pw2@a.example.com:4000?type=kcp", "A")
        assertNotEquals(XrayConfigBuilder.signature(listOf(a)), XrayConfigBuilder.signature(listOf(changed)))
    }

    @Test fun contentDerivedIdsAreStable() {
        val link = "trojan://pw@a.example.com:4000?type=kcp"
        assertEquals(server(link, "A").id, server(link, "A").id)
        assertTrue(server(link, "A").id.startsWith("xr-"))
    }

    // ───────────── sing-box side ─────────────

    @Test fun xrayServerBecomesSocksOutboundInTheSelector() {
        val x = server("vless://$uuid@a.example.com:443?type=xhttp&security=tls", "X")
        val t = LinkParser.parse("trojan://pw@t.example.com:443")
        val json = JSONObject(
            SingBoxConfigGenerator.generate(
                listOf(t, x), x.id, 10808, "u", "p", mapOf(x.id to XrayEndpoint(41001, "xu", "xp"))
            )
        )
        val outs = json.getJSONArray("outbounds")
        val socks = (0 until outs.length()).map { outs.getJSONObject(it) }.first { it.getString("tag") == x.id }
        assertEquals("socks", socks.getString("type"))
        assertEquals("127.0.0.1", socks.getString("server"))
        assertEquals(41001, socks.getInt("server_port"))
        assertEquals("5", socks.getString("version"))
        assertEquals("xu", socks.getString("username"))
        assertEquals("xp", socks.getString("password"))
        val selector = outs.getJSONObject(0)
        assertEquals(x.id, selector.getString("default"))
        assertEquals(2, selector.getJSONArray("outbounds").length())
    }

    @Test fun xrayServerWithoutEndpointIsDroppedAndSelectorFallsBack() {
        val x = server("vless://$uuid@a.example.com:443?type=xhttp&security=tls", "X")
        val t = LinkParser.parse("trojan://pw@t.example.com:443")
        val json = JSONObject(SingBoxConfigGenerator.generate(listOf(x, t), x.id, 1, "u", "p"))
        val selector = json.getJSONArray("outbounds").getJSONObject(0)
        assertEquals(t.id, selector.getString("default"))
        assertEquals(1, selector.getJSONArray("outbounds").length())
        assertThrows(IllegalArgumentException::class.java) {
            SingBoxConfigGenerator.generate(listOf(x), x.id, 1, "u", "p")
        }
    }

    @Test fun validatorUnavailableXrayIsReportedAsSuchNotAsCoreRejection() {
        val x = server("trojan://pw@a.example.com:4000?type=kcp", "X")
        val v = object : ServerValidator {
            override fun validate(config: VpnConfig) = ServerValidator.XRAY_UNAVAILABLE
        }
        assertEquals("xray core unavailable", v.filter(listOf(x)).rejected.single().reason)
    }
}
