package com.telegram.vpncore

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Clash YAML, xray JSON, SIP008 / Outline, and the detection order between formats. */
class FormatsTest {

    private fun fixture(name: String): String =
        javaClass.getResourceAsStream("/subscriptions/$name")!!.bufferedReader(Charsets.UTF_8).readText()

    private fun parse(name: String) = SubscriptionFetcher.parseSubscription(fixture(name))
    private fun ParseResult.ob(name: String) = JSONObject(servers.first { it.name == name }.rawOutbound)

    // ───────────────────────── Clash ─────────────────────────

    @Test fun clashMixedProfile() {
        val r = parse("clash.yaml")
        assertEquals(17, r.servers.size)
        assertEquals(
            mapOf(
                "unsupported ss plugin kcptun" to 1,
                "unsupported type ssr" to 1
            ),
            r.skipCounts
        )
        // proxy-groups / rules are not servers.
        assertFalse(r.servers.any { it.name == "Auto" })

        val obfs = r.ob("SS obfs")
        assertEquals("shadowsocks", obfs.getString("type"))
        assertEquals("obfs-local", obfs.getString("plugin"))
        assertEquals("obfs=tls;obfs-host=bing.com", obfs.getString("plugin_opts"))

        val v2 = r.ob("SS v2ray 🚀")
        assertEquals(443, v2.getInt("server_port")) // port given as a string
        assertEquals("v2ray-plugin", v2.getString("plugin"))
        assertEquals("tls;host=ss2.example.com;path=/ws", v2.getString("plugin_opts"))

        val vmess = r.ob("VMess WS")
        assertEquals("ws", vmess.getJSONObject("transport").getString("type"))
        assertEquals("cdn.example.com", vmess.getJSONObject("transport").getJSONObject("headers").getString("Host"))
        assertTrue(vmess.getJSONObject("tls").getBoolean("insecure"))
        assertEquals("auto", vmess.getString("security"))

        val reality = r.ob("VLESS Reality")
        assertEquals("xtls-rprx-vision", reality.getString("flow"))
        val rtls = reality.getJSONObject("tls")
        assertEquals("PUBKEY123", rtls.getJSONObject("reality").getString("public_key"))
        assertEquals("ab12", rtls.getJSONObject("reality").getString("short_id"))
        assertEquals("firefox", rtls.getJSONObject("utls").getString("fingerprint"))
        assertEquals("www.example.org", rtls.getString("server_name"))

        assertEquals("svc", r.ob("VLESS gRPC").getJSONObject("transport").getString("service_name"))
        assertEquals("h2", r.ob("VLESS gRPC").getJSONObject("tls").getJSONArray("alpn").getString(0))
        val h2 = r.ob("VLESS H2").getJSONObject("transport")
        assertEquals("http", h2.getString("type"))
        assertEquals("/h2", h2.getString("path"))
        // Clash "http" network is HTTP header obfuscation over TCP, which only xray speaks:
        // it runs in the xray process, as a tcp stream with an http header.
        val http = JSONObject(r.servers.first { it.name == "VLESS HTTP" }.rawOutbound)
        assertEquals("xray", r.servers.first { it.name == "VLESS HTTP" }.rawType)
        val tcp = http.getJSONObject("streamSettings").getJSONObject("tcpSettings").getJSONObject("header")
        assertEquals("http", tcp.getString("type"))
        assertEquals("/a", tcp.getJSONObject("request").getJSONArray("path").getString(0))

        val trojan = r.ob("Trojan WS")
        assertEquals("httpupgrade", trojan.getJSONObject("transport").getString("type"))
        assertEquals("tr.example.com", trojan.getJSONObject("tls").getString("server_name"))

        val hy2 = r.ob("Hy2")
        assertEquals(50, hy2.getInt("up_mbps"))
        assertEquals(200, hy2.getInt("down_mbps"))
        assertEquals("20000:30000", hy2.getJSONArray("server_ports").getString(0))
        assertEquals("40000:40000", hy2.getJSONArray("server_ports").getString(1))
        assertEquals("30s", hy2.getString("hop_interval"))
        assertEquals("obfspw", hy2.getJSONObject("obfs").getString("password"))
        val hy1 = r.ob("Hysteria1")
        assertEquals("authpass", hy1.getString("auth_str"))
        assertEquals(30, hy1.getInt("up_mbps"))

        val tuic = r.ob("TUIC")
        assertEquals("bbr", tuic.getString("congestion_control"))
        assertEquals("native", tuic.getString("udp_relay_mode"))

        val wg = r.ob("WG")
        assertEquals("wireguard", wg.getString("type"))
        assertEquals(2, wg.getJSONArray("address").length())
        assertEquals(3, wg.getJSONArray("peers").getJSONObject(0).getJSONArray("reserved").length())
        assertEquals("wg.example.com", r.servers.first { it.name == "WG" }.address)

        assertEquals("bob", r.ob("SOCKS").getString("username"))
        assertTrue(r.ob("HTTP TLS").getJSONObject("tls").getBoolean("enabled"))
        assertEquals("anypw", r.ob("AnyTLS").getString("password"))
        assertEquals("root", r.ob("SSH").getString("user"))
    }

    @Test fun clashXhttpEntryRunsInXray() {
        val r = parse("clash.yaml")
        val s = r.servers.first { it.name == "VLESS XHTTP" }
        assertEquals("xray", s.rawType)
        val o = JSONObject(s.rawOutbound)
        assertEquals("vless", o.getString("protocol"))
        assertEquals("xhttp", o.getJSONObject("streamSettings").getString("network"))
        assertEquals("xh.example.com", s.address)
        assertTrue(r.xrayCapable.isEmpty())
    }

    @Test fun clashIdsAreStableAcrossParses() {
        assertEquals(parse("clash.yaml").servers.map { it.id }, parse("clash.yaml").servers.map { it.id })
    }

    @Test fun clashYamlBombIsRejectedNotExpanded() {
        val bomb = "proxies:\n  - &a [1]\n" + "  - *a\n".repeat(40)
        assertTrue(SubscriptionFetcher.parseSubscription(bomb).isEmpty)
    }

    @Test fun clashServersPassThroughTheConfigGenerator() {
        val servers = parse("clash.yaml").servers
        val json = JSONObject(SingBoxConfigGenerator.generate(servers, servers.first().id, 1, "u", "p"))
        assertEquals(1, json.getJSONArray("endpoints").length())
    }

    // ───────────────────────── xray JSON ─────────────────────────

    @Test fun xrayArrayRemnawaveStyle() {
        val r = parse("xray_array.json")
        assertEquals(
            listOf("🇩🇪 DE Reality", "NL VMess WS", "FI Trojan gRPC", "SE SS", "PL HTTPUpgrade", "FR XHTTP", "AT mKCP"),
            r.servers.map { it.name }
        )
        val de = r.ob("🇩🇪 DE Reality")
        assertEquals("vless", de.getString("type"))
        assertEquals("de.example.com", de.getString("server"))
        assertEquals("xtls-rprx-vision", de.getString("flow"))
        assertEquals("PUBKEY123", de.getJSONObject("tls").getJSONObject("reality").getString("public_key"))

        val nl = r.ob("NL VMess WS")
        assertEquals("cdn.example.com", nl.getJSONObject("transport").getJSONObject("headers").getString("Host"))
        assertTrue(nl.getJSONObject("tls").getBoolean("insecure"))
        assertEquals(2, nl.getJSONObject("tls").getJSONArray("alpn").length())

        assertEquals("grpc", r.ob("FI Trojan gRPC").getJSONObject("transport").getString("type"))
        assertEquals("fi.example.com", r.ob("FI Trojan gRPC").getJSONObject("tls").getString("server_name"))
        assertEquals("aes-256-gcm", r.ob("SE SS").getString("method"))
        assertEquals("/up", r.ob("PL HTTPUpgrade").getJSONObject("transport").getString("path"))
    }

    @Test fun xrayXhttpAndKcpRunInXrayAsIs() {
        val r = parse("xray_array.json")
        assertTrue(r.skipped.isEmpty())
        val x = JSONObject(r.servers.first { it.name == "FR XHTTP" }.rawOutbound)
        assertEquals("vless", x.getString("protocol"))
        assertEquals("/x", x.getJSONObject("streamSettings").getJSONObject("xhttpSettings").getString("path"))
        assertFalse(x.has("tag")) // the process config assigns its own tags
        assertEquals("kcp", JSONObject(r.servers.first { it.name == "AT mKCP" }.rawOutbound)
            .getJSONObject("streamSettings").getString("network"))
        assertEquals(setOf("FR XHTTP", "AT mKCP"), r.servers.filter { it.rawType == "xray" }.map { it.name }.toSet())
    }

    @Test fun xrayDialerProxyChainIsSkippedNotSentDirect() {
        val text = """{"outbounds":[{"tag":"a","protocol":"vless","settings":{"vnext":[{"address":"a.example.com","port":443,"users":[{"id":"u"}]}]},
          "streamSettings":{"network":"tcp","sockopt":{"dialerProxy":"other"}}}]}"""
        val r = SubscriptionFetcher.parseSubscription(text)
        assertTrue(r.servers.isEmpty())
        assertEquals(mapOf("unsupported dialerProxy chain" to 1), r.skipCounts)
    }

    @Test fun singleXrayConfig() {
        val r = parse("xray_single.json")
        assertEquals(1, r.servers.size)
        val c = r.servers.single()
        assertEquals("one.example.com", c.address)
        assertEquals(8443, c.port)
        assertEquals("one.example.com:8443", c.name)
        assertEquals("/ws", JSONObject(c.rawOutbound).getJSONObject("transport").getString("path"))
    }

    @Test fun xrayIsNotMistakenForSingBox() {
        assertFalse(SingBoxSubscriptionParser.looksLikeSingBoxConfig(fixture("xray_single.json")))
        assertTrue(SingBoxSubscriptionParser.looksLikeSingBoxConfig(fixture("singbox_marzban.json")))
        assertFalse(XrayJsonParser.looksLikeXray(fixture("singbox_marzban.json")))
        assertTrue(XrayJsonParser.looksLikeXray(fixture("xray_array.json")))
    }

    @Test fun xrayTcpHttpHeaderAndVlessEncryption() {
        val text = """{"outbounds":[
          {"tag":"a","protocol":"vless","settings":{"vnext":[{"address":"a.example.com","port":80,"users":[{"id":"u","encryption":"none"}]}]},
           "streamSettings":{"network":"tcp","tcpSettings":{"header":{"type":"http"}}}},
          {"tag":"b","protocol":"vless","settings":{"vnext":[{"address":"b.example.com","port":443,"users":[{"id":"u","encryption":"mlkem768x25519plus.native.0rtt.k"}]}]}}
        ]}"""
        val r = SubscriptionFetcher.parseSubscription(text)
        assertEquals(2, r.servers.size)
        assertTrue(r.servers.all { it.rawType == "xray" })
        assertTrue(r.skipped.isEmpty())
    }

    // ───────────────────────── SIP008 / Outline ─────────────────────────

    @Test fun sip008() {
        val r = parse("sip008.json")
        assertEquals(listOf("SIP008 plain", "SIP008 obfs 🚀"), r.servers.map { it.name })
        assertEquals(VpnProtocol.SHADOWSOCKS, r.servers[0].protocol)
        assertEquals("aes-256-gcm", r.servers[0].ssMethod)
        assertEquals(8388, r.servers[0].port)
        assertEquals("obfs-local", r.servers[1].ssPlugin)
        assertEquals("obfs=tls;obfs-host=bing.com", r.servers[1].ssPluginOpts)
        assertEquals(mapOf("unsupported ss plugin kcptun" to 1, "invalid link" to 1), r.skipCounts)
    }

    @Test fun ssconfLinkIsFetchedFromItsHttpsUrl() {
        var requested: String? = null
        val r = SubscriptionFetcher.parseSubscription("ssconf://keys.example.com/abc/def.json#My%20Outline") { url ->
            requested = url
            """{"server":"o.example.com","server_port":443,"password":"pw","method":"chacha20-ietf-poly1305"}"""
        }
        assertEquals("https://keys.example.com/abc/def.json", requested)
        val c = r.servers.single()
        assertEquals("My Outline", c.name)
        assertEquals("o.example.com", c.address)
    }

    @Test fun ssconfUnreachableOrWithPrefixIsReported() {
        val unreachable = SubscriptionFetcher.parseSubscription("ssconf://k.example.com/x") { null }
        assertEquals(mapOf("ssconf unreachable" to 1), unreachable.skipCounts)
        val prefixed = SubscriptionFetcher.parseSubscription("ssconf://k.example.com/x") {
            """{"server":"o.example.com","server_port":443,"password":"pw","method":"aes-256-gcm","prefix":"%16%03%01"}"""
        }
        assertEquals(mapOf("unsupported ss prefix" to 1), prefixed.skipCounts)
    }

    @Test fun ssconfToHttps() {
        assertEquals("https://h.example.com/p", SubscriptionFetcher.ssconfToHttps("ssconf://h.example.com/p#n"))
        assertNull(SubscriptionFetcher.ssconfToHttps("https://h.example.com/p"))
    }

    @Test fun outlineServerObjectAsWholeBody() {
        val r = SubscriptionFetcher.parseSubscription(
            """{"server":"o.example.com","server_port":443,"password":"pw","method":"aes-256-gcm"}"""
        )
        assertEquals(1, r.servers.size)
    }
}
