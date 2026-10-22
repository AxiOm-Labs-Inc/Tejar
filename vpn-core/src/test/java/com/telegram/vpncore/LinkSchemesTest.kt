package com.telegram.vpncore

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/** Schemes that become a sing-box outbound directly, plus transport/plugin/TLS options. */
class LinkSchemesTest {

    private val uuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    private fun raw(c: VpnConfig) = JSONObject(c.rawOutbound)

    @Test fun tuic() {
        val c = LinkParser.parse("tuic://$uuid:pw%40x@tuic.example.com:443?congestion_control=bbr&udp_relay_mode=native&alpn=h3,h2&sni=s.example.com&allow_insecure=1#TUIC 🚀")
        val o = raw(c)
        assertEquals("tuic", c.rawType)
        assertEquals("TUIC 🚀", c.name)
        assertEquals("tuic.example.com", c.address)
        assertEquals(443, c.port)
        assertEquals(uuid, o.getString("uuid"))
        assertEquals("pw@x", o.getString("password"))
        assertEquals("bbr", o.getString("congestion_control"))
        assertEquals("native", o.getString("udp_relay_mode"))
        val tls = o.getJSONObject("tls")
        assertEquals("s.example.com", tls.getString("server_name"))
        assertEquals(2, tls.getJSONArray("alpn").length())
        assertTrue(tls.getBoolean("insecure"))
        assertEquals(VpnProtocol.OTHER, c.protocol)
        assertEquals("tuic", c.protocolLabel)
    }

    @Test fun tuicWithoutPasswordIsInvalid() {
        assertThrows(IllegalArgumentException::class.java) { LinkParser.parse("tuic://$uuid@h.example.com:443") }
    }

    @Test fun hysteriaV1() {
        val c = LinkParser.parse("hysteria://hy.example.com:8443?auth=secret&peer=p.example.com&insecure=1&upmbps=50&downmbps=200&alpn=h3&obfs=xplus&obfsParam=obfspw#HY1")
        val o = raw(c)
        assertEquals("hysteria", c.rawType)
        assertEquals("secret", o.getString("auth_str"))
        assertEquals(50, o.getInt("up_mbps"))
        assertEquals(200, o.getInt("down_mbps"))
        assertEquals("obfspw", o.getString("obfs"))
        assertEquals("p.example.com", o.getJSONObject("tls").getString("server_name"))
        assertTrue(o.getJSONObject("tls").getBoolean("insecure"))
    }

    @Test fun hysteriaV1DefaultsAndUnsupportedProtocol() {
        val o = raw(LinkParser.parse("hysteria://hy.example.com:8443?auth=a"))
        assertEquals(100, o.getInt("up_mbps"))
        val e = assertThrows(UnsupportedEntryException::class.java) {
            LinkParser.parse("hysteria://hy.example.com:8443?auth=a&protocol=faketcp")
        }
        assertEquals("unsupported hysteria protocol faketcp", e.reason)
    }

    @Test fun hysteria2StillItsOwnScheme() {
        assertEquals(VpnProtocol.HYSTERIA2, LinkParser.parse("hysteria2://pw@h.example.com:443").protocol)
    }

    @Test fun hysteria2PortHoppingViaMport() {
        val c = LinkParser.parse("hysteria2://pw@hy.example.com:443?mport=20000-30000&sni=s.example.com&obfs=salamander&obfs-password=op&insecure=1#Hop")
        val o = raw(c)
        assertEquals(VpnProtocol.HYSTERIA2, c.protocol)
        assertEquals("hysteria2", c.rawType)
        assertEquals("20000:30000", o.getJSONArray("server_ports").getString(0))
        assertEquals(443, o.getInt("server_port"))
        assertEquals("pw", o.getString("password"))
        assertEquals("op", o.getJSONObject("obfs").getString("password"))
        assertEquals("s.example.com", o.getJSONObject("tls").getString("server_name"))
        assertTrue(o.getJSONObject("tls").getBoolean("insecure"))
        // Without mport the plain field-based config is unchanged.
        assertEquals("", LinkParser.parse("hysteria2://pw@hy.example.com:443").rawOutbound)
    }

    @Test fun hopPortsParsing() {
        assertEquals("[\"1000:2000\",\"3000:3000\"]", LinkParser.hopPorts("1000-2000,3000")!!.toString())
        assertNull(LinkParser.hopPorts("abc"))
        assertNull(LinkParser.hopPorts(null))
    }

    @Test fun anytls() {
        val c = LinkParser.parse("anytls://pw@any.example.com:8443?sni=s.example.com&insecure=1&fp=chrome#Any")
        val o = raw(c)
        assertEquals("anytls", c.rawType)
        assertEquals("pw", o.getString("password"))
        assertEquals("s.example.com", o.getJSONObject("tls").getString("server_name"))
        assertEquals("chrome", o.getJSONObject("tls").getJSONObject("utls").getString("fingerprint"))
        assertEquals(8443, c.port)
    }

    @Test fun wireguardIsAnEndpointObject() {
        val key = "yAnz5TF%2BlXXJte14tji3zlMNq%2BhdXmDTEQeFaaS0A1g%3D"
        val c = LinkParser.parse("wireguard://$key@wg.example.com:51820?publickey=Peer%2Bkey%3D&address=10.0.0.2,fd00::2&presharedkey=psk%3D&reserved=1,2,3&mtu=1280#WG")
        val o = raw(c)
        assertEquals("wireguard", c.rawType)
        assertEquals("wg.example.com", c.address)
        assertEquals(51820, c.port)
        assertEquals("yAnz5TF+lXXJte14tji3zlMNq+hdXmDTEQeFaaS0A1g=", o.getString("private_key"))
        assertEquals("10.0.0.2/32", o.getJSONArray("address").getString(0))
        assertEquals("fd00::2/128", o.getJSONArray("address").getString(1))
        assertEquals(1280, o.getInt("mtu"))
        val peer = o.getJSONArray("peers").getJSONObject(0)
        assertEquals("wg.example.com", peer.getString("address"))
        assertEquals("Peer+key=", peer.getString("public_key"))
        assertEquals("psk=", peer.getString("pre_shared_key"))
        assertEquals(3, peer.getJSONArray("reserved").length())
        assertEquals("0.0.0.0/0", peer.getJSONArray("allowed_ips").getString(0))
    }

    @Test fun wireguardKeyWithRawSlashAndWgAlias() {
        val c = LinkParser.parse("wg://ab/cd+ef=@wg.example.com:51820?publickey=P&address=10.0.0.2/32")
        assertEquals("ab/cd+ef=", raw(c).getString("private_key"))
        assertEquals("wg.example.com", c.address)
    }

    @Test fun wireguardMissingPartsInvalid() {
        assertThrows(IllegalArgumentException::class.java) { LinkParser.parse("wg://k@h.example.com:1?address=10.0.0.2/32") }
        assertThrows(IllegalArgumentException::class.java) { LinkParser.parse("wg://k@h.example.com:1?publickey=P") }
    }

    @Test fun socksPlainAndBase64() {
        val a = raw(LinkParser.parse("socks5://user:pa%24s@s.example.com:1080#S"))
        assertEquals("socks", a.getString("type"))
        assertEquals("5", a.getString("version"))
        assertEquals("user", a.getString("username"))
        assertEquals("pa\$s", a.getString("password"))

        val b64 = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString("bob:secret".toByteArray())
        val b = raw(LinkParser.parse("socks://$b64@s.example.com:1080"))
        assertEquals("bob", b.getString("username"))
        assertEquals("secret", b.getString("password"))

        val c = raw(LinkParser.parse("socks5://s.example.com:1080"))
        assertFalse(c.has("username"))
        assertEquals("4", raw(LinkParser.parse("socks4://s.example.com:1080")).getString("version"))
    }

    @Test fun httpWithCredentialsStillNaive() {
        assertEquals(VpnProtocol.NAIVE, LinkParser.parse("https://u:p@n.example.com:443").protocol)
    }

    // ───────────── shadowsocks plugins ─────────────

    @Test fun ssObfsPlugin() {
        val c = LinkParser.parse("ss://aes-256-gcm:pw@h.example.com:8388/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dcdn.example.com#O")
        assertEquals("obfs-local", c.ssPlugin)
        assertEquals("obfs=http;obfs-host=cdn.example.com", c.ssPluginOpts)
        assertEquals("obfs-local", LinkParser.parse("ss://aes-256-gcm:pw@h.example.com:8388?plugin=simple-obfs%3Bobfs%3Dtls").ssPlugin)
    }

    @Test fun ssV2rayPlugin() {
        val c = LinkParser.parse("ss://aes-256-gcm:pw@h.example.com:443?plugin=v2ray-plugin%3Btls%3Bhost%3Dh.example.com%3Bpath%3D%2Fws")
        assertEquals("v2ray-plugin", c.ssPlugin)
        assertEquals("tls;host=h.example.com;path=/ws", c.ssPluginOpts)
    }

    @Test fun ssUnknownPluginSkipped() {
        val e = assertThrows(UnsupportedEntryException::class.java) {
            LinkParser.parse("ss://aes-256-gcm:pw@h.example.com:443?plugin=kcptun%3Bkey%3Dx")
        }
        assertEquals("unsupported ss plugin kcptun", e.reason)
        assertFalse(e.xrayCapable)
    }

    @Test fun ssWithoutPluginHasNone() = assertEquals("", LinkParser.parse("ss://aes-256-gcm:pw@h.example.com:443").ssPlugin)

    // ───────────── vless / vmess / trojan options ─────────────

    @Test fun vlessTlsAlpnInsecure() {
        val c = LinkParser.parse("vless://$uuid@h.example.com:443?security=tls&sni=s.example.com&alpn=h2%2Chttp%2F1.1&allowInsecure=1&fp=firefox")
        assertEquals("h2,http/1.1", c.alpn)
        assertTrue(c.allowInsecure)
        assertEquals(SecurityType.TLS, c.security)
    }

    @Test fun tcpHttpHeaderNeedsXray() {
        val e = assertThrows(UnsupportedEntryException::class.java) {
            LinkParser.parse("vless://$uuid@h.example.com:443?type=tcp&headerType=http&host=x.example.com")
        }
        assertEquals("needs xray: tcp-http", e.reason)
        assertTrue(e.xrayCapable)
        assertEquals("needs xray: tcp-http", assertThrows(UnsupportedEntryException::class.java) {
            LinkParser.parse("trojan://pw@h.example.com:443?headerType=http")
        }.reason)
        // headerType=none is just plain tcp
        assertEquals(NetworkType.TCP, LinkParser.parse("vless://$uuid@h.example.com:443?type=tcp&headerType=none").network)
    }

    @Test fun vlessEncryptionNeedsXray() {
        val e = assertThrows(UnsupportedEntryException::class.java) {
            LinkParser.parse("vless://$uuid@h.example.com:443?encryption=mlkem768x25519plus.native.0rtt.abc")
        }
        assertEquals("needs xray: vless-encryption", e.reason)
        assertEquals(VpnProtocol.VLESS, LinkParser.parse("vless://$uuid@h.example.com:443?encryption=none").protocol)
    }

    @Test fun trojanAlpnAndInsecure() {
        val c = LinkParser.parse("trojan://pw@h.example.com:443?alpn=h2&allowInsecure=true")
        assertEquals("h2", c.alpn)
        assertTrue(c.allowInsecure)
    }

    @Test fun vmessJsonVariants() {
        fun link(json: String) = "vmess://" + java.util.Base64.getEncoder().encodeToString(json.toByteArray())
        val c = LinkParser.parse(link("""{"v":2,"ps":"V","add":"v.example.com","port":8443,"id":"$uuid","aid":"0","scy":"","net":"h2","type":"none","host":"h.example.com","path":"/p","tls":"tls","sni":"s.example.com","alpn":"h2,http/1.1","fp":"","allowInsecure":"1"}"""))
        assertEquals(8443, c.port)
        assertEquals(NetworkType.H2, c.network)
        assertEquals("auto", c.encryption)
        assertEquals("chrome", c.fingerprint)
        assertEquals("h2,http/1.1", c.alpn)
        assertTrue(c.allowInsecure)
        assertEquals("s.example.com", c.sni)

        val plain = LinkParser.parse(link("""{"add":"v.example.com","port":"443","id":"$uuid","aid":1,"net":"tcp","type":"none","tls":""}"""))
        assertEquals(1, plain.alterId)
        assertEquals(SecurityType.NONE, plain.security)
        assertFalse(plain.allowInsecure)

        assertEquals("needs xray: tcp-http", assertThrows(UnsupportedEntryException::class.java) {
            LinkParser.parse(link("""{"add":"v.example.com","port":"443","id":"$uuid","net":"tcp","type":"http"}"""))
        }.reason)
    }

    @Test fun looksLikeShareLinkCoversAllSchemes() {
        for (s in listOf("vless", "vmess", "ss", "trojan", "hysteria2", "hy2", "tuic", "hysteria", "anytls", "wireguard", "wg", "socks", "socks5", "naive+https")) {
            assertTrue(s, LinkParser.looksLikeShareLink("$s://x"))
        }
        assertFalse(LinkParser.looksLikeShareLink("https://example.com/sub"))
    }
}

class GeneratorEndpointTest {

    private fun server(raw: String, type: String, id: String) =
        VpnConfig(id = id, name = id, protocol = VpnProtocol.OTHER, address = "h", port = 1, rawOutbound = raw, rawType = type)

    @Test fun wireguardGoesToEndpointsAndSelector() {
        val wg = LinkParser.parse("wg://key@wg.example.com:51820?publickey=P&address=10.0.0.2/32")
        val trojan = LinkParser.parse("trojan://pw@t.example.com:443")
        val json = JSONObject(SingBoxConfigGenerator.generate(listOf(trojan, wg), trojan.id, 10808, "u", "p"))
        val endpoints = json.getJSONArray("endpoints")
        assertEquals(1, endpoints.length())
        assertEquals(wg.id, endpoints.getJSONObject(0).getString("tag"))
        val outbounds = json.getJSONArray("outbounds")
        val tags = (0 until outbounds.length()).map { outbounds.getJSONObject(it).getString("tag") }
        assertFalse(wg.id in tags)
        assertTrue(trojan.id in tags)
        val selector = outbounds.getJSONObject(0).getJSONArray("outbounds")
        assertEquals(setOf(trojan.id, wg.id), (0 until selector.length()).map { selector.getString(it) }.toSet())
    }

    @Test fun noEndpointsKeyWithoutWireguard() {
        val t = LinkParser.parse("trojan://pw@t.example.com:443")
        assertFalse(JSONObject(SingBoxConfigGenerator.generate(listOf(t), t.id, 1, "u", "p")).has("endpoints"))
    }

    @Test fun ssPluginAndAlpnReachTheOutbound() {
        val ss = LinkParser.parse("ss://aes-256-gcm:pw@h.example.com:8388?plugin=obfs-local%3Bobfs%3Dtls")
        val v = LinkParser.parse("vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@h.example.com:443?security=tls&alpn=h2,http/1.1")
        val json = JSONObject(SingBoxConfigGenerator.generate(listOf(ss, v), ss.id, 1, "u", "p"))
        val outs = json.getJSONArray("outbounds")
        fun find(tag: String) = (0 until outs.length()).map { outs.getJSONObject(it) }.first { it.getString("tag") == tag }
        assertEquals("obfs-local", find(ss.id).getString("plugin"))
        assertEquals("obfs=tls", find(ss.id).getString("plugin_opts"))
        assertEquals(2, find(v.id).getJSONObject("tls").getJSONArray("alpn").length())
    }
}
