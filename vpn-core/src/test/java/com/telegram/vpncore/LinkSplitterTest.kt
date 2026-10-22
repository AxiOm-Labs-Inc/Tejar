package com.telegram.vpncore

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class LinkSplitterTest {

    @Test fun fullLink() {
        val l = ParsedLink.parse("vless://uuid-1@example.com:8443/some/path?type=ws&path=%2Fa%20b&sni=x.org#My%20Node")
        assertEquals("vless", l.scheme)
        assertEquals("uuid-1", l.userInfo)
        assertEquals("example.com", l.host)
        assertEquals(8443, l.port)
        assertEquals("/some/path", l.path)
        assertEquals("ws", l.queryParam("type"))
        assertEquals("/a b", l.queryParam("path"))
        assertEquals("My Node", l.fragment)
    }

    @Test fun ipv6HostWithAndWithoutPort() {
        val a = ParsedLink.parse("trojan://p@[2001:db8::1]:443#n")
        assertEquals("2001:db8::1", a.host)
        assertEquals(443, a.port)
        val b = ParsedLink.parse("trojan://p@[::1]#n")
        assertEquals("::1", b.host)
        assertEquals(-1, b.port)
    }

    @Test fun unencodedSpacesEmojiAndPipeInFragment() {
        val l = ParsedLink.parse("vless://u@h.example.com:443?type=tcp#🇩🇪 Germany | fast ⚡")
        assertEquals("🇩🇪 Germany | fast ⚡", l.fragment)
        assertEquals("h.example.com", l.host)
    }

    @Test fun percentDecodedEmojiAndMalformedEscape() {
        assertEquals("⚡ 100%", ParsedLink.parse("x://h:1#%E2%9A%A1%20100%").fragment)
        assertEquals("a%zzb", ParsedLink.parse("x://h:1#a%zzb").fragment)
    }

    @Test fun lastAtSignSplitsCredentials() {
        val l = ParsedLink.parse("trojan://pa@ss@host.example.com:443")
        assertEquals("pa@ss", l.userInfo)
        assertEquals("host.example.com", l.host)
    }

    @Test fun queryPlusIsSpaceFirstKeyWinsAndBareKey() {
        val l = ParsedLink.parse("x://h:1?a=1+2&a=second&flag&e=")
        assertEquals("1 2", l.queryParam("a"))
        assertEquals("", l.queryParam("flag"))
        assertEquals("", l.queryParam("e"))
        assertNull(l.queryParam("missing"))
    }

    @Test fun noUserInfoNoPort() {
        val l = ParsedLink.parse("https://example.com/p")
        assertNull(l.userInfo)
        assertEquals(-1, l.port)
        assertEquals("example.com", l.host)
    }

    @Test fun nonNumericPortIsAbsent() = assertEquals(-1, ParsedLink.parse("x://u@h:abc").port)
}
