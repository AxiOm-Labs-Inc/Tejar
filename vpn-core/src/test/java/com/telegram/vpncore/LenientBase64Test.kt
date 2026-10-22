package com.telegram.vpncore

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class LenientBase64Test {

    @Test fun standardPadded() = assertEquals("hello world", LenientBase64.decodeToString("aGVsbG8gd29ybGQ="))

    @Test fun missingPadding() {
        assertEquals("hello world", LenientBase64.decodeToString("aGVsbG8gd29ybGQ"))
        assertEquals("ab", LenientBase64.decodeToString("YWI"))
    }

    @Test fun urlSafeAlphabet() {
        // 0xFB 0xFF 0xBE -> "+/++" standard, "-_--" URL-safe
        assertArrayEquals(byteArrayOf(0xFB.toByte(), 0xFF.toByte(), 0xBE.toByte()), LenientBase64.decode("-_--"))
        assertArrayEquals(byteArrayOf(0xFB.toByte(), 0xFF.toByte(), 0xBE.toByte()), LenientBase64.decode("+/++"))
    }

    @Test fun whitespaceAndNewlinesInside() =
        assertEquals("hello world", LenientBase64.decodeToString("aGVs\r\nbG8g\n d29y bGQ=\n"))

    @Test fun utf8Roundtrip() = assertEquals("Привет 🚀", LenientBase64.decodeToString("0J/RgNC40LLQtdGCIPCfmoA"))

    @Test fun rejectsNonBase64() {
        assertNull(LenientBase64.decode("method:password"))
        assertNull(LenientBase64.decode("vless://abc"))
        assertNull(LenientBase64.decode("A")) // a lone sextet is impossible
    }

    @Test fun emptyIsEmpty() = assertEquals("", LenientBase64.decodeToString(""))
}
