package com.telegram.vpncore

/**
 * Base64 decoder that accepts whatever real subscriptions send.
 *
 * Panels disagree on everything the RFC leaves room for: standard or URL-safe alphabet,
 * padding present or stripped, and line breaks wrapped into the payload. `android.util.Base64`
 * needs the caller to pick flags up front (and throws when guessed wrong); it is also a stub
 * on the JVM, which would keep the parsers out of unit tests. This one takes all variants.
 */
object LenientBase64 {

    private val INDEX = IntArray(128) { -1 }.also { table ->
        val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        alphabet.forEachIndexed { i, c -> table[c.code] = i }
        table['-'.code] = 62 // URL-safe alphabet
        table['_'.code] = 63
    }

    /** Decoded bytes, or null when [input] is not base64 in any of the accepted variants. */
    fun decode(input: String): ByteArray? {
        val sextets = ArrayList<Int>(input.length)
        for (c in input) {
            if (c.isWhitespace() || c == '=') continue
            val v = if (c.code < 128) INDEX[c.code] else -1
            if (v < 0) return null
            sextets.add(v)
        }
        // A single leftover sextet carries only 6 bits: never produced by a real encoder.
        if (sextets.size % 4 == 1) return null

        val out = ByteArray(sextets.size * 6 / 8)
        var acc = 0
        var bits = 0
        var o = 0
        for (v in sextets) {
            acc = (acc shl 6) or v
            bits += 6
            if (bits >= 8) {
                bits -= 8
                out[o++] = ((acc shr bits) and 0xFF).toByte()
            }
        }
        return out
    }

    /** [decode] as UTF-8 text, or null. */
    fun decodeToString(input: String): String? = decode(input)?.toString(Charsets.UTF_8)
}
