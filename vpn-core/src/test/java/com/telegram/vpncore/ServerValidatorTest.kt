package com.telegram.vpncore

import org.junit.Assert.assertEquals
import org.junit.Test

class ServerValidatorTest {

    private class Fake(private val bad: Set<String>) : ServerValidator {
        override fun validate(config: VpnConfig): String? =
            if (config.name in bad) "unknown field \"secret-token\"" else null
    }

    private fun server(name: String) = VpnConfig(name = name, protocol = VpnProtocol.TROJAN, address = "h", port = 1)

    @Test fun dropsRejectedServersAndCountsThem() {
        val out = Fake(setOf("b", "d")).filter(listOf("a", "b", "c", "d").map(::server))
        assertEquals(listOf("a", "c"), out.valid.map { it.name })
        assertEquals(2, out.rejected.size)
        assertEquals(mapOf("rejected by core" to 2), ParseResult(emptyList(), out.rejected).skipCounts)
    }

    @Test fun reasonNeverContainsCoreMessage() {
        val out = Fake(setOf("a")).filter(listOf(server("a")))
        assertEquals("rejected by core", out.rejected.single().reason)
    }

    @Test fun allValidKeepsOrder() {
        val out = Fake(emptySet()).filter(listOf("x", "y").map(::server))
        assertEquals(listOf("x", "y"), out.valid.map { it.name })
        assertEquals(0, out.rejected.size)
    }
}
