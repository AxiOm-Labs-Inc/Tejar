package com.telegram.vpncore

import android.util.Log
import io.nekohasekai.libbox.Libbox

/**
 * Asks the core whether it would accept a server.
 *
 * The core validates a config as a whole: one outbound it cannot parse makes `checkConfig`
 * fail and every server stops working. Checking servers one at a time lets the bad ones be
 * dropped instead. An interface so the filtering logic is testable without the native library.
 */
interface ServerValidator {
    /** Null when the core accepts [config]; otherwise the core's error text. */
    fun validate(config: VpnConfig): String?
}

/** Real validator: `Libbox.checkConfig` on a config holding only this server (and its chain). */
class LibboxServerValidator(private val prepare: () -> Unit) : ServerValidator {
    override fun validate(config: VpnConfig): String? = try {
        prepare()
        val json = SingBoxConfigGenerator.generate(
            listOf(config), config.id, socksUser = "check", socksPass = "check"
        )
        Libbox.checkConfig(json)
        null
    } catch (e: Exception) {
        e.message ?: e.javaClass.simpleName
    }
}

/** Servers the validator accepted and the entries it turned away. */
data class ValidationOutcome(val valid: List<VpnConfig>, val rejected: List<SkippedEntry>)

private const val TAG = "ServerValidator"

fun ServerValidator.filter(servers: List<VpnConfig>): ValidationOutcome {
    val valid = ArrayList<VpnConfig>(servers.size)
    val rejected = ArrayList<SkippedEntry>()
    for (server in servers) {
        val error = validate(server)
        if (error == null) {
            valid.add(server)
        } else {
            // Type and the core's message only: no name, address or link.
            Log.w(TAG, "Core rejected a ${server.protocolLabel} server: ${error.take(160)}")
            rejected.add(SkippedEntry(SkippedEntry.REJECTED_BY_CORE))
        }
    }
    return ValidationOutcome(valid, rejected)
}
