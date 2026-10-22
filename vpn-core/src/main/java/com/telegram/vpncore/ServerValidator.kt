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

    companion object {
        /** Returned for xray-run servers when the xray binary is not shipped / not executable. */
        const val XRAY_UNAVAILABLE = "xray core unavailable"
    }
}

/**
 * Real validator: `Libbox.checkConfig` on a config holding only this server (and its chain).
 * [xrayCheck] validates an xray-run server's own outbound (`xray run -test`); null skips that.
 */
class LibboxServerValidator(
    private val prepare: () -> Unit,
    private val xrayCheck: ((VpnConfig) -> String?)? = null
) : ServerValidator {
    override fun validate(config: VpnConfig): String? = try {
        prepare()
        val isXray = XrayConfigBuilder.isXray(config)
        if (isXray) xrayCheck?.invoke(config)?.let { return it }
        val json = SingBoxConfigGenerator.generate(
            listOf(config), config.id, socksUser = "check", socksPass = "check",
            // sing-box only sees a SOCKS outbound for an xray server; any endpoint will do.
            xrayEndpoints = if (isXray) mapOf(config.id to XrayEndpoint(1, "check", "check")) else emptyMap()
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
            rejected.add(
                SkippedEntry(
                    if (error == ServerValidator.XRAY_UNAVAILABLE) error else SkippedEntry.REJECTED_BY_CORE
                )
            )
        }
    }
    return ValidationOutcome(valid, rejected)
}
