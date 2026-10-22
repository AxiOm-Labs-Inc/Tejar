package com.telegram.vpncore

import android.util.Log
import org.json.JSONArray
import org.json.JSONObject

/**
 * Shadowsocks-only JSON subscriptions: SIP008 online configuration delivery
 * (`{"version":1,"servers":[...]}`) and a single Outline server object, which is what an
 * `ssconf://` dynamic access key serves (`{"server","server_port","password","method"}`).
 */
object Sip008Parser {

    private const val TAG = "Sip008Parser"

    fun looksLikeSip008(text: String): Boolean {
        val trimmed = text.trimStart()
        if (!trimmed.startsWith("{")) return false
        return try {
            val j = JSONObject(trimmed)
            (j.optJSONArray("servers")?.optJSONObject(0)?.let { isServer(it) } == true) || isServer(j)
        } catch (_: Exception) {
            false
        }
    }

    private fun isServer(j: JSONObject) = j.has("server") && j.has("method") && j.has("password")

    fun parse(text: String, fallbackName: String = ""): ParseResult {
        val j = JSONObject(text.trim())
        val servers = j.optJSONArray("servers")
            ?: JSONArray().put(j) // a lone Outline server object
        val results = ArrayList<VpnConfig>()
        val skipped = ArrayList<SkippedEntry>()
        for (i in 0 until servers.length()) {
            val s = servers.optJSONObject(i) ?: continue
            val name = s.optString("remarks").ifBlank { s.optString("name") }.ifBlank { fallbackName }
            try {
                results.add(toConfig(s, name))
            } catch (e: UnsupportedEntryException) {
                skipped.add(SkippedEntry(e.reason, name = name))
            } catch (e: Exception) {
                Log.w(TAG, "Skipping invalid SIP008 server: ${e.message}")
                skipped.add(SkippedEntry(SkippedEntry.INVALID_LINK, name = name))
            }
        }
        return ParseResult(results, skipped)
    }

    private fun toConfig(s: JSONObject, name: String): VpnConfig {
        // Outline's "prefix" disguises the first bytes of the stream; the core cannot do that.
        if (s.optString("prefix").isNotBlank()) throw UnsupportedEntryException("unsupported ss prefix")
        val port = s.optInt("server_port").takeIf { it in 1..65535 } ?: throw IllegalArgumentException("port")
        val (plugin, opts) = LinkParser.mapSsPlugin(s.optString("plugin"), s.optString("plugin_opts"))
        return VpnConfig(
            name = name,
            protocol = VpnProtocol.SHADOWSOCKS,
            address = s.getString("server").takeIf { it.isNotBlank() } ?: throw IllegalArgumentException("server"),
            port = port,
            password = s.getString("password"),
            ssMethod = s.getString("method"),
            ssPlugin = plugin,
            ssPluginOpts = opts
        )
    }
}
