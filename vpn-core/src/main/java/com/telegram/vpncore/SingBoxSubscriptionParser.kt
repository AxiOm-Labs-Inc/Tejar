package com.telegram.vpncore

import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest

/**
 * Reads a sing-box-format subscription (a full sing-box config document) and turns its
 * outbounds into [VpnConfig] entries.
 *
 * This is the format AxiOm v2 uses. The panel emits proxies the core can consume directly,
 * so each outbound is kept verbatim in [VpnConfig.rawOutbound] rather than being taken apart
 * and rebuilt. The parsed fields alongside it exist only for the UI (name, address, port).
 *
 * It also carries protocols the link format drops — most importantly Naive, which the panel's
 * base64-links generator omits entirely.
 */
object SingBoxSubscriptionParser {

    private const val TAG = "SingBoxSubParser"

    /** Outbound types that are routing constructs, not servers the user can pick. */
    private val NON_SERVER_TYPES = setOf("selector", "urltest", "direct", "block", "dns")

    /** Guard against a subscription whose detours form a loop, or an absurdly deep chain. */
    private const val MAX_CHAIN_DEPTH = 8

    /** True when [text] looks like a sing-box config document rather than a list of links. */
    fun looksLikeSingBoxConfig(text: String): Boolean {
        val trimmed = text.trimStart()
        if (!trimmed.startsWith("{")) return false
        return try {
            JSONObject(trimmed).has("outbounds")
        } catch (_: Exception) {
            false
        }
    }

    fun parse(text: String): List<VpnConfig> {
        val outbounds = JSONObject(text).optJSONArray("outbounds") ?: return emptyList()

        // Chains first. The panel renders ShadowTLS as two outbounds — the one the user picks
        // (shadowsocks) carries "detour" naming the other (shadowtls), which is a transport
        // link, not a destination of its own. Both look like servers here: both have a
        // server/server_port. Treating the link as a server put a phantom "STLS-…" entry in
        // the list, and — worse — left the real entry pointing at a tag no longer in the
        // config, so the core refused to start at all.
        val byTag = HashMap<String, JSONObject>()
        val chainLinks = HashSet<String>()
        for (i in 0 until outbounds.length()) {
            val outbound = outbounds.optJSONObject(i) ?: continue
            outbound.optString("tag").takeIf { it.isNotBlank() }?.let { byTag[it] = outbound }
            outbound.optString("detour").takeIf { it.isNotBlank() }?.let { chainLinks.add(it) }
        }

        val results = mutableListOf<VpnConfig>()
        val usedIds = HashSet<String>()
        for (i in 0 until outbounds.length()) {
            val outbound = outbounds.optJSONObject(i) ?: continue
            val type = outbound.optString("type")
            if (type.isBlank() || type in NON_SERVER_TYPES) continue
            val tag = outbound.optString("tag")
            if (tag in chainLinks) continue
            // A server outbound must say where to dial; anything else is a construct we
            // don't recognise and would only show as a dead entry in the list.
            val server = outbound.optString("server")
            val serverPort = outbound.optInt("server_port")
            if (server.isBlank() || serverPort == 0) {
                Log.w(TAG, "Skipping outbound '$type' without server/server_port")
                continue
            }
            // An unresolvable chain means we cannot reproduce this server at all. Dropping the
            // single entry is the honest outcome: emitting it without its links would fail the
            // whole config, and stripping the detour would dial the link's port with the wrong
            // protocol and look like a server that is merely broken.
            val dependencies = collectChain(outbound, byTag)
            if (dependencies == null) {
                Log.w(TAG, "Skipping '$type' server: its detour chain is incomplete")
                continue
            }
            results.add(
                VpnConfig(
                    id = uniqueStableId(type, tag, server, serverPort, usedIds),
                    name = tag.ifBlank { "$server:$serverPort" },
                    protocol = type.toVpnProtocol(),
                    address = server,
                    port = serverPort,
                    rawOutbound = outbound.toString(),
                    rawType = type,
                    rawDependencies = if (dependencies.length() == 0) "" else dependencies.toString()
                )
            )
        }
        Log.d(TAG, "Parsed ${results.size} servers from sing-box subscription " +
            "(${chainLinks.size} chain links folded in)")
        return results
    }

    /**
     * A server's id, derived from what identifies it on the panel so that it survives a refresh.
     *
     * Refreshing used to mint a fresh random id for every server, while the running core still
     * held the previous ids as its outbound tags. Two things broke as a result: picking a server
     * by hand asked the core for a tag it had never heard of, so instead of switching the
     * selector it tore the core down and started it again; and the core's own `urlTest` results,
     * keyed by those same tags, never matched the ids the screen was waiting on, so auto-select
     * waited out its timeout and announced that no server had responded. Stable ids also keep
     * measured latency and the active server across a refresh.
     *
     * [usedIds] guards the (panel-unlikely) case of two entries agreeing on all four fields:
     * a shared id would collapse them in the repository and duplicate a tag in the config.
     */
    private fun uniqueStableId(
        type: String,
        tag: String,
        server: String,
        port: Int,
        usedIds: MutableSet<String>
    ): String {
        val digest = MessageDigest.getInstance("SHA-256")
            .digest("$type|$tag|$server|$port".toByteArray(Charsets.UTF_8))
        val base = "sub-" + digest.take(8).joinToString("") { "%02x".format(it) }
        if (usedIds.add(base)) return base
        var n = 2
        while (!usedIds.add("$base-$n")) n++
        return "$base-$n"
    }

    /**
     * Walks the `detour` chain starting at [outbound] and returns every link along it,
     * verbatim and in order. Empty array when the outbound dials directly; null when a link
     * names a tag the subscription doesn't define, or when the chain loops.
     */
    private fun collectChain(outbound: JSONObject, byTag: Map<String, JSONObject>): JSONArray? {
        val chain = JSONArray()
        val seen = HashSet<String>()
        var current = outbound
        while (true) {
            val detour = current.optString("detour")
            if (detour.isBlank()) return chain
            if (!seen.add(detour) || chain.length() >= MAX_CHAIN_DEPTH) {
                Log.w(TAG, "Detour chain loops or is too deep at '$detour'")
                return null
            }
            val next = byTag[detour] ?: return null
            chain.put(next)
            current = next
        }
    }

    private fun String.toVpnProtocol(): VpnProtocol = when (this) {
        "vless" -> VpnProtocol.VLESS
        "vmess" -> VpnProtocol.VMESS
        "shadowsocks" -> VpnProtocol.SHADOWSOCKS
        "trojan" -> VpnProtocol.TROJAN
        "hysteria2" -> VpnProtocol.HYSTERIA2
        "http" -> VpnProtocol.NAIVE
        // Unknown types still work — the core gets the outbound verbatim — so they are kept
        // rather than dropped; only the label falls back to the raw type name.
        else -> VpnProtocol.OTHER
    }
}
