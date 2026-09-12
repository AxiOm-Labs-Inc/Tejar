package com.telegram.vpncore

import org.json.JSONArray
import org.json.JSONObject

/**
 * Generates sing-box JSON configuration.
 *
 * Every known server becomes its own outbound and they are gathered under one selector,
 * exactly the shape the panel emits for sing-box clients. That is what makes the core's
 * own measurements usable: `urlTest` on the group dials each server over its real
 * protocol, which is the only honest way to time Hysteria2 (QUIC behind salamander
 * obfuscation ignores anything else) or NaiveProxy. It also lets a server change be a
 * `selectOutbound` call rather than a core restart.
 *
 * Output inbound: SOCKS5 on 127.0.0.1:[localPort], password-authenticated.
 */
object SingBoxConfigGenerator {

    /** Tag of the selector holding every server; `urlTest` and `selectOutbound` take it. */
    const val GROUP_TAG = "proxy"

    /**
     * @param servers every server to make available; each becomes an outbound tagged with
     *        its [VpnConfig.id], so measurements can be mapped back without ambiguity.
     * @param selectedId the server the selector starts on.
     */
    fun generate(
        servers: List<VpnConfig>,
        selectedId: String,
        localPort: Int = 10808,
        socksUser: String,
        socksPass: String
    ): String {
        require(servers.isNotEmpty()) { "No servers to build a config from" }
        // A server that dials through a chain whose links we don't have (an entry saved before
        // chains were parsed) makes the core reject the ENTIRE config — every other server goes
        // down with it. Leave those out; a subscription refresh restores them complete.
        val usable = servers.filter { it.rawDependencies.isNotBlank() || !dialsThroughChain(it) }
        require(usable.isNotEmpty()) { "No servers with a reproducible outbound" }
        val defaultTag = if (usable.any { it.id == selectedId }) selectedId else usable.first().id
        val root = JSONObject()

        // ── log ──────────────────────────────────────────────────
        root.put("log", JSONObject().apply {
            put("level", "warn")
        })

        // ── inbounds ─────────────────────────────────────────────
        root.put("inbounds", JSONArray().apply {
            put(JSONObject().apply {
                put("type", "socks")
                put("tag", "socks-in")
                put("listen", "127.0.0.1")
                put("listen_port", localPort)
                // 127.0.0.1 is reachable by every app on the device, not just this one —
                // require the per-install credentials from VpnProxyManager so other apps
                // can't ride the tunnel just by knowing the well-known local port.
                put("users", JSONArray().apply {
                    put(JSONObject().apply {
                        put("username", socksUser)
                        put("password", socksPass)
                    })
                })
            })
        })

        // ── outbounds ────────────────────────────────────────────
        root.put("outbounds", JSONArray().apply {
            put(JSONObject().apply {
                put("type", "selector")
                put("tag", GROUP_TAG)
                // Chain links are deliberately absent here: they are transports of a single
                // server, not destinations to pick or measure. The panel keeps them out of its
                // own selector the same way.
                put("outbounds", JSONArray().apply { usable.forEach { put(it.id) } })
                put("default", defaultTag)
                // Matches the panel's own config: switching server should drop the
                // connections still pinned to the previous one.
                put("interrupt_exist_connections", true)
            })
            usable.forEach { server ->
                val (outbound, links) = buildServerOutbounds(server)
                put(outbound)
                links.forEach { put(it) }
            }
            put(JSONObject().apply {
                put("type", "direct")
                put("tag", "direct")
            })
        })

        // ── route ────────────────────────────────────────────────
        // Private ranges are listed explicitly: there is no geoip database in the APK,
        // so "geoip:private" would fail to load.
        root.put("route", JSONObject().apply {
            put("final", "proxy")
            put("rules", JSONArray().apply {
                // Sniffing is a route action in sing-box (the inbound "sniff" field is
                // deprecated); it lets domain rules see real hostnames.
                put(JSONObject().apply {
                    put("action", "sniff")
                })
                put(JSONObject().apply {
                    put("ip_cidr", JSONArray().apply {
                        put("10.0.0.0/8")
                        put("172.16.0.0/12")
                        put("192.168.0.0/16")
                        put("127.0.0.0/8")
                        put("::1/128")
                        put("fc00::/7")
                    })
                    put("outbound", "direct")
                })
            })
        })

        // ── dns ──────────────────────────────────────────────────
        // Resolved directly, NOT through "proxy". The outbound server is given as a
        // hostname, so routing DNS through the proxy deadlocks: dialing the proxy needs
        // the hostname resolved, resolving needs the proxy up. The core then never opens
        // a single outbound connection. (Same direct-resolution behaviour the xray
        // config had; it does mean lookups leave outside the tunnel.)
        root.put("dns", JSONObject().apply {
            put("servers", JSONArray().apply {
                put(JSONObject().apply {
                    put("tag", "bootstrap")
                    put("address", "8.8.8.8")
                    put("detour", "direct")
                })
                put(JSONObject().apply {
                    put("tag", "fallback")
                    put("address", "1.1.1.1")
                    put("detour", "direct")
                })
            })
            put("strategy", "prefer_ipv4")
        })

        return root.toString(2)
    }

    // ─────────────────────────────────────────────────────────────

    /** True when this server's own outbound dials through a `detour` (a ShadowTLS chain). */
    private fun dialsThroughChain(config: VpnConfig): Boolean {
        if (config.rawOutbound.isBlank()) return false
        return try {
            JSONObject(config.rawOutbound).optString("detour").isNotBlank()
        } catch (_: Exception) {
            false
        }
    }

    /**
     * The server's outbound plus the chain links it dials through, if any.
     *
     * Link tags are rewritten to be unique per server: two servers may dial through links the
     * panel gave the same tag, and duplicate tags make the config invalid. Every `detour` that
     * names a rewritten link is repointed to match.
     */
    private fun buildServerOutbounds(config: VpnConfig): Pair<JSONObject, List<JSONObject>> {
        val main = buildProxyOutbound(config, config.id)
        if (config.rawDependencies.isBlank()) return main to emptyList()

        val raw = try {
            JSONArray(config.rawDependencies)
        } catch (_: Exception) {
            return main to emptyList()
        }

        val renamed = HashMap<String, String>()
        val links = ArrayList<JSONObject>(raw.length())
        for (i in 0 until raw.length()) {
            val link = raw.optJSONObject(i) ?: continue
            val originalTag = link.optString("tag")
            if (originalTag.isBlank()) continue
            val uniqueTag = "${config.id}-link-$originalTag"
            renamed[originalTag] = uniqueTag
            links.add(JSONObject(link.toString()).apply { put("tag", uniqueTag) })
        }

        (listOf(main) + links).forEach { outbound ->
            val detour = outbound.optString("detour")
            if (detour.isNotBlank()) renamed[detour]?.let { outbound.put("detour", it) }
        }
        return main to links
    }

    private fun buildProxyOutbound(config: VpnConfig, tag: String): JSONObject {
        // Subscriptions in sing-box format already carry a complete outbound. Reuse it rather
        // than rebuilding one from parsed fields: the panel generates what its own servers
        // expect, and every field we don't reproduce exactly is a connection that fails.
        if (config.rawOutbound.isNotBlank()) {
            return JSONObject(config.rawOutbound).apply { put("tag", tag) }
        }
        val outbound = JSONObject().apply {
            put("tag", tag)
            put("type", config.protocol.toSingBoxType())
            put("server", config.address)
            put("server_port", config.port)
        }

        when (config.protocol) {
            VpnProtocol.VLESS -> {
                outbound.put("uuid", config.uuid)
                if (config.flow.isNotBlank()) outbound.put("flow", config.flow)
            }
            VpnProtocol.VMESS -> {
                outbound.put("uuid", config.uuid)
                outbound.put("alter_id", config.alterId)
                outbound.put("security", "auto")
            }
            VpnProtocol.TROJAN -> {
                outbound.put("password", config.password)
            }
            VpnProtocol.SHADOWSOCKS -> {
                outbound.put("method", config.ssMethod)
                outbound.put("password", config.password)
            }
            VpnProtocol.HYSTERIA2 -> {
                outbound.put("password", config.password)
                if (config.obfsPassword.isNotBlank()) {
                    outbound.put("obfs", JSONObject().apply {
                        put("type", "salamander")
                        put("password", config.obfsPassword)
                    })
                }
                // 0 means "no explicit limit" — let the server's congestion control decide.
                if (config.upMbps > 0) outbound.put("up_mbps", config.upMbps)
                if (config.downMbps > 0) outbound.put("down_mbps", config.downMbps)
            }
            VpnProtocol.NAIVE -> {
                // NaiveProxy is HTTP CONNECT over TLS; sing-box speaks it as an http outbound.
                if (config.username.isNotBlank()) outbound.put("username", config.username)
                if (config.password.isNotBlank()) outbound.put("password", config.password)
            }
            // OTHER only ever comes from a sing-box subscription, which returns above.
            VpnProtocol.OTHER -> error("OTHER protocol requires rawOutbound")
        }

        buildTls(config)?.let { outbound.put("tls", it) }
        buildTransport(config)?.let { outbound.put("transport", it) }

        return outbound
    }

    /** Returns the `tls` block, or null when this config carries no TLS layer. */
    private fun buildTls(config: VpnConfig): JSONObject? {
        // Hysteria2 is QUIC — TLS is mandatory there and not expressed via SecurityType.
        // Naive follows its link scheme instead: https:// means TLS, http:// means none.
        val forced = config.protocol == VpnProtocol.HYSTERIA2
        if (!forced && config.security == SecurityType.NONE) return null

        return JSONObject().apply {
            put("enabled", true)
            val serverName = config.sni.ifBlank { config.host.ifBlank { config.address } }
            if (serverName.isNotBlank()) put("server_name", serverName)
            if (config.allowInsecure) put("insecure", true)

            if (config.security == SecurityType.REALITY) {
                put("reality", JSONObject().apply {
                    put("enabled", true)
                    put("public_key", config.publicKey)
                    if (config.shortId.isNotBlank()) put("short_id", config.shortId)
                })
                // REALITY requires uTLS; without it the handshake is rejected.
                put("utls", JSONObject().apply {
                    put("enabled", true)
                    put("fingerprint", config.fingerprint.ifBlank { "chrome" })
                })
            } else if (config.fingerprint.isNotBlank() && config.protocol != VpnProtocol.HYSTERIA2) {
                // Hysteria2 runs over QUIC and has no uTLS knob.
                put("utls", JSONObject().apply {
                    put("enabled", true)
                    put("fingerprint", config.fingerprint)
                })
            }
        }
    }

    /** Returns the `transport` block, or null for plain TCP (and for QUIC-native protocols). */
    private fun buildTransport(config: VpnConfig): JSONObject? {
        // Hysteria2 carries its own QUIC transport; Naive is plain HTTP CONNECT.
        if (config.protocol == VpnProtocol.HYSTERIA2 || config.protocol == VpnProtocol.NAIVE) return null

        return when (config.network) {
            NetworkType.TCP -> null
            NetworkType.WS -> JSONObject().apply {
                put("type", "ws")
                if (config.path.isNotBlank()) put("path", config.path)
                if (config.host.isNotBlank()) {
                    put("headers", JSONObject().apply { put("Host", config.host) })
                }
            }
            NetworkType.HTTPUPGRADE -> JSONObject().apply {
                put("type", "httpupgrade")
                if (config.path.isNotBlank()) put("path", config.path)
                if (config.host.isNotBlank()) put("host", config.host)
            }
            NetworkType.GRPC -> JSONObject().apply {
                put("type", "grpc")
                if (config.serviceName.isNotBlank()) put("service_name", config.serviceName)
            }
            NetworkType.H2 -> JSONObject().apply {
                put("type", "http")
                if (config.path.isNotBlank()) put("path", config.path)
                if (config.host.isNotBlank()) {
                    put("host", JSONArray().apply { put(config.host) })
                }
            }
            // sing-box has no standalone QUIC transport for VLESS/VMess the way xray did;
            // fall back to plain TCP rather than emitting a config the core will reject.
            NetworkType.QUIC -> null
        }
    }

    private fun VpnProtocol.toSingBoxType(): String = when (this) {
        VpnProtocol.VLESS -> "vless"
        VpnProtocol.VMESS -> "vmess"
        VpnProtocol.SHADOWSOCKS -> "shadowsocks"
        VpnProtocol.TROJAN -> "trojan"
        VpnProtocol.HYSTERIA2 -> "hysteria2"
        VpnProtocol.NAIVE -> "http"
        VpnProtocol.OTHER -> error("OTHER protocol requires rawOutbound")
    }
}
