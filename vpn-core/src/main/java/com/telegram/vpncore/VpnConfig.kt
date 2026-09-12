package com.telegram.vpncore

import android.os.Parcelable
import kotlinx.parcelize.Parcelize

enum class VpnProtocol {
    VLESS, VMESS, SHADOWSOCKS, TROJAN, HYSTERIA2, NAIVE,

    /** Any sing-box outbound type we have no dedicated label for; see [VpnConfig.rawType]. */
    OTHER
}

enum class NetworkType {
    TCP, WS, GRPC, H2, QUIC, HTTPUPGRADE
}

enum class SecurityType {
    NONE, TLS, REALITY
}

@Parcelize
data class VpnConfig(
    val id: String = java.util.UUID.randomUUID().toString(),
    val name: String = "",
    val protocol: VpnProtocol,
    val address: String,
    val port: Int,

    // Auth
    val uuid: String = "",       // VLESS, VMess
    val password: String = "",   // Shadowsocks, Trojan

    // VLESS / VMess specific
    val encryption: String = "none",
    val flow: String = "",       // e.g. "xtls-rprx-vision"
    val alterId: Int = 0,        // VMess

    // Transport
    val network: NetworkType = NetworkType.TCP,
    val path: String = "",       // WS / H2 path
    val host: String = "",       // WS host header
    val serviceName: String = "", // gRPC service name

    // TLS / Reality
    val security: SecurityType = SecurityType.NONE,
    val sni: String = "",
    val fingerprint: String = "chrome",

    // Reality only
    val publicKey: String = "",
    val shortId: String = "",
    val spiderX: String = "",

    // Shadowsocks specific
    val ssMethod: String = "aes-256-gcm",

    // Hysteria2 specific
    val obfsPassword: String = "",  // salamander obfuscation; empty = no obfuscation
    val upMbps: Int = 0,            // 0 = let the server decide (BBR)
    val downMbps: Int = 0,

    // Naive / http-CONNECT specific
    val username: String = "",

    // Accept a server certificate that doesn't validate. Only set from an explicit
    // allowInsecure/insecure flag in the link — never defaulted on.
    val allowInsecure: Boolean = false,

    val rawLink: String = "",

    // Set when this config came from a sing-box-format subscription: the server's own
    // outbound object, verbatim. When present it is used as-is instead of rebuilding the
    // outbound from the fields above — the panel already generates exactly what the core
    // expects, so there is nothing for us to get subtly wrong.
    val rawOutbound: String = "",
    /** sing-box outbound type as the server named it. Only meaningful with [rawOutbound]. */
    val rawType: String = "",

    // Outbounds this server dials *through*, verbatim, as a JSON array — the panel emits
    // ShadowTLS as a chain: a shadowsocks outbound whose "detour" names a separate shadowtls
    // outbound. Those links are not servers of their own, so they are carried here instead of
    // appearing in the list; without them the core rejects the whole config with
    // "dependency[...] not found for outbound[...]".
    val rawDependencies: String = ""
) : Parcelable {
    val displayName: String get() = name.ifBlank { "$address:$port" }
    val protocolLabel: String get() = when (protocol) {
        VpnProtocol.VLESS -> "VLESS"
        VpnProtocol.VMESS -> "VMess"
        VpnProtocol.SHADOWSOCKS -> "Shadowsocks"
        VpnProtocol.TROJAN -> "Trojan"
        VpnProtocol.HYSTERIA2 -> "Hysteria2"
        VpnProtocol.NAIVE -> "Naive"
        VpnProtocol.OTHER -> rawType.ifBlank { "Proxy" }
    }
}
