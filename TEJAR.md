# Tejar — Telegram Android + VPN

Fork of [Telegram for Android](https://github.com/DrKLO/Telegram) with an integrated VPN/proxy
module (`vpn-core`) powered by [sing-box](https://github.com/SagerNet/sing-box).

**Current release:** [v1.6.0](https://github.com/AxiOm-Labs-Inc/Tejar/releases/latest) — Telegram 13.0.3 base, sing-box core plus a bundled Xray core, subscriptions in any common format.

## Features

- Built-in SOCKS5 proxy on `127.0.0.1:10808` — Telegram traffic routes through the tunnel without a separate VPN app.
- Subscriptions fetched in **sing-box format**; panel outbounds kept verbatim (full protocol support including Hysteria2 and Naive).
- Subscriptions in other formats too: share-link lists (base64/plain/HTML), Clash/Mihomo YAML, xray JSON, SIP008/Outline; servers the core rejects are dropped individually instead of stopping everything.
- Transports sing-box lacks (XHTTP, mKCP, TCP HTTP-header obfuscation) run in a bundled **Xray core** child process — see below.
- Latency measured by the core via `urlTest` (real protocol handshake, not TCP probes).
- Server switching via outbound selector — no core restart.
- In-app updates from GitHub Releases (`GithubUpdaterController`), with separate arm64 and armv7 APKs.

## Build

Requires Android Studio JBR 21, Android SDK 35, NDK 27.2+. See the developer guide in the parent
project's `docs/DEVELOPMENT.md` (local, not in this repo — contains signing secrets).

```bash
./gradlew.bat :TMessagesProj_AppStandalone:assembleAfatStandalone \
              :TMessagesProj_AppStandalone:assembleAfat32Standalone
```

The first build downloads Xray-core (about 20 MB per ABI) from the upstream GitHub release, checks it
against the SHA-256 pinned in `vpn-core/build.gradle` and caches it in `~/.gradle/tejar-xray/`; later
builds, including offline ones, use the cache. A digest mismatch fails the build.

Distributed package: `com.tejar.messenger.web` (standalone flavor with `.web` suffix).

## vpn-core module

| Component | Role |
|---|---|
| `SingBoxConfigGenerator.kt` | Builds sing-box JSON config |
| `SingBoxPlatform.kt` | `PlatformInterface` for libbox |
| `SingBoxCommandClient.kt` | Core lifecycle (`startOrReloadService`, `selectOutbound`) |
| `SingBoxLatency.kt` | Parses unsigned latency values from urlTest |
| `SubscriptionFetcher.kt` | Fetches subscription with `User-Agent: SFA/…` |
| `VpnProxyManager.kt` | Orchestrates proxy start/stop and Telegram bridge |
| `LinkParser.kt`, `ClashSubscriptionParser.kt`, `XrayJsonParser.kt`, `Sip008Parser.kt` | Subscription formats -> servers (+ skip reasons) |
| `XrayOutbounds.kt`, `XrayConfig.kt`, `XrayProcess.kt` | Xray core: outbound conversion, process config, child process |
| `libs/libbox.aar` | sing-box core (~93 MB) |

Parser unit tests (`./gradlew :vpn-core:testDebugUnitTest`) run on a plain JVM.

## Xray core

libbox (sing-box) and the old libv2ray are both gomobile builds that ship `go/Seq`, so they cannot
share one APK. Xray therefore runs as a separate **executable child process**; sing-box stays the only
in-process core and the only thing Telegram talks to.

- Servers that need xray (`rawType == "xray"`: XHTTP, mKCP, TCP+HTTP header, VLESS encryption...) are
  started in one xray process with a local SOCKS inbound per server (random port and credentials per
  session). sing-box sees each as a plain SOCKS outbound, so the selector, latency test, auto-select and
  manual switching work unchanged.
- The binary is the official upstream release, shipped as `libxray.so` (arm64-v8a: `Xray-android-arm64-v8a`,
  armeabi-v7a: `Xray-linux-arm32-v7a`, no android arm32 build exists) so that it lands in the app's native
  library directory; the app modules therefore set `useLegacyPackaging = true`. On other ABIs, or if the file
  is missing, xray servers are skipped with the reason "xray core unavailable".
- Lifecycle: started before sing-box, stopped after it (stop, Energy Saving pause, startup failure);
  restarted once if it dies while connected.
- No geoip/geosite data is shipped; xray gets explicit DNS servers and resolves IPv4 only.

**Licence notice.** The bundled binary is [Xray-core](https://github.com/XTLS/Xray-core) v26.3.27 from the
unmodified upstream release, licensed under the Mozilla Public License 2.0. Source:
<https://github.com/XTLS/Xray-core/tree/v26.3.27>. To update, change `xrayVersion` and the pinned digests
(from the release's `.zip.dgst` files) in `vpn-core/build.gradle`.

## Versioning

Two independent version pairs in `gradle.properties`:

| Property | Current | Meaning |
|---|---|---|
| `APP_VERSION_*` | 13.0.3 / 7183 | Upstream Telegram base |
| `TEJAR_VERSION_*` | 1.6.0 / 6979 | Tejar release (APK versionCode = `6979*10 + abiCode`) |

The bundled cores are versioned separately: sing-box 1.13.19 (`libs/libbox.aar`, `SingBoxCore.VERSION`,
sent as `SFA/<version>` to panels) and Xray-core v26.3.27 (`xrayVersion` in `vpn-core/build.gradle`).

## License

Tejar as a whole is distributed under the **GNU GPL v3** — see [LICENSE](LICENSE) and
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

- Upstream Telegram for Android is GPL v2 **or later**; the bundled sing-box core (`libbox`) is GPL v3
  (with an extra condition on its name), so the combined work is GPL v3.
- The Xray-core binary is shipped unmodified as a separate program under MPL 2.0 (see "Xray core" above).
- Publish the matching source (a git tag) for every released build, including Play builds.
- "Telegram" and the paper-plane logo belong to Telegram; Tejar is an unofficial client and must not
  use Telegram's name as its own or its logo as the app icon.
