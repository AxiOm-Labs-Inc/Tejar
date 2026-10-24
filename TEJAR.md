# Tejar — Telegram Android + VPN

Fork of [Telegram for Android](https://github.com/DrKLO/Telegram) with an integrated VPN/proxy
module (`vpn-core`) powered by [sing-box](https://github.com/SagerNet/sing-box).

**Current release:** [v1.5.2](https://github.com/AxiOm-Labs-Inc/Tejar/releases/latest) — Telegram 12.10.0 base, sing-box core, Hysteria2 and NaiveProxy support.

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

## Google Play build

Module `TMessagesProj_App` (package `com.tejar.messenger`, no suffix) is the Play build;
`TMessagesProj_AppStandalone` (`com.tejar.messenger.web`) stays the website/GitHub build.

```bash
./gradlew.bat :TMessagesProj_App:bundleBundleAfatRelease
# → TMessagesProj_App/build/outputs/bundle/bundleAfatRelease/*.aab
```

What differs from the standalone build:

- **No self-update.** `GithubUpdaterController` exists only in the standalone module, and
  `LaunchActivity.checkAppUpdate()` skips non-standalone builds — updates come from Play only.
- **No Telegram Premium / Stars purchases** (`BuildVars.IS_BILLING_UNAVAILABLE = true` in
  `TMessagesProj_App/.../ApplicationLoaderImpl.java`): a fork cannot sell them via Play Billing.
- Version: `versionCode = TEJAR_VERSION_CODE * 10 + abiVersionCode`, `versionName = TEJAR_VERSION_NAME`.

Before the first upload:

- **Signing:** `TMessagesProj/config/release.keystore` in git is the upstream dummy key.
  Use Play App Signing with your own upload key (keep it out of the repo, like the standalone key).
- **App icon:** both builds still use the Telegram paper-plane icon
  (`TMessagesProj/src/main/res/mipmap-*/ic_launcher*`, `icon_foreground*`). Telegram's API terms
  forbid using their logo, and Play treats it as impersonation — replace before submitting.
- **Xray child process:** `libxray.so` is bundled in the AAB (packaged with `useLegacyPackaging`),
  not downloaded at runtime, so it is allowed by Play's policy on executable code.
- **Play Console declarations:** `FOREGROUND_SERVICE_SPECIAL_USE` (vpn-core `ProxyForegroundService`)
  needs the foreground-service declaration with a justification and a short video.
  VpnService is not used, so the VPN declaration is not needed.
- **Listing:** say "unofficial Telegram client"; do not use the names Telegram or sing-box
  as the app name or in a way that implies endorsement.

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
| `APP_VERSION_*` | 12.10.0 / 7031 | Upstream Telegram base |
| `TEJAR_VERSION_*` | 1.5.2 / 6977 | Tejar release (APK versionCode = `6977*10 + abiCode`) |

The bundled cores are versioned separately: sing-box 1.13.19 (`libs/libbox.aar`, `SingBoxCore.VERSION`,
sent as `SFA/<version>` to panels) and Xray-core v26.3.27 (`xrayVersion` in `vpn-core/build.gradle`).

## License

Inherits GPL v2+ from upstream Telegram — see [LICENSE](LICENSE). The bundled Xray-core binary is MPL-2.0
(see "Xray core" above).
