# Tejar — Telegram Android + VPN

Fork of [Telegram for Android](https://github.com/DrKLO/Telegram) with an integrated VPN/proxy
module (`vpn-core`) powered by [sing-box](https://github.com/SagerNet/sing-box).

**Current release:** [v1.5.2](https://github.com/AxiOm-Labs-Inc/Tejar/releases/latest) — Telegram 12.10.0 base, sing-box core, Hysteria2 and NaiveProxy support.

## Features

- Built-in SOCKS5 proxy on `127.0.0.1:10808` — Telegram traffic routes through the tunnel without a separate VPN app.
- Subscriptions fetched in **sing-box format**; panel outbounds kept verbatim (full protocol support including Hysteria2 and Naive).
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
| `libs/libbox.aar` | sing-box core (~93 MB) |

## Versioning

Two independent version pairs in `gradle.properties`:

| Property | Current | Meaning |
|---|---|---|
| `APP_VERSION_*` | 12.10.0 / 7031 | Upstream Telegram base |
| `TEJAR_VERSION_*` | 1.5.2 / 6977 | Tejar release (APK versionCode = `6977*10 + abiCode`) |

## License

Inherits GPL v2+ from upstream Telegram — see [LICENSE](LICENSE).
