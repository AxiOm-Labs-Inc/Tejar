# Third-party notices

Tejar is an **unofficial** Telegram client published by AxiOm Labs. It is not affiliated with or
endorsed by Telegram FZ-LLC, SagerNet or Project X.

The combined application is distributed under the **GNU General Public License v3**
([LICENSE](LICENSE)). Source for every release is published as a git tag in
<https://github.com/AxiOm-Labs-Inc/Tejar>.

## Components

| Component | Where | License | Source |
|---|---|---|---|
| Telegram for Android | `TMessagesProj*` | GPL v2 or later ([upstream text](licenses/GPL-2.0-Telegram-upstream.txt)) — used here under GPL v3 | <https://github.com/DrKLO/Telegram> |
| sing-box (`libbox`) | `vpn-core/libs/libbox.aar` | GPL v3 or later, with an additional condition: no derivative work may use the name "sing-box" or imply association with it without prior consent | <https://github.com/SagerNet/sing-box> (v1.13.19) |
| Xray-core | `libxray.so`, unmodified upstream binary, run as a separate process | Mozilla Public License 2.0 ([text](licenses/MPL-2.0.txt)) | <https://github.com/XTLS/Xray-core/tree/v26.3.27> |
| SnakeYAML | `vpn-core` dependency | Apache 2.0 ([text](licenses/Apache-2.0.txt)) | <https://bitbucket.org/snakeyaml/snakeyaml> |
| Kotlin coroutines | `vpn-core` dependency | Apache 2.0 | <https://github.com/Kotlin/kotlinx.coroutines> |
| AndroidX (core-ktx, security-crypto) | `vpn-core` dependency | Apache 2.0 | <https://android.googlesource.com/platform/frameworks/support> |

Upstream Telegram itself bundles further third-party code (FFmpeg, BoringSSL, libwebp, Opus, rlottie and
others) under their own licenses; see the license files inside `TMessagesProj/jni/` and the upstream
repository.

## Trademarks

"Telegram" and the paper-plane logo are trademarks of Telegram. "sing-box" and "Xray" are the names of
their respective projects. They are used here only to describe compatibility and the components inside
the app.
