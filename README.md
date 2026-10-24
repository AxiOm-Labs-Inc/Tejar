# Tejar

**Tejar** is an unofficial Telegram client for Android with a built-in proxy core.
Add your own server or any compatible subscription, and Telegram connects through it —
no separate VPN app needed.

Made by [AxiOm Labs](https://github.com/AxiOm-Labs-Inc). Based on the open-source
[Telegram for Android](https://github.com/DrKLO/Telegram). Not affiliated with Telegram.

## Download

Latest APK: [Releases](https://github.com/AxiOm-Labs-Inc/Tejar/releases/latest)
(`arm64` for modern phones, `armv7` for older ones).

## Features

- Built-in proxy: Telegram's traffic goes through your server; other apps are not affected.
- Works with any compatible provider, not just one service:
  - subscriptions in sing-box JSON, base64 / plain link lists, Clash / Mihomo YAML, xray JSON, SIP008;
  - links: VLESS, VMess, Trojan, Shadowsocks (with plugins), Hysteria / Hysteria2, TUIC, AnyTLS,
    WireGuard, SOCKS, NaiveProxy;
  - "add to app" links from other clients (`sing-box://`, `clash://` and similar), with confirmation.
- Subscriptions refresh themselves every 6 hours.
- Real latency test through each server, automatic choice of the fastest one, switching without reconnecting.
- Everything else is the regular Telegram app.

## Building

See [TEJAR.md](TEJAR.md) — build commands, the `vpn-core` module, the bundled cores and versioning.
You need your own Telegram `api_id` / `api_hash` (<https://my.telegram.org>) and your own signing key.

## License

GNU GPL v3 — see [LICENSE](LICENSE). Third-party components and their licenses:
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
