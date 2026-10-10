# DPI VPN — MVP (DPI öncelikli)

Flutter + Rust core hedefli. Şu an Flutter yok, o yüzden Rust çekirdek + Windows test proxy hazır.

## Yapı
- `dpi-core/` — ortak çekirdek: SNI bulma, ClientHello bölme. OS bağımsız.
- `dpi-proxy/` — sürücüsüz Windows test proxy'si (127.0.0.1:8888).

## Test sonucu
- `cargo test -p dpi-core` → 4/4 geçti
- `cargo build -p dpi-proxy` → ok

## Çalıştır
```
cargo run -p dpi-proxy -- --listen 127.0.0.1:8888 --split-at 2 --delay-ms 10
```

## Sonraki adımlar
1. WinDivert ile sistem geneli TUN (admin gerektirir)
2. Flutter kurulumu + flutter_rust_bridge ile UI
3. Android VpnService tarafı aynı `dpi-core` kullanacak
