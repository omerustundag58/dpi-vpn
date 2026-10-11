# Skill: dpi-proje

---
name: dpi-proje
description: >
  DPI VPN reposunda HERHANGİ bir iş yapmadan önce bu dosyayı oku ve kurallara
  uy. Rust çekirdek, Windows proxy/UI, Android uygulaması içerir.
---

# DPI VPN — çalışma kuralları

## Repo haritası
- `dpi-core/src/lib.rs` — SNI bulma, bölme stratejileri. API'yi BOZMA
  (`find_sni`, `split_client_hello`, `split_once`, `is_excluded` imzaları sabit).
- `dpi-proxy/src/main.rs` — Windows TCP proxy (CONNECT, düz HTTP, IPv6).
- `zapret-ui/app.py` — Windows arayüz (tkinter). Metinler `STR` sözlüğünde TR/EN.
- `android/` — VpnService TUN + JNI. Servis sözleşmesi: action CONNECT +
  extras profile/mode/custom_dns/quic_block/allowed_apps; yayın
  `com.dpivpn.STATE_UPDATE`.
- `diag.py` — ağ tanı scripti. `vendor/` git'te YOK (kişisel).

## Komutlar
- Test: `cargo test --workspace` (çekirdek 21 + proxy 6 olmalı, hepsi yeşil).
- Release: `$env:RUSTFLAGS='--remap-path-prefix=C:\Users\kullanici=~'` ile
  derle (exe'ye kullanıcı yolu gömülmesin).
- Android `.so`: NDK 27 + `cargo build -p dpi-core --target <arch>-linux-android --release`
  (`.cargo/config.toml` yereldir, örneği `config.toml.example`).
- APK: `gradle -p android :app:assembleDebug` (JDK 17 gerekir).

## Demir kurallar
1. Önce ilgili dosyayı OKU, sonra değiştir. Tahminle kod yazma.
2. Her değişiklikten sonra ilgili testi koş, sonucu görmeden "bitti" deme.
3. Türkçe metinlerde imlaya dikkat; koda emoji koyma.
4. Kullanıcı yolu (`C:\Users\...`) kodda ve derlemede YASAK.
5. Küçük adımlar: bir iş = birkaç dosya, her adımda commit mesajı gibi özetle.
6. Emin değilsen sor; sessizce varsayma. Özellikle: WinDivert (admin ister),
   UDP ses, IPv6 — bu üçü tuzaktır, dikkatli ol.

## Alan bilgisi (kısa)
- Varsayılan strateji record-split (TCP-birleştirmeli DPI'ya karşı kanıtlı).
- Muaf sonekler: gov.tr, com.tr, google.com, googleapis.com (bölmeden iletilir).
- QUIC (UDP 443) proxy dışından kaçar; engellenince TCP'ye düşer.
- TT DNS zehri IP'si: 195.175.254.2 (yalnızca tanı amaçlı sabit).
