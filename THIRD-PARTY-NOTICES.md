# DPI VPN — üçüncü taraf bileşenler

Bu proje GPL-3.0-or-later lisanslıdır (LICENSE). Aşağıdaki bağımsız
bileşenler kendi lisanslarıyla kullanılır:

## Derleme/kütüphane bağımlılıkları (F-Droid uyumlu)

* tokio (Rust) — MIT
* jni (Rust, yalnızca Android hedefi) — MIT / Apache-2.0
* Kotlin stdlib + AndroidX + Gradle + Android Gradle Plugin — Apache-2.0
* Python tkinter (PSF lisansı), Pillow (HPND), pystray (LGPL-3.0),
  PyInstaller (GPL-2.0+istisna) — yalnızca Windows masaüstü derlemesi için

## F-Droid dışı (depoda tutulmaz, sürüme dahil değildir)

* `vendor/zapret-win-turkey-backup/` — zapret + WinDivert ikilileri.
  Kaynak: topluluk paketi (İnternet). Lisansı belirsiz/özgür değil;
  bu yüzden F-Droid derlemesine DAHİL DEĞİLDİR ve git'te izlenmez.
  Windows masaüstü sürümünde isteğe bağlı "WinDivert motoru" olarak
  kullanıcının kendi klasöründen çalışır; yokluğunda uygulama
  Rust motoruyla tam işlevseldir.
