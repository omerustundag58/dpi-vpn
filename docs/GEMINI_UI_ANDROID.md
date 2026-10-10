<!-- Flutter UI + Android VpnService + dpi-core birlesimi — 20 satirlik mimari ozet. -->
1. Tek dogruluk kaynagi `dpi-core` (lib.rs): find_sni/split/should_process burada, OS kodu yok.
2. Flutter UI (`flutter_app/`) yalnizca kontrol duzlemi: Baglan/Kopar + strateji + delay slider.
3. `dpi_bridge.dart` iki yol sunar: FFI ile `dpi_version()` ve MethodChannel `com.dpivpn/control`.
4. find_sni/split henuz extern "C" degil; parcalama her zaman Rust core'da calisir, Dart'ta degil.
5. Android veri duzlemi `DpiVpnService.kt`: TUN kurar (10.0.0.2, route 0.0.0.0/0), paketi okur.
6. Servis TCP 443 payload'u `DpiJni.shouldProcess` ile filtreler, `splitClientHello` ile boldurur.
7. `DpiJni.kt` `libdpi_core.so` yukler; imzalar `android.rs` C ABI'ina birebir uyar.
8. `android.rs` `jni` cratesiz derlenir (dpi_android_*); tam JNI sarmalayici feature arkasinda.
9. Derleme: `cargo ndk -o android/jniLibs build -p dpi-core`, Gradle abiFilters+jniLibs, Manifest BIND_VPN.
10. Ayni Strategy secimi (Split/Fragment+delay) Flutter'dan Intent extras ile servise gecer, cekirdek ayni kalir.
