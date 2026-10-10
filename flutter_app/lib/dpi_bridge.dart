// dpi-core cdylib fonksiyonlarina Dart FFI + MethodChannel koprusu (gecici stub, FRB yok).
import 'dart:ffi' as ffi;
import 'dart:io' show Platform;
import 'package:flutter/services.dart';

/// Rust tarafindaki Strategy enum'unun Dart aynasi.
enum DpiStrategyKind { split, fragment }

class DpiStrategy {
  final DpiStrategyKind kind;
  final int splitAt;
  final int chunkSize;
  final int delayMs;
  const DpiStrategy._(this.kind, this.splitAt, this.chunkSize, this.delayMs);
  const DpiStrategy.split({int splitAt = 2})
      : this._(DpiStrategyKind.split, splitAt, 0, 0);
  const DpiStrategy.splitWithDelay({int splitAt = 2, int delayMs = 10})
      : this._(DpiStrategyKind.split, splitAt, 0, delayMs);
  const DpiStrategy.fragment({int chunkSize = 512})
      : this._(DpiStrategyKind.fragment, 0, chunkSize, 0);

  String describe() => kind == DpiStrategyKind.split
      ? 'SplitWithDelay(splitAt=$splitAt, delay=${delayMs}ms)'
      : 'Fragment(chunk=$chunkSize)';

  Map<String, dynamic> toArgs() => {
        'kind': kind.name,
        'splitAt': splitAt,
        'chunkSize': chunkSize,
        'delayMs': delayMs,
      };
}

// --- FFI: dpi-core cdylib'deki `dpi_version() -> i32` imzasi ---
typedef _VersionNative = ffi.Int32 Function();
typedef _VersionDart = int Function();

class DpiBridge {
  static const MethodChannel _ch = MethodChannel('com.dpivpn/control');

  static ffi.DynamicLibrary? _lib;
  static ffi.DynamicLibrary _loadLib() {
    if (_lib != null) return _lib!;
    final name = Platform.isWindows
        ? 'dpi_core.dll'
        : Platform.isAndroid
            ? 'libdpi_core.so'
            : 'libdpi_core.so';
    _lib = ffi.DynamicLibrary.open(name);
    return _lib!;
  }

  /// Rust `dpi_version()` cagrisi; kutuphane yoksa -1 doner (stub davranisi).
  static int nativeVersion() {
    try {
      final f = _loadLib().lookupFunction<_VersionNative, _VersionDart>('dpi_version');
      return f();
    } catch (_) {
      return -1; // henuz cdylib paketlenmemisken calisir UI.
    }
  }

  // NOT: find_sni / split_client_hello / should_process henuz extern "C"
  // degil; flutter_rust_bridge gelene kadar bu islemler MethodChannel ile
  // Android VpnService / local proxy tarafinda (Rust core uzerinden) yapilir.
  static Future<void> connect(DpiStrategy s) =>
      _ch.invokeMethod('connect', s.toArgs());
  static Future<void> disconnect() => _ch.invokeMethod('disconnect');
}
