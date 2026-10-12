// SPDX-License-Identifier: GPL-3.0-or-later
// Android JNI köprüsü — DpiJni.kt imzalarının karşılığı.
//! Yalnızca `target_os = "android"` derlenir. panic-free: tüm girişler doğrulanır.
//! C ABI stub'ları (dpi_android_*) korundu; JNI fonksiyonları eklendi.
#![cfg(target_os = "android")]

use crate::{dpi_version, find_sni, should_process, split_client_hello, split_quic_initial, split_records, CutPos, SendOrder, Strategy};
use jni::objects::{JByteArray, JClass};
use jni::sys::jboolean;
use jni::JNIEnv;
use std::os::raw::{c_int, c_uchar};
use std::slice;

// ---------- C ABI (eskiler, korundu) ----------

#[no_mangle]
pub extern "C" fn dpi_android_version() -> c_int {
    dpi_version()
}

#[no_mangle]
pub unsafe extern "C" fn dpi_android_should_process(
    port: u16,
    data: *const c_uchar,
    len: usize,
) -> c_int {
    if data.is_null() {
        return 0;
    }
    let bytes = slice::from_raw_parts(data as *const u8, len);
    if should_process(port, bytes) {
        1
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn dpi_android_split_count(
    packet: *const c_uchar,
    packet_len: usize,
    strategy_code: c_int,
    param: c_int,
    delay_ms: u64,
) -> c_int {
    if packet.is_null() {
        return 0;
    }
    let bytes = slice::from_raw_parts(packet as *const u8, packet_len);
    split_client_hello(bytes, code_to_strategy(strategy_code, param, delay_ms)).len() as c_int
}

fn code_to_strategy(code: c_int, param: c_int, delay_ms: u64) -> Strategy {
    match code {
        // 0 = TCP split (gecikmeli), 1 = fragment, 2 = record-split, 3 = ters sıra
        1 => Strategy::Fragment { chunk_size: (param.max(1)) as usize },
        2 => Strategy::RecordSplit { delay_ms },
        3 => Strategy::Custom {
            cut: CutPos::Mid,
            order: SendOrder::Reversed,
            delay_ms,
        },
        _ => Strategy::SplitWithDelay { split_at: (param.max(1)) as usize, delay_ms },
    }
}

// ---------- JNI (DpiJni.kt) ----------

fn read_bytes(env: &mut JNIEnv, arr: JByteArray) -> Option<Vec<u8>> {
    env.convert_byte_array(arr).ok()
}

/// SNI muaf listede mi? (DpiJni.isExcluded)
#[no_mangle]
pub extern "system" fn Java_com_dpivpn_DpiJni_isExcluded(
    mut env: JNIEnv,
    _class: JClass,
    packet: JByteArray,
) -> jboolean {
    let yes = read_bytes(&mut env, packet)
        .and_then(|p| {
            let (s, e) = find_sni(&p)?;
            Some(crate::is_excluded(&String::from_utf8_lossy(&p[s..e])))
        })
        .unwrap_or(false);
    if yes {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "system" fn Java_com_dpivpn_DpiJni_dpiVersion(
    mut env: JNIEnv,
    _class: JClass,
) -> c_int {
    let _ = &mut env;
    dpi_version()
}

#[no_mangle]
pub extern "system" fn Java_com_dpivpn_DpiJni_shouldProcess(
    mut env: JNIEnv,
    _class: JClass,
    port: c_int,
    first: JByteArray,
) -> jboolean {
    match read_bytes(&mut env, first) {
        Some(b) if should_process(port as u16, &b) => 1,
        _ => 0,
    }
}

/// byte[][] döner: record-split parçaları (SNI gizli, framing geçerli).
#[no_mangle]
pub extern "system" fn Java_com_dpivpn_DpiJni_splitRecords<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    packet: JByteArray<'local>,
) -> jni::sys::jobjectArray {
    let out: Vec<Vec<u8>> = match read_bytes(&mut env, packet) {
        Some(p) => split_records(&p),
        None => vec![],
    };
    match env.new_object_array(
        out.len() as i32,
        "[B",
        jni::objects::JObject::null(),
    ) {
        Ok(arr) => {
            for (i, part) in out.iter().enumerate() {
                if let Ok(ja) = env.byte_array_from_slice(part) {
                    let _ = env.set_object_array_element(&arr, i as i32, ja);
                }
            }
            arr.into_raw()
        }
        Err(_) => std::ptr::null_mut(),
    }
}

/// byte[][] döner: TCP split + delay bilgisi delayMs ile (gecikmeyi Kotlin uygular).
#[no_mangle]
pub extern "system" fn Java_com_dpivpn_DpiJni_splitTcp<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    packet: JByteArray<'local>,
    delay_ms: jni::sys::jlong,
) -> jni::sys::jobjectArray {
    let out: Vec<Vec<u8>> = match read_bytes(&mut env, packet) {
        Some(p) => {
            // SNI ortası kesit; delay Kotlin tarafında uygulanır
            let s = Strategy::SplitWithDelay { split_at: 2, delay_ms: delay_ms as u64 };
            // SNI yoksa bile 2 parça garantisi yok — ne çıkarsa
            let _ = find_sni(&p);
            split_client_hello(&p, s)
        }
        None => vec![],
    };
    parts_to_java(&mut env, out)
}

/// byte[][] döner: ince ayarlı bölme.
/// cut_code: 0 = SNI ortası, 1 = SNI öncesi. reverse: 1 = ters sıra.
#[no_mangle]
pub extern "system" fn Java_com_dpivpn_DpiJni_splitCustom<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    packet: JByteArray<'local>,
    _delay_ms: jni::sys::jlong,
    cut_code: jni::sys::jint,
    reverse: jni::sys::jint,
) -> jni::sys::jobjectArray {
    let out: Vec<Vec<u8>> = match read_bytes(&mut env, packet) {
        Some(p) => {
            let cut = if cut_code == 1 { CutPos::Before } else { CutPos::Mid };
            let order = if reverse == 1 { SendOrder::Reversed } else { SendOrder::InOrder };
            let mut parts = split_client_hello(
                &p,
                Strategy::Custom { cut, order, delay_ms: 0 },
            );
            // Gönderim sırası burada uygulanır (gecikme ilk gönderilenden sonra).
            if reverse == 1 && parts.len() == 2 {
                parts.swap(0, 1);
            }
            parts
        }
        None => vec![],
    };
    parts_to_java(&mut env, out)
}

/// byte[][] döner: QUIC Initial bölme (2 datagram ya da aynen).
/// QUIC engelle kapalıysa Android UDP yolunda kullanılır.
#[no_mangle]
pub extern "system" fn Java_com_dpivpn_DpiJni_splitQuic<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    packet: JByteArray<'local>,
) -> jni::sys::jobjectArray {
    let out: Vec<Vec<u8>> = match read_bytes(&mut env, packet) {
        Some(p) => split_quic_initial(&p),
        None => vec![],
    };
    parts_to_java(&mut env, out)
}

/// byte[][] döner: otomatik taktik (auto_pick + bölme).
#[no_mangle]
pub extern "system" fn Java_com_dpivpn_DpiJni_splitAuto<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    packet: JByteArray<'local>,
) -> jni::sys::jobjectArray {
    let out: Vec<Vec<u8>> = match read_bytes(&mut env, packet) {
        Some(p) => {
            let st = crate::auto_pick(&p);
            split_client_hello(&p, st)
        }
        None => vec![],
    };
    parts_to_java(&mut env, out)
}

fn parts_to_java<'local>(env: &mut JNIEnv<'local>, out: Vec<Vec<u8>>) -> jni::sys::jobjectArray {
    match env.new_object_array(
        out.len() as i32,
        "[B",
        jni::objects::JObject::null(),
    ) {
        Ok(arr) => {
            for (i, part) in out.iter().enumerate() {
                if let Ok(ja) = env.byte_array_from_slice(part) {
                    let _ = env.set_object_array_element(&arr, i as i32, ja);
                }
            }
            arr.into_raw()
        }
        Err(_) => std::ptr::null_mut(),
    }
}
