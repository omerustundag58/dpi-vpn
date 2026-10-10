// SPDX-License-Identifier: GPL-3.0-or-later
// Android JNI köprüsü — DpiJni.kt imzalarının karşılığı.
//! Yalnızca `target_os = "android"` derlenir. panic-free: tüm girişler doğrulanır.
//! C ABI stub'ları (dpi_android_*) korundu; JNI fonksiyonları eklendi.
#![cfg(target_os = "android")]

use crate::{dpi_version, find_sni, should_process, split_client_hello, split_records, Strategy};
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
        // 0 = TCP split (gecikmeli), 1 = fragment, 2 = record-split
        1 => Strategy::Fragment { chunk_size: (param.max(1)) as usize },
        2 => Strategy::RecordSplit { delay_ms },
        _ => Strategy::SplitWithDelay { split_at: (param.max(1)) as usize, delay_ms },
    }
}

// ---------- JNI (DpiJni.kt) ----------

fn read_bytes(env: &mut JNIEnv, arr: JByteArray) -> Option<Vec<u8>> {
    env.convert_byte_array(arr).ok()
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
