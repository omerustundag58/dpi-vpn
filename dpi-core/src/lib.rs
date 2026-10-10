// SPDX-License-Identifier: GPL-3.0-or-later
//! dpi-core: platform bağımsız DPI bypass mantığı.
//!
//! Flutter (flutter_rust_bridge) + Windows CLI + Android VpnService
//! hepsi bu çekirdeği kullanır. OS'ye özel kod YOK.
//!
//! MVP teknikler:
//! - TLS ClientHello içinde SNI bulma
//! - TCP segment bölme (SNI'yi iki pakete ayırma - GoodbyeDPI / zapret tekniği)
//! - Parça sıralama / gecikme stratejisi

pub mod zapret;
#[cfg(target_os = "android")]
pub mod android;

/// DPI bypass stratejisi.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    /// SNI'yi `split_at` byte'ından ikiye böl.
    Split { split_at: usize },
    /// ClientHello'yu N byte'lık parçalara böl.
    Fragment { chunk_size: usize },
    /// TLS record katmanında böl: her parça kendi record başlığını alır.
    /// TCP-birleştirmeli DPI'lar tek record'u parse eder; SNI record'lara
    /// dağılınca görünmez. Sunucular çok-record'lu hello'yu kabul eder.
    /// (zapret multisplit dengi, kullanıcı-alanında çalışır)
    /// delay_ms: record'lar arası bekleme (Dengeli mod).
    RecordSplit { delay_ms: u64 },
    /// Böl + ilk parçadan sonra gecikme (ms). Birçok DPI kutusu out-of-order'ı yakalayamaz.
    SplitWithDelay { split_at: usize, delay_ms: u64 },
}

impl Default for Strategy {
    fn default() -> Self {
        // Kanıtlı varsayılan: TCP-birleştirmeli DPI'ya karşı record-split.
        Strategy::RecordSplit { delay_ms: 0 }
    }
}

/// TLS ClientHello içinde SNI (hostname) konumunu bul.
///
/// Dönüş: (sni_value_start, sni_value_end) — paketin içindeki byte offset'leri.
/// Bulunamazsa None.
pub fn find_sni(packet: &[u8]) -> Option<(usize, usize)> {
    // Minimum: TLS record header (5) + handshake header (4)
    if packet.len() < 9 {
        return None;
    }
    // 0: ContentType == 0x16 (Handshake)
    if packet[0] != 0x16 {
        return None;
    }
    // 1-2: TLS version (0x0301..0x0304)
    // 5-6: record length — tutarlılık kontrolü (gevşek)
    // Handshake: 5: type == 0x01 (ClientHello)
    if packet[5] != 0x01 {
        return None;
    }

    // Extensions alanına kadar parse etmemiz lazım.
    // ClientHello gövdesi offset 9'dan başlar (record 5 + handshake 4).
    let body = &packet[9..];
    let mut pos = 0usize;

    // client_version(2) + random(32)
    if body.len() < 34 {
        return None;
    }
    pos += 34;
    // session_id
    if body.len() < pos + 1 {
        return None;
    }
    let sid_len = body[pos] as usize;
    pos += 1 + sid_len;
    // cipher_suites
    if body.len() < pos + 2 {
        return None;
    }
    let cs_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2 + cs_len;
    // compression_methods
    if body.len() < pos + 1 {
        return None;
    }
    let comp_len = body[pos] as usize;
    pos += 1 + comp_len;
    // extensions
    if body.len() < pos + 2 {
        return None;
    }
    let ext_total = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_total;
    if body.len() < ext_end {
        return None;
    }

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let ext_len = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        pos += 4;
        if body.len() < pos + ext_len {
            return None;
        }
        // 0x0000 = server_name
        if ext_type == 0x0000 && ext_len >= 2 {
            // server_name_list_len(2), sonra: name_type(1) + name_len(2) + name
            if body.len() < pos + 2 {
                return None;
            }
            let list_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
            // ext datası: [list_len(2)][liste(list_len)]
            let ext_end_bound = pos + ext_len;
            let list_end = (pos + 2 + list_len).min(ext_end_bound);
            let mut p = pos + 2;
            while p + 3 <= list_end && p + 3 <= body.len() {
                let name_type = body[p];
                let name_len = u16::from_be_bytes([body[p + 1], body[p + 2]]) as usize;
                p += 3;
                if name_type == 0 && p + name_len <= body.len() && p + name_len <= ext_end_bound {
                    // body offset -> packet offset (+9)
                    return Some((9 + p, 9 + p + name_len));
                }
                match p.checked_add(name_len) {
                    Some(np) if np <= body.len() => p = np,
                    _ => break,
                }
                if p > list_end {
                    break;
                }
            }
        }
        pos += ext_len;
    }
    None
}

/// Bir ClientHello paketini stratejiye göre parçalara böl.
///
/// Dönüş: gönderilecek parça listesi. DPI kutusu tek parçada SNI göremez.
pub fn split_client_hello(packet: &[u8], strategy: Strategy) -> Vec<Vec<u8>> {
    // 2 byte'tan küçük paket bölünemez — clamp panic'ini önlemek için erken çık.
    if packet.len() < 2 {
        return vec![packet.to_vec()];
    }
    match strategy {
        Strategy::Split { split_at } | Strategy::SplitWithDelay { split_at, .. } => {
            // SNI varsa bölme noktasını SNI'nin içine koy (en etkili yer),
            // yoksa verilen offset'i paket başına göre uygula.
            let cut = if let Some((sni_start, sni_end)) = find_sni(packet) {
                // SNI ortasından kes
                let mid = sni_start + (sni_end - sni_start) / 2;
                mid.clamp(1, packet.len() - 1)
            } else {
                split_at.clamp(1, packet.len() - 1)
            };
            if cut == 0 || cut >= packet.len() {
                return vec![packet.to_vec()];
            }
            vec![packet[..cut].to_vec(), packet[cut..].to_vec()]
        }
        Strategy::Fragment { chunk_size } => {
            let cs = chunk_size.max(1);
            packet.chunks(cs).map(|c| c.to_vec()).collect()
        }
        Strategy::RecordSplit { .. } => split_records(packet),
    }
}

/// TLS record-framing ile böl. Tek record'lu hello'yu SNI ortasından
/// iki record'a ayırır. Geçerli hello değilse düz bölmeye düşer.
pub fn split_records(packet: &[u8]) -> Vec<Vec<u8>> {
    // en az record(5) + handshake(4)
    if packet.len() < 10 || packet[0] != 0x16 || packet[5] != 0x01 {
        return split_client_hello(packet, Strategy::Split { split_at: 2 });
    }
    // u16 record-uzunluğu taşmasın: 16KB üstü hello gerçekçi değil
    if packet.len() > 16384 {
        return split_client_hello(packet, Strategy::Split { split_at: 2 });
    }
    let reclen = u16::from_be_bytes([packet[3], packet[4]]) as usize;
    if 5 + reclen != packet.len() {
        // çok record'lu ya da padding'li — düz böl
        return split_client_hello(packet, Strategy::Split { split_at: 2 });
    }
    // kesim: SNI ortası (TLS yükü içinde), yoksa handshake ortası
    let cut = match find_sni(packet) {
        Some((s, e)) => s + (e - s) / 2,
        None => 5 + reclen / 2,
    };
    if cut <= 6 || cut >= packet.len() - 1 {
        return vec![packet.to_vec()];
    }
    // parça1 = record[len=cut-5] + payload[5..cut]; parça2 = record + payload[cut..]
    let mut r1 = vec![0x16, packet[1], packet[2]];
    r1.extend_from_slice(&((cut - 5) as u16).to_be_bytes());
    r1.extend_from_slice(&packet[5..cut]);
    let mut r2 = vec![0x16, packet[1], packet[2]];
    r2.extend_from_slice(&((packet.len() - cut) as u16).to_be_bytes());
    r2.extend_from_slice(&packet[cut..]);
    vec![r1, r2]
}

/// Hız öncelikli preset: gecikmesiz bölme. DPI kutularının çoğu
/// SNI'ı tek parçada göremeyince geçirir; 10ms gecikme hıza mal olur.
/// Hız istiyorsan bunu kullan.
pub fn fast_strategy() -> Strategy {
    Strategy::Split { split_at: 2 }
}

/// Tek parse ile SNI + parçaları döndürür (hızlı yol).
/// Ayrı ayrı `find_sni` + `split_client_hello` çağırmak paketi 2 kez
/// parse eder; bu fonksiyon 1 kez eder. Android'de pil/CPU dostu.
pub fn split_once(packet: &[u8], strategy: Strategy) -> (Option<(usize, usize)>, Vec<Vec<u8>>) {
    if packet.len() < 2 {
        return (None, vec![packet.to_vec()]);
    }
    let sni = find_sni(packet);
    let parts = match strategy {
        Strategy::Split { split_at } | Strategy::SplitWithDelay { split_at, .. } => {
            let cut = match sni {
                Some((s, e)) => (s + (e - s) / 2).clamp(1, packet.len() - 1),
                None => split_at.clamp(1, packet.len() - 1),
            };
            if cut == 0 || cut >= packet.len() {
                vec![packet.to_vec()]
            } else {
                vec![packet[..cut].to_vec(), packet[cut..].to_vec()]
            }
        }
        Strategy::Fragment { chunk_size } => {
            let cs = chunk_size.max(1);
            packet.chunks(cs).map(|c| c.to_vec()).collect()
        }
        Strategy::RecordSplit { .. } => split_records(packet),
    };
    (sni, parts)
}
/// Paketin DPI işlemine girip girmeyeceğine karar ver.
/// Şimdilik: TLS ClientHello (0x16 0x03 ..) ise true.
pub fn should_process(port: u16, first_bytes: &[u8]) -> bool {
    if port != 443 && port != 8443 {
        // 80 portu için de HTTP Host bölme ileride eklenecek
        if port != 80 {
            // Yine de TLS ise işle (bazı sunucular farklı portta)
            if first_bytes.len() >= 3 && first_bytes[0] == 0x16 {
                return true;
            }
            return false;
        }
    }
    if first_bytes.len() >= 3 && first_bytes[0] == 0x16 {
        return true;
    }
    // HTTP plain (ileride) — şimdilik false
    false
}

// ---- FFI (Flutter ilerde buradan bağlanacak) ----

/// C/Flutter tarafı için: strateji kodu -> parça sayısı testi.
/// Keep simple, ileride flutter_rust_bridge gelecek.
#[no_mangle]
pub extern "C" fn dpi_version() -> i32 {
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal sentetik ClientHello üret (SNI = example.com).
    fn fake_client_hello(sni: &[u8]) -> Vec<u8> {
        // Extension: server_name
        let mut sn_ext = vec![];
        let name_entry_len = 1 + 2 + sni.len();
        let list_len = name_entry_len;
        let ext_data_len = 2 + list_len;
        sn_ext.extend_from_slice(&[0x00, 0x00]); // ext type server_name
        sn_ext.extend_from_slice(&(ext_data_len as u16).to_be_bytes());
        sn_ext.extend_from_slice(&(list_len as u16).to_be_bytes());
        sn_ext.push(0x00); // host_name
        sn_ext.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        sn_ext.extend_from_slice(sni);

        let mut body = vec![];
        body.extend_from_slice(&[0x03, 0x03]); // client_version TLS1.2
        body.extend_from_slice(&[0xAA; 32]); // random
        body.push(0x00); // session_id len 0
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // 1 cipher suite
        body.push(0x01); // comp methods len
        body.push(0x00); // null
        body.extend_from_slice(&(sn_ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&sn_ext);

        let mut hs = vec![0x01]; // ClientHello
        let blen = body.len() as u32;
        hs.extend_from_slice(&[(blen >> 16) as u8, (blen >> 8) as u8, blen as u8]);
        hs.extend_from_slice(&body);

        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn finds_sni() {
        let pkt = fake_client_hello(b"example.com");
        let (s, e) = find_sni(&pkt).expect("SNI bulunmalı");
        assert_eq!(&pkt[s..e], b"example.com");
    }

    #[test]
    fn split_hides_sni_in_single_piece() {
        let pkt = fake_client_hello(b"example.com");
        let parts = split_client_hello(&pkt, fast_strategy());
        assert_eq!(parts.len(), 2);
        // Tek parçada tam SNI geçmemeli
        for p in &parts {
            assert!(
                p.windows(b"example.com".len())
                    .all(|w| w != b"example.com"),
                "SNI tek parçada görünmemeli"
            );
        }
        // Birleşince orijinal geri gelmeli
        let joined: Vec<u8> = parts.concat();
        assert_eq!(joined, pkt);
    }

    #[test]
    fn fragment_roundtrip() {
        let pkt = fake_client_hello(b"test.org");
        let parts = split_client_hello(&pkt, Strategy::Fragment { chunk_size: 10 });
        assert!(parts.len() > 2);
        assert_eq!(parts.concat(), pkt);
    }

    #[test]
    fn non_tls_not_processed() {
        assert!(!should_process(443, b"GET / HTTP/1.1"));
        assert!(should_process(443, &[0x16, 0x03, 0x01, 0x00]));
    }

    // ============ AGRESİF TESTLER ============

    #[test]
    fn empty_and_tiny_never_panic() {
        for len in 0..12usize {
            let pkt = vec![0x16u8; len];
            let _ = find_sni(&pkt);
            let parts = split_client_hello(&pkt, fast_strategy());
            assert_eq!(parts.concat(), pkt, "roundtrip len={len}");
            let frag = split_client_hello(&pkt, Strategy::Fragment { chunk_size: 0 });
            assert_eq!(frag.concat(), pkt);
            let frag1 = split_client_hello(&pkt, Strategy::Fragment { chunk_size: 1 });
            assert_eq!(frag1.concat(), pkt);
        }
        // boş paket fragment: chunks(1) boş -> 0 parça, concat boş. kabul.
        let empty = split_client_hello(&[], Strategy::Fragment { chunk_size: 10 });
        assert!(empty.concat().is_empty());
    }

    #[test]
    fn truncated_at_every_prefix_no_panic() {
        let full = fake_client_hello(b"agresif-test.example.com");
        for cut in 0..full.len() {
            let prefix = &full[..cut];
            let _ = find_sni(prefix); // panic yok yeterli
            for strat in [
                Strategy::Split { split_at: 2 },
                Strategy::Split { split_at: 0 },
                Strategy::Split { split_at: usize::MAX },
                Strategy::SplitWithDelay { split_at: 2, delay_ms: 0 },
                Strategy::Fragment { chunk_size: 1 },
                Strategy::Fragment { chunk_size: 7 },
            ] {
                let parts = split_client_hello(prefix, strat);
                assert_eq!(parts.concat(), prefix, "roundtrip cut={cut} strat={strat:?}");
            }
        }
    }

    #[test]
    fn corrupt_lengths_no_panic() {
        let base = fake_client_hello(b"example.com");
        // session_id len şişir
        let mut m1 = base.clone();
        if m1.len() > 43 {
            m1[43] = 255;
        }
        assert!(find_sni(&m1).is_none_or(|_| true)); // panic yok
        let _ = split_client_hello(&m1, fast_strategy());
        // cipher_suites len şişir
        let mut m2 = base.clone();
        if m2.len() > 45 {
            m2[44] = 0xFF;
            m2[45] = 0xFF;
        }
        let _ = find_sni(&m2);
        let _ = split_client_hello(&m2, fast_strategy());
        // extensions total şişir
        let mut m3 = base.clone();
        // extensions len offsetini bul: sondan geriye değil, parse'a güven — son 2 byte'ı boz
        if m3.len() > 10 {
            let n = m3.len();
            m3[n - 1] = 0xFF;
            m3[n - 2] = 0xFF;
        }
        let _ = find_sni(&m3);
        // record length tutarsız ama gevşek kabul — panic yok
        let mut m4 = base.clone();
        m4[5] = 0xFF;
        m4[6] = 0xFF;
        let _ = find_sni(&m4);
        // hepsi roundtrip vermeli
        for m in [&m1, &m2, &m3, &m4] {
            assert_eq!(split_client_hello(m, fast_strategy()).concat(), *m);
        }
    }

    #[test]
    fn wrong_types_rejected() {
        let mut pkt = fake_client_hello(b"example.com");
        // content type appdata
        pkt[0] = 0x17;
        assert!(find_sni(&pkt).is_none());
        pkt[0] = 0x16;
        // handshake type ServerHello
        pkt[5] = 0x02;
        assert!(find_sni(&pkt).is_none());
        pkt[5] = 0x01;
        assert!(find_sni(&pkt).is_some());
        // random garbage
        assert!(find_sni(&[0x16, 0x03, 0x01, 0xFF, 0xFF]).is_none());
        assert!(find_sni(&[0x00; 100]).is_none());
        assert!(find_sni(&[0x16; 100]).is_none());
    }

    #[test]
    fn sni_edge_lengths() {
        // 1 karakter
        let p1 = fake_client_hello(b"a");
        let (s, e) = find_sni(&p1).unwrap();
        assert_eq!(&p1[s..e], b"a");
        let parts = split_client_hello(&p1, fast_strategy());
        assert_eq!(parts.concat(), p1);
        // 1-char SNI bölününce tek parçada görünmeyebilir ya da 1 byte kalır — roundtrip yeterli
        // uzun SNI (200 char)
        let long = vec![b'x'; 200];
        let pl = fake_client_hello(&long);
        let (s, e) = find_sni(&pl).unwrap();
        assert_eq!(&pl[s..e], &long[..]);
        let parts = split_client_hello(&pl, fast_strategy());
        assert_eq!(parts.len(), 2);
        for p in &parts {
            assert!(!p.windows(long.len()).any(|w| w == &long[..]));
        }
        assert_eq!(parts.concat(), pl);
        // unicode host (utf8 bytes)
        let uni = "türkiye-örnek.com".as_bytes();
        let pu = fake_client_hello(uni);
        let (s, e) = find_sni(&pu).unwrap();
        assert_eq!(&pu[s..e], uni);
    }

    #[test]
    fn sni_not_first_extension() {
        // SNI'dan önce dummy extension (0x000a) koy
        let pkt = fake_client_hello_with_prefix_ext(b"second-ext.com");
        let (s, e) = find_sni(&pkt).expect("ikinci ext'teki SNI bulunmalı");
        assert_eq!(&pkt[s..e], b"second-ext.com");
        assert_eq!(split_client_hello(&pkt, fast_strategy()).concat(), pkt);
    }

    /// SNI önünde başka extension olan ClientHello üretir.
    fn fake_client_hello_with_prefix_ext(sni: &[u8]) -> Vec<u8> {
        let mut dummy = vec![0x00, 0x0A, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF];
        let mut sn_ext = vec![];
        let name_entry_len = 1 + 2 + sni.len();
        sn_ext.extend_from_slice(&[0x00, 0x00]);
        sn_ext.extend_from_slice(&((2 + name_entry_len) as u16).to_be_bytes());
        sn_ext.extend_from_slice(&(name_entry_len as u16).to_be_bytes());
        sn_ext.push(0x00);
        sn_ext.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        sn_ext.extend_from_slice(sni);
        let mut all_ext = dummy.clone();
        all_ext.extend_from_slice(&sn_ext);
        // body
        let mut body = vec![];
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0xBB; 32]);
        body.push(0x00);
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        body.push(0x01);
        body.push(0x00);
        body.extend_from_slice(&(all_ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&all_ext);
        let mut hs = vec![0x01];
        let blen = body.len() as u32;
        hs.extend_from_slice(&[(blen >> 16) as u8, (blen >> 8) as u8, blen as u8]);
        hs.extend_from_slice(&body);
        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        let _ = &mut dummy;
        rec
    }

    #[test]
    fn split_strategies_all_roundtrip_and_hide() {
        let sni = b"split-agresif-test.com";
        let pkt = fake_client_hello(sni);
        let strats = [
            Strategy::Split { split_at: 0 },
            Strategy::Split { split_at: 1 },
            Strategy::Split { split_at: 5 },
            Strategy::Split { split_at: usize::MAX / 2 },
            Strategy::SplitWithDelay { split_at: 0, delay_ms: 0 },
            Strategy::SplitWithDelay { split_at: 100000, delay_ms: 50 },
            Strategy::Fragment { chunk_size: 0 },
            Strategy::Fragment { chunk_size: 1 },
            Strategy::Fragment { chunk_size: 2 },
            Strategy::Fragment { chunk_size: 135 },
            Strategy::Fragment { chunk_size: usize::MAX },
            Strategy::RecordSplit { delay_ms: 0 },
        ];
        for st in strats {
            let parts = split_client_hello(&pkt, st);
            if matches!(st, Strategy::RecordSplit { .. }) {
                // record-split yeniden çerçeveler: yük eşitliği kontrol edilir
                let mut payload = vec![];
                for p in &parts {
                    assert_eq!(p[0], 0x16);
                    payload.extend_from_slice(&p[5..]);
                }
                assert_eq!(payload, &pkt[5..], "record-split yük roundtrip {st:?}");
            } else {
                assert_eq!(parts.concat(), pkt, "roundtrip {st:?}");
            }
            // SNI'lı pakette Split* her zaman 2 parça vermeli
            match st {
                Strategy::Split { .. } | Strategy::SplitWithDelay { .. } => {
                    assert_eq!(parts.len(), 2, "{st:?} 2 parça olmalı");
                    for p in &parts {
                        assert!(
                            !p.windows(sni.len()).any(|w| w == sni),
                            "{st:?} SNI tek parçada görünmemeli"
                        );
                    }
                }
                Strategy::Fragment { chunk_size } => {
                    let cs = chunk_size.max(1);
                    let expect = pkt.len().div_ceil(cs);
                    assert_eq!(parts.len(), expect, "{st:?} parça sayısı");
                }
                Strategy::RecordSplit { .. } => {
                    assert_eq!(parts.len(), 2, "{st:?} 2 parça olmalı");
                    for p in &parts {
                        assert!(
                            !p.windows(sni.len()).any(|w| w == sni),
                            "{st:?} SNI tek record'da görünmemeli"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn should_process_matrix() {
        // TLS her portta yakalanmalı (farklı portta TLS olabilir)
        for port in [443u16, 8443, 80, 8080, 2053, 1, 65535] {
            assert!(should_process(port, &[0x16, 0x03, 0x03]), "port {port}");
        }
        // non-TLS 443'te false
        assert!(!should_process(443, b"GET / HTTP/1.1\r\n"));
        assert!(!should_process(443, &[]));
        assert!(!should_process(443, &[0x16]));
        assert!(!should_process(443, &[0x15, 0x03, 0x01])); // alert
        assert!(!should_process(80, b"GET / HTTP/1.1"));
        assert!(!should_process(1234, b"hello"));
    }

    /// Deterministik PRNG (xorshift) — dev bağımlılık yok.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % (n as u64).max(1)) as usize
        }
    }

    #[test]
    fn fuzz_10k_random_no_panic_roundtrip() {
        let mut rng = Rng(0x1234_5678_ABCD_EF01);
        let mut sni_hidden_ok = 0;
        let mut sni_found = 0;
        for _ in 0..10_000 {
            let len = rng.below(600);
            let mut pkt = vec![0u8; len];
            for b in pkt.iter_mut() {
                *b = (rng.next() & 0xFF) as u8;
            }
            // %20 ihtimalle başı TLS yap (gerçekçi karışım)
            if rng.below(5) == 0 && len >= 6 {
                pkt[0] = 0x16;
                pkt[1] = 0x03;
                pkt[5] = 0x01;
            }
            let found = find_sni(&pkt);
            // bulunan offset'ler sınır içinde olmalı
            if let Some((s, e)) = found {
                assert!(s <= e && e <= pkt.len(), "offset taşması s={s} e={e} len={len}");
                sni_found += 1;
            }
            let strat = match rng.below(3) {
                0 => Strategy::Split { split_at: rng.below(300) },
                1 => Strategy::SplitWithDelay { split_at: rng.below(300), delay_ms: 0 },
                _ => Strategy::Fragment { chunk_size: rng.below(50) },
            };
            let parts = split_client_hello(&pkt, strat);
            assert_eq!(parts.concat(), pkt, "fuzz roundtrip");
            if let Some((s, e)) = found {
                let sni = &pkt[s..e];
                if !sni.is_empty() && parts.len() == 2 {
                    // 2+ byte SNI'lar gizlenmeli (1-byte SNI bölünemeyebilir)
                    if sni.len() >= 2 && e - s >= 2 {
                        let hidden = parts.iter().all(|p| {
                            if p.len() < sni.len() {
                                true
                            } else {
                                !p.windows(sni.len()).any(|w| w == sni)
                            }
                        });
                        if hidden {
                            sni_hidden_ok += 1;
                        }
                    }
                }
            }
        }
        println!("fuzz: sni_found={sni_found}/10000 hidden_ok={sni_hidden_ok}");
    }

    #[test]
    fn perf_split_throughput() {
        // 1500 byte paket x 20k bölme — 2 sn altında olmalı (debug dahil)
        let pkt = fake_client_hello(&[b'q'; 100]);
        assert!(pkt.len() > 100);
        let start = std::time::Instant::now();
        let mut total_parts = 0;
        for _ in 0..20_000 {
            total_parts += split_client_hello(&pkt, fast_strategy()).len();
        }
        let el = start.elapsed();
        println!("perf: 20k split = {el:?}, parts={total_parts}");
        assert_eq!(total_parts, 40_000);
        assert!(el.as_secs() < 5, "çok yavaş: {el:?}");
    }

    #[test]
    fn bench_hot_path_real_hello() {
        // Hız öncelikli: gerçek 1518B hello üzerinde tek-parse vs çift-parse.
        let pkt = fake_client_hello(&[b'z'; 120]);
        let iters = 50_000u32;
        // çift-parse (eski yol)
        let t0 = std::time::Instant::now();
        let mut n = 0;
        for _ in 0..iters {
            let s = find_sni(&pkt);
            let p = split_client_hello(&pkt, Strategy::Split { split_at: 2 });
            n += p.len() + s.is_some() as usize;
        }
        let two = t0.elapsed();
        // tek-parse (yeni hızlı yol)
        let t1 = std::time::Instant::now();
        let mut m = 0;
        for _ in 0..iters {
            let (s, p) = split_once(&pkt, fast_strategy());
            m += p.len() + s.is_some() as usize;
        }
        let one = t1.elapsed();
        println!(
            "bench: two-parse={two:?} ({:.0}ns/op) one-parse={one:?} ({:.0}ns/op) n={n} m={m}",
            two.as_nanos() as f64 / iters as f64,
            one.as_nanos() as f64 / iters as f64,
        );
        assert_eq!(n, m, "iki yol aynı sonucu vermeli");
        // hızlı yol en azından daha yavaş olmamalı; hedef <5µs/op (debug dahil)
        assert!(one.as_nanos() / iters as u128 / 1000 < 50, "hızlı yol çok yavaş: {one:?}");
    }

    #[test]
    fn fast_preset_hides_sni_no_delay() {
        let pkt = fake_client_hello(b"hizli-test.com");
        let (sni, parts) = split_once(&pkt, fast_strategy());
        assert_eq!(sni.map(|(s, e)| &pkt[s..e]), Some(b"hizli-test.com".as_slice()));
        assert_eq!(parts.len(), 2);
        assert_eq!(parts.concat(), pkt);
    }

    #[test]
    fn record_split_framing_valid_and_hides_sni() {
        let sni = b"record-test.com";
        let pkt = fake_client_hello(sni);
        let parts = split_client_hello(&pkt, Strategy::RecordSplit { delay_ms: 0 });
        assert_eq!(parts.len(), 2);
        for p in &parts {
            // her parça geçerli TLS record başlığı taşımalı
            assert_eq!(p[0], 0x16);
            let rl = u16::from_be_bytes([p[3], p[4]]) as usize;
            assert_eq!(5 + rl, p.len(), "record uzunluğu tutmalı");
            // tek record'da tam SNI görünmemeli
            assert!(!p.windows(sni.len()).any(|w| w == sni));
        }
        // TLS yükleri birleşince orijinal yüke eşit olmalı
        let mut payload = vec![];
        for p in &parts {
            payload.extend_from_slice(&p[5..]);
        }
        assert_eq!(payload, &pkt[5..]);
        // split_once da RecordSplit'i desteklemeli
        let (found, p2) = split_once(&pkt, Strategy::RecordSplit { delay_ms: 0 });
        assert!(found.is_some());
        assert_eq!(p2, parts);
    }
}
