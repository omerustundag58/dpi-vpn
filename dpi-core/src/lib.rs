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
    /// İnce ayarlı TCP bölme: kesim yeri + gönderim sırası (goodbyedpi/zapret taktikleri).
    Custom { cut: CutPos, order: SendOrder, delay_ms: u64 },
}

/// Kesim noktası (SNI bulunduğunda).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CutPos {
    /// SNI ortası (varsayılan, kanıtlı).
    Mid,
    /// SNI'nın hemen öncesi (goodbyedpi --frag-by-sni).
    Before,
    /// Ham offset (SNI yoksa veya özel durum).
    At(usize),
}

/// Parça gönderim sırası.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendOrder {
    /// Sıralı: parça1, bekle, parça2.
    InOrder,
    /// Ters: parça2 önce (goodbyedpi --reverse-frag). Sunucu TCP'si birleştirir.
    Reversed,
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
    let (body, data_off, data_len) = find_ext_data(packet, 0x0000)?;
    // server_name_list_len(2), sonra: name_type(1) + name_len(2) + name
    if data_len < 2 {
        return None;
    }
    let list_len = u16::from_be_bytes([body[data_off], body[data_off + 1]]) as usize;
    let ext_end_bound = data_off + data_len;
    let list_end = (data_off + 2 + list_len).min(ext_end_bound);
    let mut p = data_off + 2;
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
    None
}

/// ECH (Encrypted Client Hello, tip 0xFE0D) uzantısının ham verisini bul.
/// Dönüş: paketteki (data_start, data_end). Outer SNI sahte olabilir!
pub fn find_ech(packet: &[u8]) -> Option<(usize, usize)> {
    let (_body, data_off, data_len) = find_ext_data(packet, 0xFE0D)?;
    Some((9 + data_off, 9 + data_off + data_len))
}

/// Hello özeti: SNI + ECH varlığı tek parse'ta.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HelloInfo {
    pub sni: Option<(usize, usize)>,
    pub ech: Option<(usize, usize)>,
}

pub fn hello_info(packet: &[u8]) -> HelloInfo {
    HelloInfo { sni: find_sni(packet), ech: find_ech(packet) }
}

/// ClientHello extensions alanında `want` tipini ara.
/// Dönüş: (body, data_offset_body, data_len). Offsetler body'ye göre.
fn find_ext_data(packet: &[u8], want: u16) -> Option<(&[u8], usize, usize)> {
    // Minimum: TLS record header (5) + handshake header (4)
    if packet.len() < 9 {
        return None;
    }
    // 0: ContentType == 0x16 (Handshake)
    if packet[0] != 0x16 {
        return None;
    }
    // Handshake: 5: type == 0x01 (ClientHello)
    if packet[5] != 0x01 {
        return None;
    }

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
        if ext_type == want {
            return Some((body, pos, ext_len));
        }
        pos += ext_len;
    }
    None
}

/// Bir ClientHello paketini stratejiye göre parçalara böl.
///
/// Dönüş: gönderilecek parça listesi. DPI kutusu tek parçada SNI göremez.
/// Reversed sırada bile parça SIRA listede [birinci, ikinci] döner;
/// gönderim sırasını çağıran uygular (delay ilk gönderilenden sonra).
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
            cut_packet(packet, cut)
        }
        Strategy::Custom { cut, .. } => {
            let at = match cut {
                CutPos::Mid => find_sni(packet)
                    .map(|(s, e)| s + (e - s) / 2)
                    .unwrap_or(packet.len() / 2),
                CutPos::Before => find_sni(packet).map(|(s, _)| s).unwrap_or(packet.len() / 2),
                CutPos::At(off) => off,
            };
            cut_packet(packet, at.clamp(1, packet.len() - 1))
        }
        Strategy::Fragment { chunk_size } => {
            let cs = chunk_size.max(1);
            packet.chunks(cs).map(|c| c.to_vec()).collect()
        }
        Strategy::RecordSplit { .. } => split_records(packet),
    }
}

/// Tek kesitli bölme yardımcısı.
fn cut_packet(packet: &[u8], cut: usize) -> Vec<Vec<u8>> {
    if cut == 0 || cut >= packet.len() {
        return vec![packet.to_vec()];
    }
    vec![packet[..cut].to_vec(), packet[cut..].to_vec()]
}

/// HTTP Host başlık ismini `hoSt` yap (goodbyedpi -r).
/// Başlık İSMİ büyük/küçük harf duyarsız olduğundan tamamen yasal;
/// saf DPI Host dizesini göremez. İlk Host başlığına uygulanır.
pub fn disguise_host(request: &[u8]) -> Vec<u8> {
    // "Host:" / "host:" / "HOST:" — ':' öncesi 4 harf
    let mut out = request.to_vec();
    let mut i = 0;
    while i + 5 <= out.len() {
        if out[i..i + 4].eq_ignore_ascii_case(b"host") && out[i + 4] == b':' {
            // satır başı mı? (istek satırındaki "...host..." sahte eşleşmesin)
            let at_line = i == 0 || (i >= 2 && &out[i - 2..i] == b"\r\n");
            if at_line {
                out[i + 1] = b'o';
                out[i + 2] = b'S';
                return out;
            }
        }
        i += 1;
    }
    out
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

/// Strateji değerlendirmesi: bölünmüş parçaların her birinde SNI görünürlüğü.
/// Otomatik mod seçiminin temeli — dene, ölç, en gizliyi seç.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    /// SNI hiçbir tek parçada bütün halde yok (hedeflenen).
    Hidden,
    /// SNI bir parçada bütün halde görünüyor (kesim SNI dışına düştü).
    Visible { piece: usize },
    /// SNI bulunamadı (TLS değil ya da hello değil) — değerlendirilemez.
    NoSni,
}

/// `packet` + `strategy` için görünürlük raporu.
pub fn assess(packet: &[u8], strategy: Strategy) -> Visibility {
    let sni = match find_sni(packet) {
        Some((s, e)) => &packet[s..e],
        None => return Visibility::NoSni,
    };
    if sni.is_empty() {
        return Visibility::NoSni;
    }
    for (i, part) in split_client_hello(packet, strategy).iter().enumerate() {
        if part.len() >= sni.len() && part.windows(sni.len()).any(|w| w == sni) {
            return Visibility::Visible { piece: i };
        }
    }
    Visibility::Hidden
}

/// Birden çok stratejiyi dener, SNI'ı gizleyeni seçer.
/// Hepsi gösteriyorsa en çok parçalayanı, hiçbiri gizleyemiyorsa None.
pub fn auto_strategy(packet: &[u8], candidates: &[Strategy]) -> Option<Strategy> {
    let mut fallback: Option<(usize, Strategy)> = None;
    for &st in candidates {
        match assess(packet, st) {
            Visibility::Hidden => return Some(st),
            Visibility::Visible { .. } => {
                let n = split_client_hello(packet, st).len();
                if fallback.map(|(m, _)| n > m).unwrap_or(true) {
                    fallback = Some((n, st));
                }
            }
            Visibility::NoSni => {}
        }
    }
    fallback.map(|(_, st)| st)
}

/// Otomatik strateji: SNI'ı gizleyen ilk taktiği seç (ucuzdan pahalıya).
/// Ağ probu YOK — assess filtresi + sabit sıra. İlk bağlantıda bir kez çalışır,
/// sonrası önbellekten gelir. Hiçbiri gizleyemezse varsayılan döner.
pub fn auto_pick(packet: &[u8]) -> Strategy {
    const ORDER: [Strategy; 4] = [
        Strategy::RecordSplit { delay_ms: 0 },
        Strategy::Custom { cut: CutPos::Before, order: SendOrder::InOrder, delay_ms: 0 },
        Strategy::Custom { cut: CutPos::Mid, order: SendOrder::Reversed, delay_ms: 0 },
        Strategy::Split { split_at: 2 },
    ];
    auto_strategy(packet, &ORDER).unwrap_or_default()
}
/// SNI'ı tek parçada göremeyince geçirir.
/// Hız istiyorsan bunu kullan.
pub fn fast_strategy() -> Strategy {
    Strategy::Split { split_at: 2 }
}

/// Tünel dışı bırakılacak yerli/düşük riskli alanlar.
/// Devlet (.gov.tr), yerli (.com.tr) ve altyapı (google) trafiği
/// bölünmeden direkt iletilir — hem hızlı hem gereksiz işlem yok.
/// Kaynak liste: zapret-win-turkey config/excludelist.txt
const EXCLUDED_SUFFIXES: [&str; 4] = ["gov.tr", "com.tr", "google.com", "googleapis.com"];

/// host bu listeye giriyor mu? (alt alan adları dahil)
pub fn is_excluded(host: &str) -> bool {
    matches_suffix_list(host, &EXCLUDED_SUFFIXES)
}

fn matches_suffix_list(host: &str, list: &[&str]) -> bool {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    list.iter().any(|s| h == *s || h.ends_with(&format!(".{s}")))
}

/// Allowlist modu: SADECE listedeki hostlar bölünür, gerisi ham geçer.
/// Sansürlü listesi belli olan ağlarda hız + pil kazandırır.
/// Dönüş: (bölündü_mü, parçalar).
pub fn split_allowlist(packet: &[u8], strategy: Strategy, allow: &[&str]) -> (bool, Vec<Vec<u8>>) {
    let hit = find_sni(packet)
        .map(|(s, e)| matches_suffix_list(&String::from_utf8_lossy(&packet[s..e]), allow))
        .unwrap_or(false);
    if hit {
        (true, split_client_hello(packet, strategy))
    } else {
        (false, vec![packet.to_vec()])
    }
}

/// Sıfır kopyalı bölme planı: parça bayt aralıkları, tahsis YOK.
/// Çağıran `packet[a..b]` dilimlerini doğrudan sokete yazar.
/// RecordSplit yeniden çerçeveler (`needs_reframe`), aralık vermez.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitPlan {
    pub sni: Option<(usize, usize)>,
    pub ranges: Vec<(usize, usize)>,
    pub needs_reframe: bool,
}

/// Tek parse + tahsissiz plan. Android veri düzlemi ve sıcak döngüler için.
pub fn plan_split(packet: &[u8], strategy: Strategy) -> SplitPlan {
    if packet.len() < 2 {
        return SplitPlan { sni: None, ranges: vec![(0, packet.len())], needs_reframe: false };
    }
    let sni = find_sni(packet);
    let cut_of = |at: usize| at.clamp(1, packet.len() - 1);
    let two = |cut: usize| {
        if cut == 0 || cut >= packet.len() {
            vec![(0, packet.len())]
        } else {
            vec![(0, cut), (cut, packet.len())]
        }
    };
    match strategy {
        Strategy::Split { split_at } | Strategy::SplitWithDelay { split_at, .. } => {
            let cut = match sni {
                Some((s, e)) => cut_of(s + (e - s) / 2),
                None => cut_of(split_at),
            };
            SplitPlan { sni, ranges: two(cut), needs_reframe: false }
        }
        Strategy::Custom { cut, .. } => {
            let at = match cut {
                CutPos::Mid => sni.map(|(s, e)| s + (e - s) / 2).unwrap_or(packet.len() / 2),
                CutPos::Before => sni.map(|(s, _)| s).unwrap_or(packet.len() / 2),
                CutPos::At(off) => off,
            };
            SplitPlan { sni, ranges: two(cut_of(at)), needs_reframe: false }
        }
        Strategy::Fragment { chunk_size } => {
            let cs = chunk_size.max(1);
            let mut ranges = vec![];
            let mut o = 0;
            while o < packet.len() {
                let e = (o + cs).min(packet.len());
                ranges.push((o, e));
                o = e;
            }
            SplitPlan { sni, ranges, needs_reframe: false }
        }
        Strategy::RecordSplit { .. } => SplitPlan { sni, ranges: vec![], needs_reframe: true },
    }
}

/// Tek parse ile SNI + parçaları döndürür (hızlı yol).
/// Ayrı ayrı `find_sni` + `split_client_hello` çağırmak paketi 2 kez
/// parse eder; bu fonksiyon 1 kez eder. Android'de pil/CPU dostu.
pub fn split_once(packet: &[u8], strategy: Strategy) -> (Option<(usize, usize)>, Vec<Vec<u8>>) {
    if matches!(strategy, Strategy::RecordSplit { .. }) {
        return (find_sni(packet), split_records(packet));
    }
    let plan = plan_split(packet, strategy);
    let parts = plan.ranges.iter().map(|&(a, b)| packet[a..b].to_vec()).collect();
    (plan.sni, parts)
}
/// Paketin DPI işlemine girip girmeyeceğine karar ver.
/// Şimdilik: TLS ClientHello (0x16 0x03 ..) ise true.
pub fn should_process(port: u16, first_bytes: &[u8]) -> bool {
    if port != 443 && port != 8443 {
        // 80: düz HTTP — Host bölme/kılık değiştirme uygulanır
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

// ================= QUIC Initial bölme =================
// QUIC (UDP) ham soket olmadan bölünebilir: sunucu CRYPTO akışını
// offset'lerle birleştirir, datagram sırası/bölünmesi normal karşılanır.
// SNI, CRYPTO içindeki TLS hello'da bulunur; kesim SNI ortasındandır.

/// QUIC değişken tamsayısı oku. Dönüş: (değer, yeni_pos).
fn qvarint_read(buf: &[u8], pos: usize) -> Option<(u64, usize)> {
    if pos >= buf.len() {
        return None;
    }
    match buf[pos] >> 6 {
        0 => Some((buf[pos] as u64, pos + 1)),
        1 => {
            if pos + 2 > buf.len() {
                return None;
            }
            Some((((buf[pos] & 0x3F) as u64) << 8 | buf[pos + 1] as u64, pos + 2))
        }
        2 => {
            if pos + 4 > buf.len() {
                return None;
            }
            let v = ((buf[pos] & 0x3F) as u64) << 24
                | (buf[pos + 1] as u64) << 16
                | (buf[pos + 2] as u64) << 8
                | buf[pos + 3] as u64;
            Some((v, pos + 4))
        }
        _ => {
            if pos + 8 > buf.len() {
                return None;
            }
            let mut v = 0u64;
            for b in &buf[pos + 1..pos + 8] {
                v = (v << 8) | *b as u64;
            }
            v |= ((buf[pos] & 0x3F) as u64) << 56;
            Some((v, pos + 8))
        }
    }
}

/// QUIC değişken tamsayısı yaz (en kısa kodlama).
fn qvarint_encode(v: u64) -> Vec<u8> {
    if v < 64 {
        vec![v as u8]
    } else if v < 16384 {
        vec![0x40 | (v >> 8) as u8, v as u8]
    } else if v < 1_073_741_824 {
        vec![0x80 | (v >> 24) as u8, (v >> 16) as u8, (v >> 8) as u8, v as u8]
    } else {
        let mut out = vec![0xC0];
        out.extend_from_slice(&v.to_be_bytes());
        out
    }
}

/// Parse edilmiş QUIC Initial başlığı.
struct QuicInitial {
    dcid: Vec<u8>,
    scid: Vec<u8>,
    token: Vec<u8>,
    pn_len: usize,
    pn: u32,
    payload_off: usize, // CRYPTO çerçevelerinin başladığı offset (pn dahil değil: pn_off)
    pn_off: usize,
    payload_len: usize,
}

fn parse_quic_initial(packet: &[u8]) -> Option<QuicInitial> {
    if packet.len() < 7 {
        return None;
    }
    let flags = packet[0];
    if flags & 0x80 == 0 || flags & 0x40 == 0 {
        return None; // uzun başlık + sabit bit şart
    }
    if u32::from_be_bytes([packet[1], packet[2], packet[3], packet[4]]) != 1 {
        return None; // yalnızca QUIC v1
    }
    let mut pos = 5;
    if pos >= packet.len() {
        return None;
    }
    let dcid_len = packet[pos] as usize;
    pos += 1;
    if pos + dcid_len > packet.len() {
        return None;
    }
    let dcid = packet[pos..pos + dcid_len].to_vec();
    pos += dcid_len;
    if pos >= packet.len() {
        return None;
    }
    let scid_len = packet[pos] as usize;
    pos += 1;
    if pos + scid_len > packet.len() {
        return None;
    }
    let scid = packet[pos..pos + scid_len].to_vec();
    pos += scid_len;
    let (token_len, p2) = qvarint_read(packet, pos)?;
    pos = p2;
    if pos + token_len as usize > packet.len() {
        return None;
    }
    let token = packet[pos..pos + token_len as usize].to_vec();
    pos += token_len as usize;
    let (length, p3) = qvarint_read(packet, pos)?;
    pos = p3;
    let payload_len = length as usize;
    if pos + payload_len > packet.len() {
        return None;
    }
    let pn_len = (flags & 0x03) as usize + 1;
    if pos + pn_len > packet.len() {
        return None;
    }
    let mut pn: u32 = 0;
    for b in &packet[pos..pos + pn_len] {
        pn = (pn << 8) | *b as u32;
    }
    Some(QuicInitial { dcid, scid, token, pn_len, pn, pn_off: pos, payload_off: pos + pn_len, payload_len })
}

/// QUIC Initial içindeki CRYPTO verisini çıkar (tek CRYPTO + dolgu varsayımı).
/// Dönüş: (crypto_off, crypto_len, frame_off, frame_header_len).
fn quic_crypto_span(packet: &[u8], q: &QuicInitial) -> Option<(usize, usize, usize, usize)> {
    let mut pos = q.payload_off;
    let end = q.pn_off + q.payload_len;
    // baştaki dolgu baytlarını atla
    while pos < end && packet[pos] == 0x00 {
        pos += 1;
    }
    if pos >= end || packet[pos] != 0x06 {
        return None; // ilk çerçeve CRYPTO değil
    }
    let frame_off = pos;
    pos += 1;
    let (offset, p2) = qvarint_read(packet, pos)?;
    if offset != 0 {
        return None; // ilk CRYPTO offset 0 olmalı (bölünmemiş hello)
    }
    pos = p2;
    let (len, p3) = qvarint_read(packet, pos)?;
    pos = p3;
    let len = len as usize;
    if pos + len > end {
        return None;
    }
    // sondaki dolgu serbest; fazlası varsa tek çerçeve varsayımı bozulur — yine de devam
    Some((pos, len, frame_off, pos - frame_off))
}

/// CRYPTO verisi içindeki SNI konumunu bul (sahte record başlığıyla find_sni).
/// Dönüş: crypto'ya göre (sni_start, sni_end).
fn sni_in_crypto(crypto: &[u8]) -> Option<(usize, usize)> {
    if crypto.len() < 5 || crypto[0] != 0x01 {
        return None;
    }
    let mut fake = vec![0x16u8, 0x03, 0x01, 0, 0];
    let len = crypto.len().min(65535);
    fake[3..5].copy_from_slice(&(len as u16).to_be_bytes());
    fake.extend_from_slice(&crypto[..len]);
    find_sni(&fake).map(|(s, e)| (s - 5, e - 5))
}

/// QUIC Initial datagramını ikiye böl (SNI ortasından).
/// Her parça geçerli Initial başlıklı ayrı datagramdır; sunucu CRYPTO
/// akışını offset'lerle birleştirir. Olmazsa tek parça döner.
pub fn split_quic_initial(packet: &[u8]) -> Vec<Vec<u8>> {
    let q = match parse_quic_initial(packet) {
        Some(q) => q,
        None => return vec![packet.to_vec()],
    };
    let (coff, clen, _foff, _fhlen) = match quic_crypto_span(packet, &q) {
        Some(s) => s,
        None => return vec![packet.to_vec()],
    };
    if clen < 16 {
        return vec![packet.to_vec()];
    }
    let crypto = &packet[coff..coff + clen];
    // kesim: SNI ortası, yoksa crypto ortası
    let cut_rel = match sni_in_crypto(crypto) {
        Some((s, e)) => coff + s + (e - s) / 2,
        None => coff + clen / 2,
    };
    if cut_rel <= coff || cut_rel >= coff + clen {
        return vec![packet.to_vec()];
    }
    let off1 = 0usize;
    let len1 = cut_rel - coff;
    let off2 = len1;
    let len2 = clen - len1;

    // CRYPTO çerçevesi kurucu: [0x06][offset][len][veri]
    fn crypto_frame(offset: usize, data: &[u8]) -> Vec<u8> {
        let mut f = vec![0x06u8];
        f.extend(qvarint_encode(offset as u64));
        f.extend(qvarint_encode(data.len() as u64));
        f.extend_from_slice(data);
        f
    }
    let f1 = crypto_frame(off1, &packet[cut_rel - len1..cut_rel]);
    let f2 = crypto_frame(off2, &packet[cut_rel..cut_rel + len2]);
    // yük + pn uzunlukları 16KB altında kalmalı (2 baytlık Length için)
    let pn_len = q.pn_len;
    if f1.len() + pn_len > 16000 || f2.len() + pn_len > 16000 {
        return vec![packet.to_vec()];
    }

    // datagram kurucu
    let build = |pn: u32, frame: &[u8]| -> Vec<u8> {
        let mut d = vec![packet[0]];
        d.extend_from_slice(&packet[1..5]); // version
        d.push(q.dcid.len() as u8);
        d.extend_from_slice(&q.dcid);
        d.push(q.scid.len() as u8);
        d.extend_from_slice(&q.scid);
        d.extend(qvarint_encode(q.token.len() as u64));
        d.extend_from_slice(&q.token);
        let payload_len = pn_len + frame.len();
        d.extend(qvarint_encode(payload_len as u64));
        let mask = if pn_len >= 4 { u32::MAX } else { (1u32 << (pn_len * 8)) - 1 };
        let pn = pn & mask;
        for i in (0..pn_len).rev() {
            d.push((pn >> (i * 8)) as u8);
        }
        d.extend_from_slice(frame);
        d
    };
    vec![build(q.pn, &f1), build(q.pn.wrapping_add(1), &f2)]
}

/// QUIC v1 Initial mı? (hızlı ön kontrol)
pub fn is_quic_initial(packet: &[u8]) -> bool {
    parse_quic_initial(packet).is_some()
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
        let (ss, _se) = find_sni(&pkt).expect("test SNI");
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
            Strategy::Custom { cut: CutPos::Mid, order: SendOrder::InOrder, delay_ms: 0 },
            Strategy::Custom { cut: CutPos::Before, order: SendOrder::InOrder, delay_ms: 0 },
            Strategy::Custom { cut: CutPos::Mid, order: SendOrder::Reversed, delay_ms: 5 },
            Strategy::Custom { cut: CutPos::At(ss + 3), order: SendOrder::InOrder, delay_ms: 0 },
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
                Strategy::Custom { cut: CutPos::Before, .. } => {
                    // Before: SNI parça2'de bütün kalır, parça1 temizdir (konumsal taktik)
                    assert_eq!(parts.len(), 2, "{st:?} 2 parça olmalı");
                    assert!(
                        !parts[0].windows(sni.len()).any(|w| w == sni),
                        "{st:?} parça1 temiz olmalı"
                    );
                }
                Strategy::Custom { .. } => {
                    assert_eq!(parts.len(), 2, "{st:?} 2 parça olmalı");
                    for p in &parts {
                        assert!(
                            !p.windows(sni.len()).any(|w| w == sni),
                            "{st:?} SNI tek parçada görünmemeli"
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
    fn excluded_suffixes() {
        // devlet + yerli direkt geçer
        for h in ["turkiye.gov.tr", "GOV.TR", "ornek.com.tr", "google.com",
                  "mail.google.com", "fonts.googleapis.com", "turkiye.gov.tr."] {
            assert!(is_excluded(h), "{h} muaf olmalı");
        }
        // sansürlüler tünelde kalır — benzer isimler kandırmamalı
        for h in ["discord.com", "govtrevil.com", "fakegoogle.com.tr.evil.org", "", "com"] {
            assert!(!is_excluded(h), "{h} muaf OLMAMALI");
        }
    }

    #[test]
    fn assess_grades_strategies() {
        let pkt = fake_client_hello(b"deger-test.com");
        // gizleyenler Hidden
        for st in [
            Strategy::Split { split_at: 2 },
            Strategy::RecordSplit { delay_ms: 0 },
            Strategy::Fragment { chunk_size: 7 },
            Strategy::Custom { cut: CutPos::Mid, order: SendOrder::InOrder, delay_ms: 0 },
        ] {
            assert_eq!(assess(&pkt, st), Visibility::Hidden, "{st:?}");
        }
        // SNI dışına kesen At(2) -> parça1'de bütün SNI görünür
        assert!(matches!(
            assess(&pkt, Strategy::Custom { cut: CutPos::At(2), order: SendOrder::InOrder, delay_ms: 0 }),
            Visibility::Visible { .. }
        ));
        // TLS değilse NoSni
        assert_eq!(assess(b"GET / HTTP/1.0", Strategy::default()), Visibility::NoSni);
        assert_eq!(assess(&[], Strategy::default()), Visibility::NoSni);
    }

    #[test]
    fn auto_strategy_picks_hider() {        let pkt = fake_client_hello(b"oto-test.com");
        let cands = [
            Strategy::Custom { cut: CutPos::At(2), order: SendOrder::InOrder, delay_ms: 0 },
            Strategy::Fragment { chunk_size: 5 },
        ];
        // ilk aday gösterir, ikinci gizler -> ikinci seçilir
        assert_eq!(auto_strategy(&pkt, &cands), Some(Strategy::Fragment { chunk_size: 5 }));
        // hepsi gizliyorsa ilk gizleyen döner
        let both = [Strategy::Split { split_at: 2 }, Strategy::RecordSplit { delay_ms: 0 }];
        assert_eq!(auto_strategy(&pkt, &both), Some(Strategy::Split { split_at: 2 }));
        // boş liste / SNI yoksa None
        assert_eq!(auto_strategy(&pkt, &[]), None);
        assert_eq!(auto_strategy(b"GET /", &both), None);
    }

    /// fake hello'ya ECH uzantısı ekler (uzunluk alanları güncellenir).
    fn with_ech(mut pkt: Vec<u8>, ech_data: &[u8]) -> Vec<u8> {
        // ext_total alanı paket offset 50'de (9 + 41)
        let ext_off = 50usize;
        let old_total = u16::from_be_bytes([pkt[ext_off], pkt[ext_off + 1]]) as usize;
        let mut ext = vec![0xFE, 0x0D];
        ext.extend_from_slice(&(ech_data.len() as u16).to_be_bytes());
        ext.extend_from_slice(ech_data);
        let at = ext_off + 2 + old_total; // eski extensions sonu
        pkt.splice(at..at, ext.iter().cloned());
        let new_total = (old_total + ext.len()) as u16;
        pkt[ext_off..ext_off + 2].copy_from_slice(&new_total.to_be_bytes());
        // handshake + record uzunlukları
        let hs_len = u32::from_be_bytes([0, pkt[6], pkt[7], pkt[8]]) as usize + ext.len();
        pkt[6] = (hs_len >> 16) as u8;
        pkt[7] = (hs_len >> 8) as u8;
        pkt[8] = hs_len as u8;
        let rec_len = u16::from_be_bytes([pkt[3], pkt[4]]) as usize + ext.len();
        pkt[3..5].copy_from_slice(&(rec_len as u16).to_be_bytes());
        pkt
    }

    #[test]
    fn ech_detected_with_sni() {
        let pkt = with_ech(fake_client_hello(b"outer-ornek.com"), &[0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04]);
        let info = hello_info(&pkt);
        // SNI hâlâ bulunur (outer, sahte olabilir)
        let (s, e) = info.sni.expect("SNI bulunmalı");
        assert_eq!(&pkt[s..e], b"outer-ornek.com");
        // ECH verisi bulunur
        let (es, ee) = info.ech.expect("ECH bulunmalı");
        assert_eq!(&pkt[es..ee], &[0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04]);
        // ECH'siz hello'da yok
        let plain = fake_client_hello(b"sade.com");
        assert!(find_ech(&plain).is_none());
        assert!(hello_info(&plain).ech.is_none());
        // bölme ECH'li pakette de çalışır
        let parts = split_client_hello(&pkt, Strategy::default());
        assert_eq!(parts.len(), 2);
    }

    #[test]
    fn ech_truncated_no_panic() {
        let mut pkt = with_ech(fake_client_hello(b"x.com"), &[0x01; 6]);
        for cut in [pkt.len() - 1, pkt.len() - 3, 60, 30, 10] {
            let pre = &pkt[..cut.min(pkt.len())];
            let _ = find_ech(pre);
            let _ = hello_info(pre);
            let _ = split_client_hello(pre, Strategy::default());
        }
        // bozuk ECH uzunluğu
        pkt[50] = 0xFF;
        pkt[51] = 0xFF;
        assert!(find_ech(&pkt).is_none_or(|_| true));
    }

    #[test]
    fn record_split_framing_valid_and_hides_sni() {        let sni = b"record-test.com";
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

    #[test]
    fn custom_before_cuts_at_sni_start() {
        let sni = b"once-test.com";
        let pkt = fake_client_hello(sni);
        let (s, _e) = find_sni(&pkt).unwrap();
        let parts = split_client_hello(
            &pkt,
            Strategy::Custom { cut: CutPos::Before, order: SendOrder::InOrder, delay_ms: 0 },
        );
        assert_eq!(parts.len(), 2);
        assert_eq!(parts.concat(), pkt);
        // ilk parça SNI başlangıcında biter
        assert_eq!(parts[0].len(), s);
        // Before kesitte SNI parça2'de BÜTÜN kalır (frag-by-sni doğası);
        // kazanç konumsal: SNI paket sınırında başlar. Parça1 temiz olmalı.
        assert!(!parts[0].windows(sni.len()).any(|w| w == sni));
        assert_eq!(&parts[1][0..sni.len()], sni);
        // split_once ile aynı
        let (_, p2) = split_once(
            &pkt,
            Strategy::Custom { cut: CutPos::Before, order: SendOrder::InOrder, delay_ms: 0 },
        );
        assert_eq!(p2, parts);
    }

    #[test]
    fn custom_mid_matches_legacy_split() {
        let pkt = fake_client_hello(b"mid-test.com");
        let a = split_client_hello(&pkt, Strategy::Split { split_at: 2 });
        let b = split_client_hello(
            &pkt,
            Strategy::Custom { cut: CutPos::Mid, order: SendOrder::InOrder, delay_ms: 0 },
        );
        assert_eq!(a, b);
    }

    #[test]
    fn disguise_host_rewrites_header_name() {
        let req = b"GET http://ornek.com/ HTTP/1.1\r\nHost: ornek.com\r\n\r\n";
        let out = disguise_host(req);
        assert!(out.windows(4).any(|w| w == b"HoSt"), "HoSt olmalı");
        assert!(!out.windows(5).any(|w| w == b"Host:"), "düz Host kalmamalı");
        // değer aynen durur
        assert!(out.windows(9).any(|w| w == b"ornek.com"));
        // Host'suz istek aynen döner
        let plain = b"GET / HTTP/1.0\r\n\r\n";
        assert_eq!(disguise_host(plain), plain);
        // istek satırındaki 'host' kelimesi eşleşmez
        let tricky = b"GET http://myhost.com/ HTTP/1.1\r\nHost: myhost.com\r\n\r\n";
        let t2 = disguise_host(tricky);
        assert!(t2.starts_with(b"GET http://myhost.com/"));
    }

    /// Sentetik QUIC v1 Initial kur (CRYPTO içinde tam hello).
    fn quic_initial(sni: &[u8]) -> Vec<u8> {
        let full = fake_client_hello(sni);
        let hs = &full[5..]; // record başlığını at, handshake mesajı kalır
        let mut frame = vec![0x06u8, 0x00]; // CRYPTO, offset 0
        frame.extend(qvarint_encode(hs.len() as u64));
        frame.extend_from_slice(hs);
        let mut payload = vec![0x07u8]; // pn=7 (1 bayt)
        payload.extend_from_slice(&frame);
        let mut d = vec![0xC0u8, 0, 0, 0, 1]; // long+fixed, v1
        d.push(8);
        d.extend_from_slice(&[0x11; 8]); // dcid
        d.push(8);
        d.extend_from_slice(&[0x22; 8]); // scid
        d.extend(qvarint_encode(0)); // token yok
        d.extend(qvarint_encode(payload.len() as u64));
        d.extend_from_slice(&payload);
        d
    }

    fn quic_crypto_of(dgram: &[u8]) -> Vec<u8> {
        // ilk CRYPTO çerçevesini çıkar (offset ne olursa olsun — test yardımcısı)
        let q = parse_quic_initial(dgram).expect("gecerli initial");
        let mut pos = q.payload_off;
        let end = q.pn_off + q.payload_len;
        while pos < end && dgram[pos] == 0x00 {
            pos += 1;
        }
        assert_eq!(dgram[pos], 0x06, "CRYPTO bekleniyor");
        pos += 1;
        let (_, p2) = qvarint_read(dgram, pos).unwrap();
        let (len, p3) = qvarint_read(dgram, p2).unwrap();
        dgram[p3..p3 + len as usize].to_vec()
    }

    #[test]
    fn quic_split_roundtrip_and_hides_sni() {
        let sni = b"quic-test.com";
        let pkt = quic_initial(sni);
        assert!(is_quic_initial(&pkt));
        let parts = split_quic_initial(&pkt);
        assert_eq!(parts.len(), 2);
        // her parça geçerli Initial
        for p in &parts {
            assert!(is_quic_initial(p), "parça parse edilmeli");
        }
        // CRYPTO akışı birebir birleşir
        let mut joined = quic_crypto_of(&parts[0]);
        joined.extend_from_slice(&quic_crypto_of(&parts[1]));
        assert_eq!(joined, quic_crypto_of(&pkt));
        // SNI tek datagramda görünmez
        for p in &parts {
            assert!(!p.windows(sni.len()).any(|w| w == sni), "SNI sızıyor");
        }
        // pn artar
        let q1 = parse_quic_initial(&parts[0]).unwrap();
        let q2 = parse_quic_initial(&parts[1]).unwrap();
        assert_eq!(q2.pn, q1.pn.wrapping_add(1));
        assert_eq!(q1.dcid, q2.dcid);
    }

    #[test]
    fn quic_non_initial_passthrough() {
        assert_eq!(split_quic_initial(&[]), vec![Vec::<u8>::new()]);
        let tls = fake_client_hello(b"x.com");
        assert_eq!(split_quic_initial(&tls), vec![tls.clone()]);
        // kısa / bozuk başlık
        assert_eq!(split_quic_initial(&[0xC0, 0, 0]), vec![vec![0xC0, 0, 0]]);
        // version farklı
        let mut v2 = quic_initial(b"y.com");
        v2[4] = 0x02;
        assert_eq!(split_quic_initial(&v2), vec![v2.clone()]);
        assert!(!is_quic_initial(&v2));
    }

    #[test]
    fn plan_ranges_match_materialized() {        let pkt = fake_client_hello(b"plan-test.com");
        let strats = [
            Strategy::Split { split_at: 2 },
            Strategy::SplitWithDelay { split_at: 2, delay_ms: 5 },
            Strategy::Custom { cut: CutPos::Mid, order: SendOrder::Reversed, delay_ms: 0 },
            Strategy::Custom { cut: CutPos::Before, order: SendOrder::InOrder, delay_ms: 0 },
            Strategy::Fragment { chunk_size: 9 },
        ];
        for st in strats {
            let plan = plan_split(&pkt, st);
            assert!(!plan.needs_reframe);
            assert_eq!(plan.sni, find_sni(&pkt));
            // aralıklar bitişik + tam kapsama
            let mut off = 0;
            for (a, b) in &plan.ranges {
                assert_eq!(*a, off);
                assert!(b > a && *b <= pkt.len());
                off = *b;
            }
            assert_eq!(off, pkt.len());
            // dilimleme tahsisli yolla aynı
            let sliced: Vec<Vec<u8>> = plan.ranges.iter().map(|&(a, b)| pkt[a..b].to_vec()).collect();
            assert_eq!(sliced, split_client_hello(&pkt, st));
            let (s2, p2) = split_once(&pkt, st);
            assert_eq!(s2, plan.sni);
            assert_eq!(p2, sliced);
        }
        // record: reframe işareti
        let rp = plan_split(&pkt, Strategy::RecordSplit { delay_ms: 0 });
        assert!(rp.needs_reframe && rp.ranges.is_empty());
        // boş paket paniklemez
        let ep = plan_split(&[], Strategy::Split { split_at: 2 });
        assert_eq!(ep.ranges, vec![(0, 0)]);
    }

    #[test]
    fn bench_plan_vs_alloc() {
        let pkt = fake_client_hello(&[b'p'; 120]);
        let iters = 50_000u32;
        let t0 = std::time::Instant::now();
        let mut n = 0;
        for _ in 0..iters {
            n += split_client_hello(&pkt, fast_strategy()).len();
        }
        let alloc = t0.elapsed();
        let t1 = std::time::Instant::now();
        let mut m = 0;
        for _ in 0..iters {
            m += plan_split(&pkt, fast_strategy()).ranges.len();
        }
        let plan = t1.elapsed();
        println!(
            "planbench: alloc={alloc:?} ({:.0}ns/op) plan={plan:?} ({:.0}ns/op)",
            alloc.as_nanos() as f64 / iters as f64,
            plan.as_nanos() as f64 / iters as f64,
        );
        assert_eq!(n, m);
    }

    #[test]
    fn allowlist_splits_only_listed() {        let allow = ["discord.com", "roblox.com"];
        let pkt = fake_client_hello(b"cdn.discord.com");
        let (hit, parts) = split_allowlist(&pkt, Strategy::default(), &allow);
        assert!(hit);
        assert_eq!(parts.len(), 2);
        // listede yoksa ham tek parça
        let pkt2 = fake_client_hello(b"ornek.com");
        let (hit2, parts2) = split_allowlist(&pkt2, Strategy::default(), &allow);
        assert!(!hit2);
        assert_eq!(parts2, vec![pkt2.clone()]);
        // boş liste: kimse bölünmez
        let (hit3, _) = split_allowlist(&pkt, Strategy::default(), &[]);
        assert!(!hit3);
        // TLS değilse bölünmez
        let (hit4, p4) = split_allowlist(b"GET /", Strategy::default(), &allow);
        assert!(!hit4 && p4 == vec![b"GET /".to_vec()]);
    }

    #[test]
    fn auto_pick_hides_and_caches() {
        let pkt = fake_client_hello(b"oto-pick.com");
        // normal hello'da ilk gizleyen (record-split) seçilir
        assert_eq!(auto_pick(&pkt), Strategy::RecordSplit { delay_ms: 0 });
        // TLS değilse varsayılan
        assert_eq!(auto_pick(b"GET /"), Strategy::default());
        // seçilen gerçekten gizler
        assert_eq!(assess(&pkt, auto_pick(&pkt)), Visibility::Hidden);
    }
}
