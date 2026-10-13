"""DNS Doktoru - saf cozumleme ve karsilastirma fonksiyonlari.

Bu modul ag paketlerine dokunmaz; yalnizca sistem cozucuyu
(`socket.getaddrinfo`) ve DoH JSON API'yi (`urllib`) kullanir.
"""
import json
import socket
import urllib.parse
import urllib.request

DOH_URL = "https://cloudflare-dns.com/dns-query"
DOH_TIMEOUT = 5

DURUM_TAMAM = "TAMAM"
DURUM_ENGELLI = "ENGELLİ/ZEHİRLİ olabilir"
DURUM_COZULEMEDI = "ÇÖZÜLEMEDİ"


def cozum_sistem(host):
    """Sistem DNS'i ile coz. Donus: (ip_listesi, hata)."""
    try:
        bilgiler = socket.getaddrinfo(host, None, socket.AF_INET,
                                      socket.SOCK_STREAM)
    except socket.gaierror as exc:
        return [], str(exc)
    except OSError as exc:
        return [], str(exc)
    ipler = sorted({b[4][0] for b in bilgiler})
    return ipler, None


def doh_json_coz(yanit):
    """Cloudflare DoH JSON cevabini coz. Donus: (ip_listesi, hata)."""
    if not isinstance(yanit, dict):
        return [], "gecersiz yanit"
    cevaplar = yanit.get("Answer") or []
    ipler = sorted({c.get("data") for c in cevaplar
                    if isinstance(c, dict) and c.get("type") == 1
                    and c.get("data")})
    if not ipler:
        return [], "A kaydi yok"
    return ipler, None


def cozum_doh(host, zaman_asimi=DOH_TIMEOUT):
    """DoH (Cloudflare JSON API) ile coz. Donus: (ip_listesi, hata)."""
    adres = DOH_URL + "?name=" + urllib.parse.quote(host) + "&type=A"
    istek = urllib.request.Request(
        adres, headers={"Accept": "application/dns-json"})
    try:
        with urllib.request.urlopen(istek, timeout=zaman_asimi) as bag:
            veri = bag.read().decode("utf-8", "replace")
        return doh_json_coz(json.loads(veri))
    except Exception as exc:  # ag yok, zaman asimi, bozuk JSON
        return [], str(exc)


def sinifla(sis_ipler, doh_ipler, sis_hata, doh_hata):
    """Iki cozumu karsilastir, durum dizesi dondur."""
    if sis_hata and doh_ipler:
        return DURUM_ENGELLI
    if sis_ipler and doh_ipler:
        if set(sis_ipler) == set(doh_ipler):
            return DURUM_TAMAM
        return DURUM_ENGELLI
    if sis_ipler and not doh_ipler:
        return DURUM_TAMAM
    return DURUM_COZULEMEDI


def sonuc_metni(host, sis_ipler, doh_ipler, durum):
    """Panoya kopyalanacak duz metin satiri."""
    sis = ",".join(sis_ipler) if sis_ipler else "-"
    doh = ",".join(doh_ipler) if doh_ipler else "-"
    return f"{host} | sistem: {sis} | doh: {doh} | {durum}"
