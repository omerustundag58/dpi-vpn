"""DNS Doktoru - Windows DNS uygula/geri al.

Guvenlik kurallari:
- PowerShell komutlari tirnak kacirma olmadan calistirilir: komut
  UTF-16LE + base64 ile `-EncodedCommand` olarak verilir.
- Yoneticilik gerektiren komutlar `-Wait -PassThru` ile calistirilir,
  cikis kodu kontrol edilir.
- Degisim oncesi ayarlar %LOCALAPPDATA%\\DNSDoktoru\\onceki.json
  dosyasina kaydedilir; geri alma bu dosyadan yapilir.
- Ag paketlerine dokunulmaz, surucu kullanilmaz.
"""
import base64
import json
import os
import subprocess
import sys

DNS_BIRINCIL = "1.1.1.1"
DNS_IKINCIL = "1.0.0.1"
DOH_SABLON = "https://cloudflare-dns.com/dns-query"

KLASOR_ADI = "DNSDoktoru"
ONCEKI_DOSYA = "onceki.json"


def windows_mu():
    return sys.platform == "win32"


def onceki_yolu():
    taban = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    return os.path.join(taban, KLASOR_ADI, ONCEKI_DOSYA)


def yonetici_mi():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _kodlanmis(ps_komutu):
    ham = ps_komutu.encode("utf-16-le")
    return base64.b64encode(ham).decode("ascii")


def _ps_argumanlari(ps_komutu):
    return ["-NoProfile", "-NonInteractive",
            "-EncodedCommand", _kodlanmis(ps_komutu)]


def _hata_sarmala(ps_komutu):
    """Komutu try/catch ile sar: hata kisa 'HATA: ...' satiri olur.

    Yonlendirilmis stderr PowerShell'de CLIXML ham metin uretir,
    bu yuzden hata stdout uzerinden duz metinle tasinir.
    """
    return ("try { " + ps_komutu + " } catch { "
            "Write-Output ('HATA: ' + $_.Exception.Message); exit 1 }")


def _kisa_hata(metin, ust_sinir=300):
    tek = " ".join((metin or "").split())
    if len(tek) > ust_sinir:
        return tek[:ust_sinir] + "..."
    return tek or "bilinmeyen hata"


def _hata_satiri(cikti):
    for satir in (cikti or "").splitlines():
        if satir.startswith("HATA:"):
            return _kisa_hata(satir[5:].strip())
    return ""


def _ps_calistir(ps_komutu, zaman_asimi=30):
    """Yonetici olarak zaten calisiyorsa dogrudan calistir."""
    try:
        islem = subprocess.run(
            ["powershell"] + _ps_argumanlari(_hata_sarmala(ps_komutu)),
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=zaman_asimi)
    except FileNotFoundError:
        return False, "", "powershell bulunamadi"
    except subprocess.TimeoutExpired:
        return False, "", "komut zaman asimina ugradi"
    cikti = (islem.stdout or "").strip()
    if islem.returncode != 0:
        return False, cikti, _hata_satiri(cikti) or \
            f"cikis kodu {islem.returncode}"
    return True, cikti, ""


def _yukseltilmis_calistir(ps_komutu):
    """UAC ile yukselt, -Wait -PassThru ile bekle, sonucu dondur.

    Dis katmanda tirnak kullanilmaz: ic komut base64 oldugundan
    tek tirnakli dizi oge olarak guvenle gecilir. Yukseltilmis
    cocugun stdout'u yakalanamadigindan sonuc gecici dosyayla
    tasinir; pencere gizlenir (UAC sorusu yine cikar).
    Donus: (basarili, ileti). Basarida ileti komutun ciktisidir.
    """
    import tempfile
    tanitim, sonuc_yolu = tempfile.mkstemp(prefix="dnsdoktoru-",
                                           suffix=".txt")
    os.close(tanitim)
    yol_ps = sonuc_yolu.replace("'", "''")
    govde = ("$dosya = '" + yol_ps + "'; try { $cikti = @(" + ps_komutu +
             "); ($cikti -join [Environment]::NewLine) | "
             "Set-Content -LiteralPath $dosya -Encoding utf8; exit 0 } "
             "catch { ('HATA: ' + $_.Exception.Message) | "
             "Set-Content -LiteralPath $dosya -Encoding utf8; exit 1 }")
    kod = _kodlanmis(govde)
    ic = ("Start-Process -FilePath powershell -ArgumentList '-NoProfile',"
          "'-NonInteractive','-EncodedCommand','" + kod + "' -Verb RunAs "
          "-WindowStyle Hidden -Wait -PassThru | "
          "Select-Object -ExpandProperty ExitCode")
    try:
        islem = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive",
             "-Command", ic],
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=120)
    except FileNotFoundError:
        return False, "powershell bulunamadi"
    except subprocess.TimeoutExpired:
        return False, "yukseltilmis komut zaman asimina ugradi"
    try:
        with open(sonuc_yolu, encoding="utf-8") as dosya:
            sonuc = dosya.read().strip()
    except OSError:
        sonuc = ""
    finally:
        try:
            os.remove(sonuc_yolu)
        except OSError:
            pass
    cikti = (islem.stdout or "").strip()
    if islem.returncode != 0:
        # Kullanici UAC'yi reddetti ya da baslatma basarisiz.
        return False, "UAC reddedildi ya da baslatilamadi"
    try:
        kod_sonuc = int(cikti.split()[-1])
    except (ValueError, IndexError):
        return False, "yukseltilmis komutun cikis kodu okunamadi"
    if kod_sonuc != 0:
        return False, _hata_satiri(sonuc) or \
            f"komut cikis kodu {kod_sonuc}"
    return True, sonuc


def _takma_ad(ps_komutu_takma):
    return ps_komutu_takma.replace("'", "''")


def aktif_adaptorler():
    """Acik ag adaptorlerinin takma adlarini dondur: (liste, hata)."""
    if not windows_mu():
        return [], "yalnizca Windows desteklenir"
    ps = ("Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | "
          "Select-Object -ExpandProperty Name")
    ok, cikti, hata = _ps_calistir(ps)
    if not ok:
        return [], hata or "adaptor listesi alinamadi"
    adlar = [s.strip() for s in cikti.splitlines() if s.strip()]
    return adlar, ""


def doh_destegi_var():
    ps = ("if (Get-Command Add-DnsClientDohServerAddress "
          "-ErrorAction SilentlyContinue) { 'VAR' } else { 'YOK' }")
    ok, cikti, _hata = _ps_calistir(ps)
    return ok and cikti.strip() == "VAR"


def mevcut_dns(takma_ad):
    ps = ("(Get-DnsClientServerAddress -InterfaceAlias '" +
          _takma_ad(takma_ad) + "' -AddressFamily IPv4 | "
          "Select-Object -ExpandProperty ServerAddresses) -join ','")
    ok, cikti, hata = _ps_calistir(ps)
    if not ok:
        return [], hata or "mevcut DNS alinamadi"
    return [s for s in cikti.split(",") if s], ""


def onceki_kaydet(takma_ad, sunucular):
    yol = onceki_yolu()
    try:
        os.makedirs(os.path.dirname(yol), exist_ok=True)
        with open(yol, "w", encoding="utf-8") as dosya:
            json.dump({"takma_ad": takma_ad,
                       "sunucular": sunucular}, dosya)
        return True, ""
    except OSError as exc:
        return False, str(exc)


def onceki_yukle():
    try:
        with open(onceki_yolu(), encoding="utf-8") as dosya:
            return json.load(dosya), ""
    except (OSError, ValueError) as exc:
        return {}, str(exc)


def uygula_komutu(takma_ad):
    """Uygulama PowerShell komutunu kur (saf fonksiyon).

    Add-DnsClientDohServerAddress -ServerAddress tek adres alir,
    dizi verilirse donusum hatasi verir; bu yuzden iki ayri cagri.
    """
    doh_ekle = "; ".join(
        "Add-DnsClientDohServerAddress -ServerAddress " + adres +
        " -DohTemplate " + DOH_SABLON +
        " -AllowFallbackToUdp $false -AutoUpgrade $true"
        for adres in (DNS_BIRINCIL, DNS_IKINCIL))
    return ("$ErrorActionPreference = 'Stop'; "
            "Set-DnsClientServerAddress -InterfaceAlias '" +
            _takma_ad(takma_ad) + "' -ServerAddresses " +
            DNS_BIRINCIL + "," + DNS_IKINCIL + "; "
            "if (Get-Command Add-DnsClientDohServerAddress "
            "-ErrorAction SilentlyContinue) { " +
            doh_ekle + "; 'DOH-TAMAM' } else { 'DOH-YOK' }")


def geri_al_komutu(takma_ad, sunucular):
    """Geri alma PowerShell komutunu kur (saf fonksiyon)."""
    if sunucular:
        dns_ifade = "-ServerAddresses " + ",".join(sunucular)
    else:
        dns_ifade = "-ResetServerAddresses"
    return ("$ErrorActionPreference = 'Stop'; "
            "Set-DnsClientServerAddress -InterfaceAlias '" +
            _takma_ad(takma_ad) + "' " + dns_ifade + "; "
            "Remove-DnsClientDohServerAddress -ServerAddress " +
            DNS_BIRINCIL + " -ErrorAction SilentlyContinue; "
            "Remove-DnsClientDohServerAddress -ServerAddress " +
            DNS_IKINCIL + " -ErrorAction SilentlyContinue; 'GERI-TAMAM'")


def uygula(takma_ad):
    """DNS'i Cloudflare + DoH yap. Donus: (basarili, ileti)."""
    if not windows_mu():
        return False, "yalnizca Windows desteklenir"
    if not takma_ad:
        return False, "ag adaptoru secilmedi"
    sunucular, hata = mevcut_dns(takma_ad)
    if hata:
        return False, f"mevcut ayar okunamadi: {hata}"
    ok, hata = onceki_kaydet(takma_ad, sunucular)
    if not ok:
        return False, f"onceki ayar kaydedilemedi: {hata}"
    ps = uygula_komutu(takma_ad)
    if yonetici_mi():
        ok, cikti, hata = _ps_calistir(ps, zaman_asimi=60)
        if not ok:
            return False, f"uygulanamadi: {hata}"
    else:
        ok, cikti = _yukseltilmis_calistir(ps)
        if not ok:
            return False, f"uygulanamadi: {cikti}"
    if "DOH-YOK" in cikti:
        return True, "DNS ayarlandi, DoH destegi yok (eski Windows)"
    return True, "DNS + DoH ayarlandi (1.1.1.1)"


def geri_al():
    """Kaydedilmis onceki DNS ayarini geri yukle."""
    if not windows_mu():
        return False, "yalnizca Windows desteklenir"
    kayit, hata = onceki_yukle()
    if not kayit or not kayit.get("takma_ad"):
        return False, ("onceki ayar bulunamadi, "
                       "Windows ayarlarindan sifirlayin")
    takma_ad = kayit["takma_ad"]
    sunucular = kayit.get("sunucular") or []
    ps = geri_al_komutu(takma_ad, sunucular)
    if yonetici_mi():
        ok, _cikti, hata = _ps_calistir(ps, zaman_asimi=60)
        if not ok:
            return False, f"geri alinamadi: {hata}"
    else:
        ok, hata = _yukseltilmis_calistir(ps)
        if not ok:
            return False, f"geri alinamadi: {hata}"
    return True, "onceki DNS ayarlari geri yuklendi"
