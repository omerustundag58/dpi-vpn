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


def _ps_calistir(ps_komutu, zaman_asimi=30):
    """Yonetici olarak zaten calisiyorsa dogrudan calistir."""
    try:
        islem = subprocess.run(
            ["powershell"] + _ps_argumanlari(ps_komutu),
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=zaman_asimi)
    except FileNotFoundError:
        return False, "", "powershell bulunamadi"
    except subprocess.TimeoutExpired:
        return False, "", "komut zaman asimina ugradi"
    if islem.returncode != 0:
        return False, islem.stdout.strip(), islem.stderr.strip() or \
            f"cikis kodu {islem.returncode}"
    return True, islem.stdout.strip(), ""


def _yukseltilmis_calistir(ps_komutu):
    """UAC ile yukselt, -Wait -PassThru ile bekle, cikis kodunu dondur.

    Dis katmanda tirnak kullanilmaz: ic komut base64 oldugundan
    tek tirnakli dizi oge olarak guvenle gecilir.
    """
    kod = _kodlanmis(ps_komutu)
    ic = ("Start-Process -FilePath powershell -ArgumentList '-NoProfile',"
          "'-NonInteractive','-EncodedCommand','" + kod + "' -Verb RunAs "
          "-Wait -PassThru | Select-Object -ExpandProperty ExitCode")
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
    cikti = (islem.stdout or "").strip()
    if islem.returncode != 0:
        # Kullanici UAC'yi reddetti ya da baslatma basarisiz.
        hata = (islem.stderr or "").strip().splitlines()
        son = hata[-1] if hata else "UAC reddedildi ya da baslatilamadi"
        return False, son
    try:
        kod_sonuc = int(cikti.split()[-1])
    except (ValueError, IndexError):
        return False, "yukseltilmis komutun cikis kodu okunamadi"
    if kod_sonuc != 0:
        return False, f"komut cikis kodu {kod_sonuc}"
    return True, ""


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
    ps = ("$ErrorActionPreference = 'Stop'; "
          "Set-DnsClientServerAddress -InterfaceAlias '" +
          _takma_ad(takma_ad) + "' -ServerAddresses " +
          DNS_BIRINCIL + "," + DNS_IKINCIL + "; "
          "if (Get-Command Add-DnsClientDohServerAddress "
          "-ErrorAction SilentlyContinue) { "
          "Add-DnsClientDohServerAddress -ServerAddress " +
          DNS_BIRINCIL + "," + DNS_IKINCIL +
          " -DohTemplate " + DOH_SABLON +
          " -AllowFallbackToUdp $false -AutoUpgrade $true; 'DOH-TAMAM' } "
          "else { 'DOH-YOK' }")
    if yonetici_mi():
        ok, cikti, hata = _ps_calistir(ps, zaman_asimi=60)
        if not ok:
            return False, f"uygulanamadi: {hata}"
    else:
        ok, hata = _yukseltilmis_calistir(ps)
        if not ok:
            return False, f"uygulanamadi: {hata}"
        cikti = ""
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
    if sunucular:
        dns_ifade = "-ServerAddresses " + ",".join(sunucular)
    else:
        dns_ifade = "-ResetServerAddresses"
    ps = ("$ErrorActionPreference = 'Stop'; "
          "Set-DnsClientServerAddress -InterfaceAlias '" +
          _takma_ad(takma_ad) + "' " + dns_ifade + "; "
          "Remove-DnsClientDohServerAddress -ServerAddress " +
          DNS_BIRINCIL + " -ErrorAction SilentlyContinue; "
          "Remove-DnsClientDohServerAddress -ServerAddress " +
          DNS_IKINCIL + " -ErrorAction SilentlyContinue")
    if yonetici_mi():
        ok, _cikti, hata = _ps_calistir(ps, zaman_asimi=60)
        if not ok:
            return False, f"geri alinamadi: {hata}"
    else:
        ok, hata = _yukseltilmis_calistir(ps)
        if not ok:
            return False, f"geri alinamadi: {hata}"
    return True, "onceki DNS ayarlari geri yuklendi"
