"""DNS Doktoru - sistem DNS'i ile DoH sonucunu karsilastiran yardimci.

Ag paketlerine dokunmaz, surucu kullanmaz. DNS degisikligi yalnizca
kullanici dugmeye basinca ve UAC onayi ile yapilir.
"""
import os
import queue
import sys
import threading
import tkinter as tk
from tkinter import ttk, messagebox

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import dns_check
import win_dns

# TR/EN sozlugu: anahtar -> (tr, en)
STR = {
    "title": ("DNS Doktoru", "DNS Doctor"),
    "hosts": ("Kontrol edilecek hostlar (satir basina bir tane):",
              "Hosts to check (one per line):"),
    "check": ("Kontrol et", "Check"),
    "checking": ("Kontrol ediliyor...", "Checking..."),
    "done": ("Bitti.", "Done."),
    "apply": ("DoH'u uygula (1.1.1.1)", "Apply DoH (1.1.1.1)"),
    "revert": ("Onceki ayara don", "Restore previous"),
    "copy": ("Sonucu kopyala", "Copy result"),
    "lang": ("Dil / Language:", "Dil / Language:"),
    "adapter": ("Ag adaptoru:", "Network adapter:"),
    "no_adapter": ("(adaptor bulunamadi)", "(no adapter found)"),
    "col_host": ("Host", "Host"),
    "col_sys": ("Sistem DNS", "System DNS"),
    "col_doh": ("DoH (Cloudflare)", "DoH (Cloudflare)"),
    "col_state": ("Durum", "Status"),
    "copied": ("Sonuclar panoya kopyalandi.", "Results copied."),
    "no_result": ("Kopyalanacak sonuc yok.", "Nothing to copy."),
    "admin_note": ("DNS degisikligi yonetici ister, UAC sorar.",
                   "Changing DNS needs admin, UAC will ask."),
    "confirm_apply": ("aktif adaptorun DNS'i 1.1.1.1 olacak. Devam?",
                      "will set the active adapter DNS to 1.1.1.1. Continue?"),
    "confirm_title": ("Onay", "Confirm"),
    "ok_title": ("Tamam", "Done"),
    "err_title": ("Hata", "Error"),
    "status_ok": ("TAMAM", "OK"),
    "status_block": ("ENGELLI/ZEHIRLI olabilir", "BLOCKED/POISONED?"),
    "status_fail": ("COZULEMEDI", "UNRESOLVED"),
    "footer": ("Surucusuz, pakete dokunmaz.", "Driverless, touches no packets."),
}

DURUM_CEVIRI = {
    dns_check.DURUM_TAMAM: "status_ok",
    dns_check.DURUM_ENGELLI: "status_block",
    dns_check.DURUM_COZULEMEDI: "status_fail",
}


def taban_dizin():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def varsayilan_hostlar():
    yol = os.path.join(taban_dizin(), "hosts.txt")
    try:
        with open(yol, encoding="utf-8") as dosya:
            return [s.strip() for s in dosya if s.strip()]
    except OSError:
        return ["discord.com", "www.roblox.com"]


class App:
    def __init__(self, kok):
        self.kok = kok
        self.dil = "tr"
        self.sonuclar = []
        self.kuyruk = queue.Queue()
        kok.geometry("640x560")
        kok.minsize(560, 480)

        self.dil_deg = tk.StringVar(value="tr")
        self.adap_deg = tk.StringVar()

        ust = ttk.Frame(kok, padding=8)
        ust.pack(fill="x")
        self.lbl_dil = ttk.Label(ust)
        self.lbl_dil.pack(side="left")
        ttk.Radiobutton(ust, text="TR", variable=self.dil_deg,
                        value="tr", command=self.dili_degistir).pack(side="left")
        ttk.Radiobutton(ust, text="EN", variable=self.dil_deg,
                        value="en", command=self.dili_degistir).pack(side="left")
        self.lbl_adap = ttk.Label(ust)
        self.lbl_adap.pack(side="left", padx=(16, 4))
        self.adap_kutu = ttk.Combobox(ust, textvariable=self.adap_deg,
                                      state="readonly", width=22)
        self.adap_kutu.pack(side="left")
        self.adap_doldur()

        self.lbl_hosts = ttk.Label(kok, padding=(8, 0))
        self.lbl_hosts.pack(anchor="w")
        self.host_kutu = tk.Text(kok, height=6)
        self.host_kutu.pack(fill="x", padx=8)
        self.host_kutu.insert("1.0", "\n".join(varsayilan_hostlar()))

        dugme = ttk.Frame(kok, padding=8)
        dugme.pack(fill="x")
        self.btn_kontrol = ttk.Button(dugme, command=self.kontrol_baslat)
        self.btn_kontrol.pack(side="left")
        self.btn_uygula = ttk.Button(dugme, command=self.doh_uygula)
        self.btn_uygula.pack(side="left", padx=6)
        self.btn_geri = ttk.Button(dugme, command=self.geri_al)
        self.btn_geri.pack(side="left")
        self.btn_kopya = ttk.Button(dugme, command=self.kopyala)
        self.btn_kopya.pack(side="right")

        kolonlar = ("host", "sis", "doh", "durum")
        self.tablo = ttk.Treeview(kok, columns=kolonlar, show="headings",
                                  height=10)
        for k in kolonlar:
            self.tablo.heading(k, text=k)
            self.tablo.column(k, width=140 if k != "host" else 170)
        self.tablo.pack(fill="both", expand=True, padx=8)
        self.tablo.tag_configure("ok", foreground="#16A34A")
        self.tablo.tag_configure("kot", foreground="#DC2626")
        self.tablo.tag_configure("bos", foreground="#6B7280")

        alt = ttk.Frame(kok, padding=8)
        alt.pack(fill="x")
        self.lbl_durum = ttk.Label(alt)
        self.lbl_durum.pack(side="left")
        ttk.Label(alt, text=self.t("footer")).pack(side="right")

        self.kok.after(100, self.kuyrugu_isle)
        self.metni_yenile()

    def t(self, anahtar):
        tr, en = STR[anahtar]
        return tr if self.dil == "tr" else en

    def dili_degistir(self):
        self.dil = self.dil_deg.get()
        self.metni_yenile()

    def metni_yenile(self):
        self.kok.title(self.t("title"))
        self.lbl_dil.config(text=self.t("lang"))
        self.lbl_adap.config(text=self.t("adapter"))
        self.lbl_hosts.config(text=self.t("hosts"))
        self.btn_kontrol.config(text=self.t("check"))
        self.btn_uygula.config(text=self.t("apply"))
        self.btn_geri.config(text=self.t("revert"))
        self.btn_kopya.config(text=self.t("copy"))
        self.tablo.heading("host", text=self.t("col_host"))
        self.tablo.heading("sis", text=self.t("col_sys"))
        self.tablo.heading("doh", text=self.t("col_doh"))
        self.tablo.heading("durum", text=self.t("col_state"))
        if not self.sonuclar:
            self.lbl_durum.config(text=self.t("admin_note"))

    def adap_doldur(self):
        adlar, _hata = win_dns.aktif_adaptorler()
        if adlar:
            self.adap_kutu["values"] = adlar
            self.adap_deg.set(adlar[0])
        else:
            self.adap_kutu["values"] = [self.t("no_adapter")]

    def hostlari_al(self):
        metin = self.host_kutu.get("1.0", "end")
        return [s.strip() for s in metin.split() if s.strip()]

    def kontrol_baslat(self):
        hostlar = self.hostlari_al()
        if not hostlar:
            return
        self.btn_kontrol.config(state="disabled")
        self.lbl_durum.config(text=self.t("checking"))
        for satir in self.tablo.get_children():
            self.tablo.delete(satir)
        self.sonuclar = []
        is_parcasi = threading.Thread(target=self.arka_kontrol,
                                      args=(hostlar,), daemon=True)
        is_parcasi.start()

    def arka_kontrol(self, hostlar):
        for host in hostlar:
            sis, sis_hata = dns_check.cozum_sistem(host)
            doh, doh_hata = dns_check.cozum_doh(host)
            durum = dns_check.sinifla(sis, doh, sis_hata, doh_hata)
            self.kuyruk.put((host, sis, doh, durum))
        self.kuyruk.put(None)

    def kuyrugu_isle(self):
        try:
            while True:
                oge = self.kuyruk.get_nowait()
                if oge is None:
                    self.btn_kontrol.config(state="normal")
                    self.lbl_durum.config(text=self.t("done"))
                    self.metni_tazele_tablo()
                    continue
                host, sis, doh, durum = oge
                self.sonuclar.append(oge)
                etiket = ("ok" if durum == dns_check.DURUM_TAMAM
                          else "kot" if durum == dns_check.DURUM_ENGELLI
                          else "bos")
                self.tablo.insert("", "end", values=(
                    host, ",".join(sis) or "-",
                    ",".join(doh) or "-",
                    self.t(DURUM_CEVIRI[durum])), tags=(etiket,))
        except queue.Empty:
            pass
        self.kok.after(100, self.kuyrugu_isle)

    def metni_tazele_tablo(self):
        for satir in self.tablo.get_children():
            onceki = self.tablo.item(satir, "values")
            for host, sis, doh, durum in self.sonuclar:
                if onceki and onceki[0] == host:
                    self.tablo.item(satir, values=(
                        host, ",".join(sis) or "-", ",".join(doh) or "-",
                        self.t(DURUM_CEVIRI[durum])))

    def doh_uygula(self):
        ad = self.adap_deg.get()
        if not ad or not messagebox.askyesno(
                self.t("confirm_title"),
                ad + " " + self.t("confirm_apply") + "\n" +
                self.t("admin_note")):
            return
        ok, ileti = win_dns.uygula(ad)
        if ok:
            messagebox.showinfo(self.t("ok_title"), ileti)
        else:
            messagebox.showerror(self.t("err_title"), ileti)

    def geri_al(self):
        ok, ileti = win_dns.geri_al()
        if ok:
            messagebox.showinfo(self.t("ok_title"), ileti)
        else:
            messagebox.showerror(self.t("err_title"), ileti)

    def kopyala(self):
        if not self.sonuclar:
            messagebox.showinfo(self.t("ok_title"), self.t("no_result"))
            return
        satirlar = [dns_check.sonuc_metni(h, s, d, u)
                    for h, s, d, u in self.sonuclar]
        self.kok.clipboard_clear()
        self.kok.clipboard_append("\n".join(satirlar))
        self.lbl_durum.config(text=self.t("copied"))


def main():
    kok = tk.Tk()
    App(kok)
    kok.mainloop()


if __name__ == "__main__":
    main()
