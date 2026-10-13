# SPDX-License-Identifier: GPL-3.0-or-later
# DPI VPN Türkiye — modern arayüz (tkinter).
# Özellikler: ISP profili, Hızlı/Dengeli/Parçala, gecikme, canlı log, hız testi,
# ISS analizi, LAN paylaşımı, sistem proxy'si, DNS modu, TR/EN dil,
# Rust Proxy + WinDivert motorları, tepsi simgesi, tema (açık/koyu/sistem).
import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import ttk, messagebox

try:
    import winreg
except ImportError:
    winreg = None

try:
    import pystray
    from PIL import Image, ImageDraw
    HAVE_TRAY = True
except ImportError:
    HAVE_TRAY = False

APP_TITLE = "DPI VPN v0.3"
DNS_PRIMARY = "1.1.1.1"
DNS_SECONDARY = "1.0.0.1"
DNS6_PRIMARY = "2606:4700:4700::1111"
DNS6_SECONDARY = "2606:4700:4700::1001"
IE_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"

THEMES = {
    "acik": {"BG": "#E8EDF3", "CARD": "#FFFFFF", "INK": "#1F2937",
             "MUTED": "#6B7280", "BORDER": "#D5DDE8", "TROUGH": "#D7E0EC"},
    "koyu": {"BG": "#0F172A", "CARD": "#1E293B", "INK": "#F1F5F9",
             "MUTED": "#94A3B8", "BORDER": "#334155", "TROUGH": "#475569"},
}
GREEN = "#16A34A"
RED = "#DC2626"
ACCENT = "#2563EB"
LOG_BG = "#0B1220"
LOG_FG = "#C9D4E3"

# TR/EN sözlüğü: anahtar -> (tr, en)
STR = {
    "ready": ("SİSTEM HAZIR", "SYSTEM READY"),
    "running": ("ÇALIŞIYOR", "RUNNING"),
    "died": ("PROXY ÖLDÜ", "PROXY DIED"),
    "start": ("▶  BAŞLAT", "▶  START"),
    "stop": ("⏹  DURDUR", "⏹  STOP"),
    "profile": ("Profil (ISS):", "Profile (ISP):"),
    "mode": ("Mod:", "Mode:"),
    "delay": ("Gecikme:", "Delay:"),
    "live_log": ("Canlı log", "Live log"),
    "analyze": ("ISS Analizi Yap", "Run ISP check"),
    "lan_on": ("LAN Paylaşım: açık", "LAN share: on"),
    "lan_off": ("LAN Paylaşım: kapalı", "LAN share: off"),
    "bench": ("Hız Testi", "Speed test"),
    "syspx_on": ("Sistem Proxy: AÇIK", "System proxy: ON"),
    "syspx_off": ("Sistem Proxy: kapalı", "System proxy: off"),
    "dns_on": ("DNS Modu: AÇIK  (1.1.1.1)", "DNS mode: ON  (1.1.1.1)"),
    "dns_off": ("DNS Modu: kapalı  (1.1.1.1)", "DNS mode: off  (1.1.1.1)"),
    "quic_on": ("QUIC Engelle: AÇIK (UDP 443)", "Block QUIC: ON (UDP 443)"),
    "quic_off": ("QUIC Engelle: kapalı", "Block QUIC: off"),
    "settings": ("⚙ Ayarlar", "⚙ Settings"),
    "settings_title": ("Ayarlar", "Settings"),
    "theme": ("Tema", "Theme"),
    "light": ("Açık mod", "Light"),
    "dark": ("Koyu mod", "Dark"),
    "system": ("Sistem varsayılanı", "System default"),
    "behavior": ("Davranış", "Behavior"),
    "to_tray": ("Kapatınca tepsiye al", "Minimize to tray on close"),
    "auto_off": ("Durdurunca sistem proxy'sini kapat", "Turn off system proxy on stop"),
    "close": ("Kapat", "Close"),
    "lang": ("Dil", "Language"),
    "engine": ("Motor", "Engine"),
    "eng_rust": ("Rust Proxy (sürücüsüz)", "Rust proxy (driverless)"),
    "eng_winws": ("WinDivert (sürücülü, admin)", "WinDivert (driver, admin)"),
    "mode_fast": ("Hızlı (gecikmesiz)", "Fast (no delay)"),
    "mode_bal": ("Dengeli (böl+gecikme)", "Balanced (split+delay)"),
    "mode_frag": ("Parçala (fragment)", "Fragment"),
    "mode_rev": ("Ters (önce+kuyruk)", "Reversed (before+tail)"),
    "mode_auto": ("Otomatik (seçer)", "Automatic (picks)"),
    "already": ("Program zaten çalışıyor.", "Already running."),
    "no_proxy": ("Derlenmiş proxy yok:", "Proxy binary missing:"),
    "cant_start": ("Başlatılamadı", "Could not start"),
    "need_admin": ("WinDivert admin ister. Yönetici olarak çalıştırın.",
                   "WinDivert needs admin. Run as administrator."),
    "no_winws": ("winws2.exe bulunamadı:", "winws2.exe not found:"),
    "footer": ("DPI VPN v0.3  •  Rust çekirdek", "DPI VPN v0.3  •  Rust core"),
    "tray_show": ("Göster", "Show"),
    "tray_toggle": ("BAŞLAT/DURDUR", "START/STOP"),
    "tray_exit": ("Çıkış", "Exit"),
    "an_clean": ("DNS temiz.", "DNS is clean."),
    "an_poison": ("DNS ZEHİRLİ (195.175.254.2).", "DNS POISONED (195.175.254.2)."),
    "an_vague": ("Belirsiz:", "Unclear:"),
    "an_title": ("Analiz", "Check"),
    "tip_profile": ("ISS'ne göre hazır ayar.", "Preset for your ISP."),
    "tip_mode": ("Hızlı en çabuk. Dengeli çoğu sitede. Parçala inatçı sitede. Ters en agresif. Otomatik kendisi seçer.",
                 "Fast is quickest. Balanced fits most. Fragment for stubborn ones. Reversed is most aggressive. Automatic picks itself."),
    "tip_delay": ("İki parça arası bekleme (ms). 0 en hızlı.",
                  "Wait between parts (ms). 0 is fastest."),
    "tip_theme": ("Açık, koyu ya da Windows'a uyar.", "Light, dark, or follow Windows."),
    "tip_tray": ("Kapatınca program tepside çalışır.", "App keeps running in tray on close."),
    "tip_off": ("Durdurunca internet ayarın eskiye döner.", "Restores internet settings on stop."),
    "tip_engine": ("Rust sürücüsüz çalışır. WinDivert tüm trafiği yakalar (admin).",
                   "Rust needs no driver. WinDivert catches all traffic (admin)."),
}


def base_dir():
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return sys._MEIPASS
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


BASE = base_dir()
PROXY_EXE = os.path.join(BASE, "dpi-proxy.exe")
if not os.path.exists(PROXY_EXE):
    _dev = os.path.join(BASE, "target", "debug", "dpi-proxy.exe")
    if os.path.exists(_dev):
        PROXY_EXE = _dev
BACKUP_CANDIDATES = [
    os.path.join(BASE, "vendor", "zapret-win-turkey-backup"),
    os.path.join(os.path.dirname(sys.executable), "zapret-win-turkey-backup") if getattr(sys, "frozen", False) else None,
    os.path.join(os.path.expanduser("~"), "Downloads", "zapret-win-turkey"),
]


def find_backup():
    for c in BACKUP_CANDIDATES:
        if c and os.path.isdir(c):
            return c
    return None


BACKUP = find_backup()
WINWS_DIR = os.path.join(BACKUP, "bin", "zapret", "zapret-winws") if BACKUP else ""
WINWS2 = os.path.join(WINWS_DIR, "winws2.exe") if BACKUP else ""
LUA = os.path.join(WINWS_DIR, "lua") if BACKUP else ""
HOSTLIST_AUTO = os.path.join(BACKUP, "config", "autohostlist.txt") if BACKUP else ""
EXCLUDELIST = os.path.join(BACKUP, "config", "excludelist.txt") if BACKUP else ""

PROFILES = ["Türk Telekom", "TT Alternatif", "Superonline", "SOL Alternatif",
            "Vodafone", "Turkcell Mobil", "Vodafone Mobil", "Telekom Mobil"]
PROFILE_DELAY = {"Türk Telekom": 4, "TT Alternatif": 3, "Superonline": 5,
                 "SOL Alternatif": 3, "Vodafone": 0, "Turkcell Mobil": 1,
                 "Vodafone Mobil": 0, "Telekom Mobil": 5}
ENGINES = ["rust", "winws"]

# au3 _GetActiveStrategyString Zapret2 kolonu birebir
WINWS2_ARGS = {
    "Türk Telekom": "--payload=tls_client_hello --lua-desync=multidisorder:pos=2:seqovl=1",
    "TT Alternatif": "--payload=tls_client_hello --lua-desync=multidisorder:pos=2:seqovl=1",
    "Superonline": "--payload=tls_client_hello --lua-desync=multidisorder:pos=2:seqovl=1",
    "SOL Alternatif": "--payload=tls_client_hello --lua-desync=multidisorder:pos=2:seqovl=1",
    "Vodafone": "--payload=tls_client_hello --lua-desync=multisplit:blob=fake_default_tls:ip_ttl=5:pos=2:nodrop:repeats=1",
    "Turkcell Mobil": "--payload=tls_client_hello --lua-desync=multidisorder:pos=2:seqovl=1",
    "Vodafone Mobil": "--payload=tls_client_hello --lua-desync=multidisorder:pos=2:seqovl=1",
    "Telekom Mobil": "--payload=tls_client_hello --lua-desync=fake:blob=0x00000000:ip_ttl=5:repeats=1",
}

NO_WINDOW = 0x08000000 if os.name == "nt" else 0


def config_path():
    if os.environ.get("DPIVPN_CONFIG"):
        return os.environ["DPIVPN_CONFIG"]
    base = os.environ.get("APPDATA") or os.path.expanduser("~")
    d = os.path.join(base, "DPIVPN")
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, "config.json")


def load_config():
    import json
    try:
        with open(config_path(), encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_config(cfg):
    import json
    try:
        with open(config_path(), "w", encoding="utf-8") as f:
            json.dump(cfg, f)
    except Exception:
        pass


def system_theme():
    if winreg is None:
        return "acik"
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
                            0, winreg.KEY_READ) as k:
            v, _ = winreg.QueryValueEx(k, "AppsUseLightTheme")
            return "acik" if v else "koyu"
    except Exception:
        return "acik"


def is_admin():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


class Tooltip:
    """Mavi ? etiketi: üstüne gelince basit açıklama gösterir."""
    def __init__(self, parent, x, y, text_fn):
        self.text_fn = text_fn
        self.tip = None
        self.lbl = tk.Label(parent, text="?", fg=ACCENT, cursor="question_arrow",
                            font=("Segoe UI", 8, "bold"))
        self.lbl.place(x=x, y=y)
        self.lbl.bind("<Enter>", self.show)
        self.lbl.bind("<Leave>", self.hide)

    def show(self, _event=None):
        if self.tip:
            return
        try:
            self.lbl.configure(bg=self.lbl.master.cget("bg"))
        except tk.TclError:
            pass
        x = self.lbl.winfo_rootx() + 16
        y = self.lbl.winfo_rooty() + 16
        self.tip = tk.Toplevel(self.lbl)
        self.tip.wm_overrideredirect(True)
        self.tip.wm_geometry(f"+{x}+{y}")
        tk.Label(self.tip, text=self.text_fn(), bg="#1F2937", fg="white",
                 font=("Segoe UI", 8), padx=8, pady=5, wraplength=220,
                 justify="left").pack()

    def hide(self, _event=None):
        if self.tip:
            self.tip.destroy()
            self.tip = None


class App:
    def __init__(self, root):
        self.root = root
        self.cfg = load_config()
        self.lang = self.cfg.get("dil", "tr")
        self.theme_name = self.cfg.get("tema", "sistem")
        self.engine = self.cfg.get("motor", "rust")
        self.close_to_tray = self.cfg.get("tepsiye_kapat", True)
        self.auto_off_sysproxy = self.cfg.get("durunca_proxy_kapat", True)
        self.T = THEMES["acik"]
        root.title(APP_TITLE)
        root.geometry("410x700")
        root.resizable(False, False)

        self.style = ttk.Style(root)
        try:
            self.style.theme_use("clam")
        except tk.TclError:
            pass

        self.proc = None
        self.logq = queue.Queue()
        self.lan_share = False
        self.sys_proxy = False
        self.dns_mode = False
        self.quic_block = False
        self.saved_proxy = {}
        self.saved_dns = {}
        self.row_labels = []
        self.menu_btns = []

        # durum kartı
        self.card = tk.Frame(root, highlightthickness=1, bd=0)
        self.card.place(x=15, y=12, width=380, height=78)
        self.dot = tk.Canvas(self.card, width=14, height=14,
                             highlightthickness=0, bd=0)
        self.dot.place(x=16, y=16)
        self._dot_color(RED)
        self.lbl_status = tk.Label(self.card, font=("Segoe UI", 12, "bold"))
        self.lbl_status.place(x=38, y=10)
        self.lbl_info = tk.Label(self.card, font=("Segoe UI", 9))
        self.lbl_info.place(x=38, y=40)

        # büyük buton
        self.btn_run = tk.Button(root, font=("Segoe UI", 13, "bold"),
                                 bg=GREEN, fg="white", activebackground="#15803D",
                                 activeforeground="white", relief="flat", bd=0,
                                 cursor="hand2", command=self.toggle)
        self.btn_run.place(x=15, y=100, width=380, height=52)

        # ayar kartı
        self.box = tk.Frame(root, highlightthickness=1, bd=0)
        self.box.place(x=15, y=162, width=380, height=128)
        self._row(self.box, "profile", 12)
        Tooltip(self.box, 158, 11, lambda: self.S("tip_profile"))
        self.cmb_profile = ttk.Combobox(self.box, values=PROFILES, state="readonly", width=22)
        self.cmb_profile.place(x=180, y=10, width=185)
        self.cmb_profile.set(self.cfg.get("profil", PROFILES[0]))
        self.cmb_profile.bind("<<ComboboxSelected>>", self.on_profile)
        self._row(self.box, "mode", 48)
        Tooltip(self.box, 158, 47, lambda: self.S("tip_mode"))
        self.cmb_mode = ttk.Combobox(self.box, state="readonly", width=22)
        self.cmb_mode.place(x=180, y=46, width=185)
        self.cmb_mode.set(self.cfg.get("mod", self.S("mode_bal")))
        self.cmb_mode.bind("<<ComboboxSelected>>", self.on_mode)
        self._row(self.box, "delay", 84)
        Tooltip(self.box, 158, 83, lambda: self.S("tip_delay"))
        self.delay = tk.IntVar(value=self.cfg.get("gecikme", PROFILE_DELAY.get(self.cmb_profile.get(), 4)))
        self.scl = ttk.Scale(self.box, from_=0, to=50, orient="h", variable=self.delay,
                             style="Horizontal.TScale", length=140,
                             command=lambda *_: self.lbl_ms.config(text=f"{int(float(self.scl.get()))} ms"))
        self.scl.place(x=180, y=86, width=140)
        self.lbl_ms = tk.Label(self.box, text=f"{self.delay.get()} ms",
                               font=("Segoe UI", 9), width=7)
        self.lbl_ms.place(x=322, y=84)

        # log konsolu
        self.lbl_log = tk.Label(root, font=("Segoe UI", 9, "bold"))
        self.lbl_log.place(x=15, y=296)
        self.txt = tk.Text(root, width=48, height=9, font=("Consolas", 8),
                           state="disabled", bg=LOG_BG, fg=LOG_FG, relief="flat",
                           bd=0, highlightthickness=0, insertbackground=LOG_FG,
                           selectbackground="#1E3A5F")
        self.txt.place(x=15, y=318, width=380, height=132)
        self.txt.tag_config("ok", foreground="#4ADE80")
        self.txt.tag_config("warn", foreground="#FBBF24")
        self.txt.tag_config("err", foreground="#F87171")
        self.txt.tag_config("info", foreground="#7DD3FC")
        self.root.after(200, self.pump_log)
        self.root.after(600, self._pulse)

        # butonlar
        self.mk_btn("analyze", 460, self.analyze)
        self.btn_lan = self.mk_btn("lan_off", 496, self.toggle_lan)
        self.mk_btn("bench", 532, self.bench)
        self.btn_sysproxy = self.mk_btn("syspx_off", 568, self.toggle_sysproxy)
        self.btn_dns = self.mk_btn("dns_off", 604, self.toggle_dns)
        self.btn_quic = self.mk_btn("quic_off", 640, self.toggle_quic)
        self.lbl_footer = tk.Label(root, font=("Segoe UI", 8))
        self.lbl_footer.place(x=0, y=676, width=300)
        self.btn_settings = tk.Button(root, command=self.open_settings,
                                      relief="flat", bd=0, cursor="hand2", font=("Segoe UI", 8))
        self.btn_settings.place(x=310, y=674, width=85, height=22)
        self.tray = None
        if HAVE_TRAY:
            self._tray_setup()
            root.bind("<Unmap>", self._on_minimize)
        root.protocol("WM_DELETE_WINDOW", self._on_x)
        self.quic_block = self.quic_active()
        self.apply_theme()
        self.apply_lang()
        self._refresh_info()
        self.fade_in()

    def S(self, key):
        tr, en = STR[key]
        return en if self.lang == "en" else tr

    def modes(self):
        return [self.S("mode_fast"), self.S("mode_bal"), self.S("mode_frag"), self.S("mode_rev"), self.S("mode_auto")]

    def _row(self, parent, key, y):
        lbl = tk.Label(parent, font=("Segoe UI", 9))
        lbl.place(x=14, y=y)
        self.row_labels.append((lbl, key))

    def fade_in(self):
        # ~600ms ease-out cubic belirme (16ms kareler).
        import time
        self._fade_t0 = time.time()
        self._fade_step()

    def _fade_step(self):
        import time
        try:
            t = min(1.0, (time.time() - self._fade_t0) / 0.6)
            eased = 1.0 - (1.0 - t) ** 3
            self.root.attributes("-alpha", eased)
            if t < 1.0:
                self.root.after(16, self._fade_step)
        except tk.TclError:
            pass

    def _dot_color(self, color):
        self._dot_c = color
        self._dot_r = 5
        self._draw_dot()

    def _draw_dot(self):
        try:
            self.dot.delete("all")
            r = self._dot_r
            self.dot.create_oval(7 - r, 7 - r, 7 + r, 7 + r,
                                 fill=self._dot_c, outline=self._dot_c)
        except tk.TclError:
            pass

    def _pulse(self):
        # çalışırken nokta nabız gibi büyüyüp küçülür
        try:
            active = self.proc is not None and self.proc.poll() is None
            if active:
                self._dot_r = 7 if self._dot_r <= 5 else 5
                self._draw_dot()
            elif getattr(self, "_dot_r", 5) != 5:
                self._dot_r = 5
                self._draw_dot()
        except tk.TclError:
            pass
        self.root.after(450, self._pulse)

    def mk_btn(self, key, y, cmd):
        b = tk.Button(self.root, command=cmd, relief="flat", bd=0,
                      highlightthickness=1, cursor="hand2", font=("Segoe UI", 9))
        b.place(x=15, y=y, width=380, height=30)
        # hover: üzerine gelince aydınlan, çıkınca temaya dön
        b.bind("<Enter>", lambda _e, w=b: w.configure(
            bg="#DBEAFE" if self.T is THEMES["acik"] else "#334155"))
        b.bind("<Leave>", lambda _e, w=b: w.configure(bg=self.T["CARD"]))
        self.menu_btns.append((b, key))
        return b

    def apply_theme(self):
        name = self.theme_name
        if name == "sistem":
            name = system_theme()
        self.T = THEMES[name]
        T = self.T
        self.root.configure(bg=T["BG"])
        self.style.configure("TCombobox", fieldbackground=T["CARD"], background=T["CARD"],
                             foreground=T["INK"], arrowcolor=T["MUTED"], padding=4)
        self.style.configure("Horizontal.TScale", background=T["CARD"], troughcolor=T["TROUGH"])
        for w in (self.card, self.box):
            w.configure(bg=T["CARD"], highlightbackground=T["BORDER"])
        self.dot.configure(bg=T["CARD"])
        self.lbl_status.configure(bg=T["CARD"], fg=T["INK"])
        self.lbl_info.configure(bg=T["CARD"], fg=T["MUTED"])
        self.lbl_log.configure(bg=T["BG"], fg=T["MUTED"])
        self.lbl_ms.configure(bg=T["CARD"], fg=T["MUTED"])
        self.lbl_footer.configure(bg=T["BG"], fg=T["MUTED"])
        self.btn_settings.configure(bg=T["BG"], fg=T["MUTED"], activebackground=T["CARD"])
        for lbl, _key in self.row_labels:
            lbl.configure(bg=T["CARD"], fg=T["MUTED"])
        for b, _key in self.menu_btns:
            fg = b.cget("fg")
            keep = fg if str(fg) == GREEN else T["INK"]
            b.configure(bg=T["CARD"], fg=keep, activebackground="#DBEAFE" if name == "acik" else "#1E3A5F",
                        activeforeground=ACCENT, highlightbackground=T["BORDER"])

    def apply_lang(self):
        self.lbl_status.configure(text=self.S("ready"))
        self.lbl_log.configure(text=self.S("live_log"))
        self.lbl_footer.configure(text=self.S("footer"))
        self.btn_run.configure(text=self.S("start"))
        self.btn_settings.configure(text=self.S("settings"))
        for lbl, key in self.row_labels:
            lbl.configure(text=self.S(key))
        cur = self.cmb_mode.get()
        idx = 1
        for i, m in enumerate(self.modes()):
            if cur == m:
                idx = i
        self.cmb_mode.configure(values=self.modes())
        # eski TR değeriyle kayıtlıysa eşleştir
        old = ["Hızlı (gecikmesiz)", "Dengeli (böl+gecikme)", "Parçala (fragment)"]
        if cur in old:
            idx = old.index(cur)
        self.cmb_mode.set(self.modes()[idx])
        keymap = {"analyze": None, "lan_off": None, "lan_on": None, "bench": None,
                  "syspx_off": None, "syspx_on": None, "dns_off": None, "dns_on": None,
                  "quic_off": None, "quic_on": None}
        for b, key in self.menu_btns:
            if key == "lan_off":
                b.configure(text=self.S("lan_on") if self.lan_share else self.S("lan_off"))
            elif key == "syspx_off":
                b.configure(text=self.S("syspx_on") if self.sys_proxy else self.S("syspx_off"))
            elif key == "dns_off":
                b.configure(text=self.S("dns_on") if self.dns_mode else self.S("dns_off"))
            elif key == "quic_off":
                b.configure(text=self.S("quic_on") if self.quic_block else self.S("quic_off"))
            elif key in keymap:
                b.configure(text=self.S(key))
        self._refresh_info()

    def persist(self):
        self.cfg.update({
            "dil": self.lang,
            "tema": self.theme_name,
            "motor": self.engine,
            "tepsiye_kapat": self.close_to_tray,
            "durunca_proxy_kapat": self.auto_off_sysproxy,
            "quic_engelle": self.quic_block,
            "profil": self.cmb_profile.get(),
            "mod": self.cmb_mode.get(),
            "gecikme": int(float(self.scl.get())),
        })
        save_config(self.cfg)

    QUIC_RULE = "DPIVPN-QUIC"

    def quic_active(self):
        # Kural var ve etkin mi? (gösterme admin istemez)
        try:
            r = subprocess.run(["netsh", "advfirewall", "firewall", "show", "rule",
                                f"name={self.QUIC_RULE}"],
                               capture_output=True, text=True, timeout=15,
                               creationflags=NO_WINDOW, errors="replace")
            out = r.stdout
            return "Enabled:" in out and "Yes" in out and "No rules match" not in out
        except Exception:
            return False

    def toggle_quic(self):
        # QUIC (UDP 443) proxy dışından kaçar; engellenince site TCP'ye düşer.
        import ctypes
        try:
            if not self.quic_block:
                cmd = (f'netsh advfirewall firewall add rule name="{self.QUIC_RULE}" '
                       f'dir=out action=block protocol=UDP remoteport=443')
                ret = ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", "powershell",
                    f'-NoProfile -Command "{cmd}"', None, 0)
                if ret <= 32:
                    return
                self.quic_block = True
                self.btn_quic.configure(text=self.S("quic_on"), fg=GREEN)
                self.log("[ui] QUIC engellendi (UDP 443) — siteler TCP'ye duser")
            else:
                cmd = f'netsh advfirewall firewall delete rule name="{self.QUIC_RULE}"'
                ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", "powershell",
                    f'-NoProfile -Command "{cmd}"', None, 0)
                self.quic_block = False
                self.btn_quic.configure(text=self.S("quic_off"), fg=self.T["INK"])
                self.log("[ui] QUIC engeli kaldirildi")
            self.persist()
        except Exception as e:
            messagebox.showerror("QUIC", str(e))

    def open_settings(self):
        win = tk.Toplevel(self.root)
        win.title(self.S("settings_title"))
        win.geometry("330x340")
        win.resizable(False, False)
        T = self.T
        win.configure(bg=T["BG"])

        tk.Label(win, text=self.S("theme"), bg=T["BG"], fg=T["INK"],
                 font=("Segoe UI", 10, "bold")).place(x=16, y=12)
        Tooltip(win, 62, 13, lambda: self.S("tip_theme"))
        var = tk.StringVar(value=self.theme_name)
        for i, (val, key) in enumerate([("acik", "light"), ("koyu", "dark"), ("sistem", "system")]):
            tk.Radiobutton(win, text=self.S(key), variable=var, value=val, bg=T["BG"], fg=T["INK"],
                           activebackground=T["BG"], selectcolor=T["CARD"],
                           font=("Segoe UI", 9),
                           command=lambda v=val: self.set_theme(v)).place(x=24, y=40 + i * 26)

        tk.Label(win, text=self.S("lang"), bg=T["BG"], fg=T["INK"],
                 font=("Segoe UI", 10, "bold")).place(x=16, y=122)
        lvar = tk.StringVar(value=self.lang)
        tk.Radiobutton(win, text="Türkçe", variable=lvar, value="tr", bg=T["BG"], fg=T["INK"],
                       activebackground=T["BG"], selectcolor=T["CARD"], font=("Segoe UI", 9),
                       command=lambda: self.set_lang("tr")).place(x=24, y=148)
        tk.Radiobutton(win, text="English", variable=lvar, value="en", bg=T["BG"], fg=T["INK"],
                       activebackground=T["BG"], selectcolor=T["CARD"], font=("Segoe UI", 9),
                       command=lambda: self.set_lang("en")).place(x=120, y=148)

        tk.Label(win, text=self.S("engine"), bg=T["BG"], fg=T["INK"],
                 font=("Segoe UI", 10, "bold")).place(x=16, y=178)
        Tooltip(win, 70, 179, lambda: self.S("tip_engine"))
        evar = tk.StringVar(value=self.engine)
        tk.Radiobutton(win, text=self.S("eng_rust"), variable=evar, value="rust", bg=T["BG"], fg=T["INK"],
                       activebackground=T["BG"], selectcolor=T["CARD"], font=("Segoe UI", 9),
                       command=lambda: self.set_engine("rust")).place(x=24, y=204)
        tk.Radiobutton(win, text=self.S("eng_winws"), variable=evar, value="winws", bg=T["BG"], fg=T["INK"],
                       activebackground=T["BG"], selectcolor=T["CARD"], font=("Segoe UI", 9),
                       command=lambda: self.set_engine("winws")).place(x=24, y=230)

        tk.Label(win, text=self.S("behavior"), bg=T["BG"], fg=T["INK"],
                 font=("Segoe UI", 10, "bold")).place(x=16, y=258)
        self._cvar_tray = tk.BooleanVar(value=self.close_to_tray)
        self._cvar_off = tk.BooleanVar(value=self.auto_off_sysproxy)
        tk.Checkbutton(win, text=self.S("to_tray"), variable=self._cvar_tray,
                       bg=T["BG"], fg=T["INK"], activebackground=T["BG"],
                       selectcolor=T["CARD"], font=("Segoe UI", 9),
                       command=self._settings_behavior).place(x=24, y=284)
        tk.Checkbutton(win, text=self.S("auto_off"), variable=self._cvar_off,
                       bg=T["BG"], fg=T["INK"], activebackground=T["BG"],
                       selectcolor=T["CARD"], font=("Segoe UI", 9),
                       command=self._settings_behavior).place(x=24, y=310)

    def set_theme(self, name):
        self.theme_name = name
        self.apply_theme()
        self.persist()
        self.log(f"[ui] tema: {name}")

    def set_lang(self, lang):
        self.lang = lang
        self.apply_lang()
        self.apply_theme()
        self.persist()
        self.log(f"[ui] dil: {lang}")

    def set_engine(self, eng):
        self.engine = eng
        self.persist()
        self.log(f"[ui] motor: {eng}")

    def _settings_behavior(self):
        self.close_to_tray = self._cvar_tray.get()
        self.auto_off_sysproxy = self._cvar_off.get()
        self.persist()

    def _on_x(self):
        if self.close_to_tray and HAVE_TRAY:
            self._to_tray()
        else:
            self.on_close()

    # ---- tray ----
    def _tray_icon_image(self):
        img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
        d = ImageDraw.Draw(img)
        d.rounded_rectangle([4, 4, 60, 60], radius=14, fill=(37, 99, 235, 255))
        d.polygon([(36, 12), (24, 36), (32, 36), (28, 52), (42, 30), (34, 30)], fill=(255, 255, 255, 255))
        return img

    def _tray_setup(self):
        menu = pystray.Menu(
            pystray.MenuItem("Göster / Show", lambda: self.root.after(0, self._tray_show), default=True),
            pystray.MenuItem("BAŞLAT-DURDUR / START-STOP", lambda: self.root.after(0, self.toggle)),
            pystray.MenuItem("Çıkış / Exit", lambda: self.root.after(0, self.on_close)),
        )
        self.tray = pystray.Icon("dpi-vpn", self._tray_icon_image(), APP_TITLE, menu)

    def _tray_run(self):
        if self.tray and not self.tray.visible:
            threading.Thread(target=self.tray.run, daemon=True).start()

    def _to_tray(self):
        self.root.withdraw()
        self._tray_run()
        self.log("[ui] tepsiye alındı")

    def _tray_show(self):
        self.root.deiconify()
        self.root.lift()

    def _on_minimize(self, event=None):
        try:
            if self.root.state() == "iconic":
                self._to_tray()
        except tk.TclError:
            pass

    # ---- log ----
    def log(self, line):
        self.logq.put(line)

    def _tag(self, line):
        if line.startswith("[=]") or "temiz" in line or "clean" in line or "ÇALIŞIYOR" in line or "RUNNING" in line:
            return "ok"
        if line.startswith("[!]") or "ZEHİR" in line or "POISON" in line or "ÖLDÜ" in line or "DIED" in line or "hata" in line or "error" in line:
            return "err"
        if line.startswith("[hız]") or line.startswith("[analiz]") or line.startswith("[ui]"):
            return "info"
        if line.startswith("[+]") or line.startswith("[.]"):
            return "warn"
        return None

    def pump_log(self):
        try:
            while True:
                line = self.logq.get_nowait()
                self.txt.config(state="normal")
                self.txt.insert("end", line + "\n", self._tag(line))
                self.txt.see("end")
                self.txt.config(state="disabled")
        except queue.Empty:
            pass
        if self.proc is not None and self.proc.poll() is not None:
            code = self.proc.poll()
            self.proc = None
            self._set_stopped()
            self.lbl_status.configure(text=self.S("died"))
            self._dot_color(RED)
            self.log(f"[ui] exit({code})")
            if self.sys_proxy and self.auto_off_sysproxy:
                self.toggle_sysproxy()
        self.root.after(200, self.pump_log)

    def _set_running(self, text):
        self.btn_run.configure(text=self.S("stop"), bg=RED, activebackground="#B91C1C")
        self.lbl_status.configure(text=text)
        self._dot_color(GREEN)

    def _set_stopped(self):
        self.btn_run.configure(text=self.S("start"), bg=GREEN, activebackground="#15803D")
        self.lbl_status.configure(text=self.S("ready"))
        self._dot_color(RED)

    def _refresh_info(self):
        mode_short = self.cmb_mode.get().split(" ")[0]
        self.lbl_info.configure(text=f"{self.cmb_profile.get()}  •  {mode_short}  •  {int(float(self.scl.get()))} ms")

    def on_profile(self, *_):
        p = self.cmb_profile.get()
        if self.cmb_mode.get() == self.S("mode_bal"):
            self.delay.set(PROFILE_DELAY.get(p, 4))
        self._refresh_info()
        self.persist()

    def on_mode(self, *_):
        if self.cmb_mode.get() == self.S("mode_bal"):
            self.on_profile()
        elif self.cmb_mode.get() == self.S("mode_rev"):
            pass  # Ters: kaydırıcıdaki gecikme korunur
        else:
            self.delay.set(0)
        self._refresh_info()
        self.persist()

    # ---- motorlar ----
    def build_cmd(self):
        listen = ("0.0.0.0:8888" if self.lan_share else "127.0.0.1:8888")
        base = [PROXY_EXE, "--listen", listen, "--quiet"]
        mode = self.cmb_mode.get()
        if mode == self.S("mode_frag"):
            return base + ["--fragment", "32"]
        if mode == self.S("mode_auto"):
            return base + ["--auto"]
        if mode == self.S("mode_rev"):
            return base + ["--cut", "before", "--reverse", "--delay-ms", str(int(float(self.scl.get())))]
        if mode == self.S("mode_bal"):
            return base + ["--tls-records", "--delay-ms", str(int(float(self.scl.get())))]
        return base + ["--tls-records"]

    def build_winws_cmd(self):
        strat = self.cmb_profile.get()
        args = WINWS2_ARGS.get(strat, WINWS2_ARGS["Türk Telekom"])
        cmd = [WINWS2, "--wf-l3=ipv4", "--wf-tcp-out=0-65535", "--wf-udp-out=0-65535"] + args.split(" ")
        if EXCLUDELIST and os.path.exists(EXCLUDELIST):
            cmd.append(f'--hostlist-exclude="{EXCLUDELIST}"')
        for lua in ("zapret-lib.lua", "zapret-antidpi.lua", "zapret-auto.lua"):
            cmd.append(f'--lua-init="@{os.path.join(LUA, lua)}"')
        return cmd

    def toggle(self):
        if self.proc and self.proc.poll() is None:
            self._stop_proc()
            return
        if self.engine == "winws":
            self._start_winws()
        else:
            self._start_proxy()

    def _stop_proc(self):
        try:
            if self.proc and self.proc.poll() is None:
                self.proc.terminate()
                # winws sürücüyü bırakmasın
                if self.engine == "winws":
                    subprocess.run(["taskkill", "/F", "/IM", "winws2.exe"],
                                   capture_output=True, creationflags=NO_WINDOW)
        except Exception:
            pass
        self.proc = None
        self._set_stopped()
        self.log("[ui] stop")
        if self.sys_proxy and self.auto_off_sysproxy:
            self.toggle_sysproxy()

    def _start_proxy(self):
        if not os.path.exists(PROXY_EXE):
            messagebox.showerror("Hata", f"{self.S('no_proxy')}\n{PROXY_EXE}")
            return
        cmd = self.build_cmd()
        try:
            self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                         stderr=subprocess.STDOUT, bufsize=1,
                                         creationflags=NO_WINDOW)
        except Exception as e:
            messagebox.showerror(self.S("cant_start"), str(e))
            return
        threading.Thread(target=self.reader, daemon=True).start()
        self._set_running(f"{self.S('running')}: {self.cmb_profile.get()}")
        self._refresh_info()
        self.log("[ui] rust: " + " ".join(cmd))

    def _start_winws(self):
        if not os.path.exists(WINWS2):
            messagebox.showerror("Hata", f"{self.S('no_winws')}\n{WINWS2}")
            return
        if not is_admin():
            messagebox.showwarning("WinDivert", self.S("need_admin"))
            return
        cmd = self.build_winws_cmd()
        try:
            self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                         stderr=subprocess.STDOUT, bufsize=1,
                                         creationflags=NO_WINDOW, cwd=WINWS_DIR)
        except Exception as e:
            messagebox.showerror(self.S("cant_start"), str(e))
            return
        threading.Thread(target=self.reader, daemon=True).start()
        self._set_running(f"{self.S('running')}: {self.cmb_profile.get()} (WinDivert)")
        self._refresh_info()
        self.log("[ui] winws: " + " ".join(cmd[1:]))

    def reader(self):
        try:
            for raw in self.proc.stdout:
                self.log(raw.decode("utf-8", "replace").rstrip())
        except Exception:
            pass

    def analyze(self):
        try:
            out = subprocess.run(["nslookup", "updates.discord.com"],
                                 capture_output=True, text=True, timeout=15,
                                 creationflags=NO_WINDOW).stdout
        except Exception as e:
            messagebox.showerror(self.S("an_title"), str(e))
            return
        if "195.175.254.2" in out:
            self.log("[analiz] POISON")
            messagebox.showwarning(self.S("an_title"), self.S("an_poison"))
        elif "162.159" in out:
            self.log("[analiz] clean")
            messagebox.showinfo(self.S("an_title"), self.S("an_clean"))
        else:
            self.log("[analiz] ?")
            messagebox.showinfo(self.S("an_title"), self.S("an_vague") + "\n" + out[:400])

    def toggle_lan(self):
        self.lan_share = not self.lan_share
        self.btn_lan.configure(text=self.S("lan_on") if self.lan_share else self.S("lan_off"),
                               fg=GREEN if self.lan_share else self.T["INK"])

    def toggle_sysproxy(self):
        if winreg is None:
            return
        try:
            if not self.sys_proxy:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, IE_KEY, 0,
                                    winreg.KEY_READ) as k:
                    for name in ("ProxyEnable", "ProxyServer", "ProxyOverride"):
                        try:
                            self.saved_proxy[name] = winreg.QueryValueEx(k, name)
                        except FileNotFoundError:
                            self.saved_proxy[name] = None
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, IE_KEY, 0,
                                    winreg.KEY_SET_VALUE) as k:
                    winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 1)
                    winreg.SetValueEx(k, "ProxyServer", 0, winreg.REG_SZ,
                                      "http=127.0.0.1:8888;https=127.0.0.1:8888")
                    winreg.SetValueEx(k, "ProxyOverride", 0, winreg.REG_SZ, "<local>")
                self.sys_proxy = True
                self.btn_sysproxy.configure(text=self.S("syspx_on"), fg=GREEN)
                self.log("[ui] sysproxy on")
            else:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, IE_KEY, 0,
                                    winreg.KEY_SET_VALUE) as k:
                    for name, val in self.saved_proxy.items():
                        if val is None:
                            try:
                                winreg.DeleteValue(k, name)
                            except FileNotFoundError:
                                pass
                        else:
                            winreg.SetValueEx(k, name, 0, val[1], val[0])
                self.sys_proxy = False
                self.btn_sysproxy.configure(text=self.S("syspx_off"), fg=self.T["INK"])
                self.log("[ui] sysproxy off")
        except Exception as e:
            messagebox.showerror("proxy", str(e))

    def toggle_dns(self):
        try:
            if not self.dns_mode:
                ps = ("Get-DnsClientServerAddress -AddressFamily IPv4 | "
                      "Where-Object {$_.ServerAddresses} | Select-Object -First 1 "
                      "InterfaceAlias,ServerAddresses | Format-List | Out-String")
                r = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                                   capture_output=True, text=True, timeout=20,
                                   errors="replace", creationflags=NO_WINDOW)
                alias = None
                for line in r.stdout.splitlines():
                    if line.strip().startswith("InterfaceAlias"):
                        alias = line.split(":", 1)[1].strip()
                        break
                if not alias:
                    return
                self.saved_dns = {"alias": alias}
                # IPv4 + IPv6 birlikte: Windows IPv6 DNS'i tercih eder,
                # orası değişmezse modem (zehirli) cevap verir.
                # Ayrıca IPv6 yığını zehirli+zaman aşımlıysa arayüzde kapatılır
                # (geri dönüşte tekrar açılır) — her şey IPv4 Cloudflare'e düşer.
                cmd = (f'Set-DnsClientServerAddress -InterfaceAlias "{alias}" '
                       f'-ServerAddresses {DNS_PRIMARY},{DNS_SECONDARY}; '
                       f'Set-DnsClientServerAddress -InterfaceAlias "{alias}" '
                       f'-ServerAddresses {DNS6_PRIMARY},{DNS6_SECONDARY}; '
                       f'Disable-NetAdapterBinding -InterfaceAlias "{alias}" -ComponentID ms_tcpip6')
                import ctypes
                ret = ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", "powershell",
                    f'-NoProfile -Command "{cmd}"', None, 0)
                if ret <= 32:
                    return
                self.dns_mode = True
                self.btn_dns.configure(text=self.S("dns_on"), fg=GREEN)
                self.log(f"[ui] dns on ({alias})")
            else:
                alias = self.saved_dns.get("alias", "")
                cmd = (f'Set-DnsClientServerAddress -InterfaceAlias "{alias}" -ResetServerAddresses; '
                       f'Enable-NetAdapterBinding -InterfaceAlias "{alias}" -ComponentID ms_tcpip6')
                import ctypes
                ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", "powershell",
                    f'-NoProfile -Command "{cmd}"', None, 0)
                self.dns_mode = False
                self.btn_dns.configure(text=self.S("dns_off"), fg=self.T["INK"])
                self.log("[ui] dns reset")
        except Exception as e:
            messagebox.showerror("dns", str(e))

    def bench(self):
        self.log("[hız] ...")
        threading.Thread(target=self.bench_run, daemon=True).start()

    def bench_run(self):
        try:
            r = subprocess.run(["cargo", "test", "-p", "dpi-core", "--lib",
                                "bench_hot_path", "--", "--nocapture"],
                               capture_output=True, text=True, timeout=120,
                               cwd=BASE, errors="replace",
                               creationflags=NO_WINDOW)
            shown = False
            for line in (r.stdout + r.stderr).splitlines():
                if "bench:" in line or "test result" in line:
                    self.log("[hız] " + line.strip())
                    shown = True
            if not shown:
                raise RuntimeError("no bench")
        except Exception:
            self.log("[hız] ölçüm yapılamadı (cargo gerekli)")

    def on_close(self):
        try:
            if self.proc and self.proc.poll() is None:
                self._stop_proc()
            elif self.sys_proxy:
                self.toggle_sysproxy()
        except Exception:
            pass
        try:
            if self.tray:
                self.tray.stop()
        except Exception:
            pass
        self.root.destroy()


def main():
    import socket
    lock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        lock.bind(("127.0.0.1", 48888))
    except OSError:
        messagebox.showerror(APP_TITLE, "Zaten çalışıyor / Already running.")
        return
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
