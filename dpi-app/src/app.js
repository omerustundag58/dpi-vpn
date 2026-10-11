/* DPI-VPN Türkiye — Tauri v2 vanilla-JS frontend (tek sayfa, framework yok) */

const STR = {
  tr: {
    "status.stopped": "Durduruldu",
    "status.running": "Çalışıyor",
    "status.starting": "Başlatılıyor…",
    "status.error": "Hata",
    "info.stopped": "Proxy çalışmıyor",
    "run.start": "BAŞLAT",
    "run.stop": "DURDUR",
    "cfg.profile": "Profil",
    "cfg.mode": "Mod",
    "cfg.delay": "Gecikme",
    "mode.hizli": "Hızlı",
    "mode.dengeli": "Dengeli",
    "mode.parcala": "Parçala",
    "btn.analyze": "ISS Analizi",
    "btn.lan": "LAN Paylaşım",
    "btn.bench": "Hız Testi",
    "btn.sysproxy": "Sistem Proxy",
    "btn.dns": "DNS Modu",
    "btn.quic": "QUIC Engelle",
    "btn.settings": "Ayarlar",
    "set.title": "Ayarlar",
    "set.theme": "Tema",
    "set.themeLight": "Açık",
    "set.themeDark": "Koyu",
    "set.themeSystem": "Sistem",
    "set.lang": "Dil",
    "set.behavior": "Davranış",
    "set.tray": "Kapatınca tepsiye küçült",
    "set.closeProxy": "Durdurunca sistem proxy'yi kapat",
    "set.engine": "Motor",
    "set.windivertSoon": "WinDivert desteği yakında",
    "set.close": "Kapat",
    "tip.profile": "ISS profilini seç — DPI bypass deseni ISS'e göre değişir.",
    "tip.mode": "Hızlı: düşük gecikme. Dengeli: önerilen. Parçala: agresif bölme.",
    "tip.delay": "Paket parçaları arası gecikme (ms). 0-50 arası.",
    "log.noipc": "Tauri IPC yok — uygulama Tauri dışında açılmış.",
    "log.started": "Proxy başlatıldı.",
    "log.stopped": "Proxy durduruldu.",
    "log.startFail": "Başlatma hatası: ",
    "log.stopFail": "Durdurma hatası: ",
    "log.analyze": "ISS analizi yapılıyor…",
    "log.bench": "Hız testi yapılıyor…",
    "log.ipcFail": "IPC hatası (",
  },
  en: {
    "status.stopped": "Stopped",
    "status.running": "Running",
    "status.starting": "Starting…",
    "status.error": "Error",
    "info.stopped": "Proxy is not running",
    "run.start": "START",
    "run.stop": "STOP",
    "cfg.profile": "Profile",
    "cfg.mode": "Mode",
    "cfg.delay": "Delay",
    "mode.hizli": "Fast",
    "mode.dengeli": "Balanced",
    "mode.parcala": "Split",
    "btn.analyze": "ISP Analysis",
    "btn.lan": "LAN Share",
    "btn.bench": "Speed Test",
    "btn.sysproxy": "System Proxy",
    "btn.dns": "DNS Mode",
    "btn.quic": "Block QUIC",
    "btn.settings": "Settings",
    "set.title": "Settings",
    "set.theme": "Theme",
    "set.themeLight": "Light",
    "set.themeDark": "Dark",
    "set.themeSystem": "System",
    "set.lang": "Language",
    "set.behavior": "Behavior",
    "set.tray": "Minimize to tray on close",
    "set.closeProxy": "Disable system proxy on stop",
    "set.engine": "Engine",
    "set.windivertSoon": "WinDivert support coming soon",
    "set.close": "Close",
    "tip.profile": "Select ISP profile — DPI bypass pattern varies per ISP.",
    "tip.mode": "Fast: low latency. Balanced: recommended. Split: aggressive fragmentation.",
    "tip.delay": "Delay between packet fragments (ms). 0-50.",
    "log.noipc": "No Tauri IPC — app opened outside Tauri.",
    "log.started": "Proxy started.",
    "log.stopped": "Proxy stopped.",
    "log.startFail": "Start failed: ",
    "log.stopFail": "Stop failed: ",
    "log.analyze": "Running ISP analysis…",
    "log.bench": "Running speed test…",
    "log.ipcFail": "IPC error (",
  },
};

const LS_KEYS = ["theme", "lang", "profile", "mode", "delay", "tray", "closeProxy", "engine"];
const store = {
  get(k, fb) { try { const v = localStorage.getItem("dpi." + k); return v === null ? fb : v; } catch { return fb; } },
  set(k, v) { try { localStorage.setItem("dpi." + k, v); } catch {} },
};

let lang = store.get("lang", "tr");
if (!STR[lang]) lang = "tr";

const $ = (id) => document.getElementById(id);
const els = {};
["dot", "status", "info", "runBtn", "profile", "mode", "delay", "delayVal", "log",
 "analyzeBtn", "lanBtn", "benchBtn", "sysproxyBtn", "dnsBtn", "quicBtn",
 "openSettings", "settingsModal", "closeSettings", "optTray", "optCloseProxy",
 "windivertWarn", "version"].forEach((id) => (els[id] = $(id)));

let running = false;
let lanShare = false;
let sysproxyOn = false;
let dnsOn = false;
let quicOn = false;

/* ---------- IPC ---------- */
function tauriCore() {
  return window.__TAURI__ && window.__TAURI__.core ? window.__TAURI__.core : null;
}

async function safeInvoke(cmd, args) {
  const core = tauriCore();
  if (!core) {
    addLog("err", t("log.noipc"));
    throw new Error("no-ipc");
  }
  return core.invoke(cmd, args || {});
}

function t(key) {
  return (STR[lang] && STR[lang][key]) || STR.tr[key] || key;
}

/* ---------- Log ---------- */
function addLog(level, text) {
  const line = document.createElement("div");
  const cls = level === "ok" || level === "warn" || level === "err" || level === "info" ? level : "info";
  const span = document.createElement("span");
  span.className = cls;
  span.textContent = String(text);
  line.appendChild(span);
  els.log.appendChild(line);
  els.log.scrollTop = els.log.scrollHeight; // otomatik kaydırma
  while (els.log.children.length > 500) els.log.removeChild(els.log.firstChild);
}

/* ---------- i18n ---------- */
function setLang(next) {
  lang = STR[next] ? next : "tr";
  store.set("lang", lang);
  document.documentElement.lang = lang;
  document.querySelectorAll("[data-i18n]").forEach((el) => {
    el.textContent = t(el.getAttribute("data-i18n"));
  });
  document.querySelectorAll(".tip[data-tip-id]").forEach((el) => {
    el.setAttribute("data-tip", t(el.getAttribute("data-tip-id")));
  });
  document.querySelectorAll('input[name="lang"]').forEach((r) => (r.checked = r.value === lang));
  refreshStatusText();
}

function refreshStatusText() {
  if (running) {
    els.status.textContent = t("status.running");
  } else {
    els.status.textContent = t("status.stopped");
    els.info.textContent = t("info.stopped");
  }
  els.runBtn.textContent = running ? t("run.stop") : t("run.start");
}

/* ---------- Tema ---------- */
function applyTheme(theme) {
  store.set("theme", theme);
  let light;
  if (theme === "light") light = true;
  else if (theme === "dark") light = false;
  else light = window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches;
  document.body.classList.toggle("light", light);
  document.querySelectorAll('input[name="theme"]').forEach((r) => (r.checked = r.value === theme));
}

/* ---------- Durum UI ---------- */
function setRunning(on, infoText) {
  running = on;
  els.dot.classList.toggle("running", on);
  els.runBtn.classList.toggle("start", !on);
  els.runBtn.classList.toggle("stop", on);
  refreshStatusText();
  if (infoText !== undefined) els.info.textContent = infoText;
}

function fmtBytes(n) {
  n = Number(n) || 0;
  if (n < 1024) return n + " B";
  if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
  if (n < 1073741824) return (n / 1048576).toFixed(1) + " MB";
  return (n / 1073741824).toFixed(2) + " GB";
}

function fmtUptime(s) {
  s = Math.max(0, Math.floor(Number(s) || 0));
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), ss = s % 60;
  const p = (n) => String(n).padStart(2, "0");
  return h > 0 ? `${h}:${p(m)}:${p(ss)}` : `${p(m)}:${p(ss)}`;
}

/* ---------- Olaylar ---------- */
async function onRun() {
  if (!running) {
    els.status.textContent = t("status.starting");
    try {
      await safeInvoke("proxy_start", {
        profile: els.profile.options[els.profile.selectedIndex].text,
        mode: els.mode.value, // 'hizli' | 'dengeli' | 'parcala'
        delay_ms: parseInt(els.delay.value, 10) || 0,
        lan_share: lanShare,
      });
      setRunning(true);
      addLog("ok", t("log.started"));
      await pollStatus();
    } catch (e) {
      if (e && e.message === "no-ipc") { refreshStatusText(); return; }
      els.status.textContent = t("status.error");
      addLog("err", t("log.startFail") + (e && e.message ? e.message : e));
    }
  } else {
    try {
      await safeInvoke("proxy_stop");
      if (store.get("closeProxy", "0") === "1" && sysproxyOn) {
        try { await safeInvoke("sysproxy_set", { on: false }); sysproxyOn = false; els.sysproxyBtn.classList.remove("on"); } catch {}
      }
      setRunning(false);
      addLog("warn", t("log.stopped"));
    } catch (e) {
      if (e && e.message === "no-ipc") return;
      addLog("err", t("log.stopFail") + (e && e.message ? e.message : e));
    }
  }
}

async function pollStatus() {
  try {
    const s = await safeInvoke("get_status");
    // {running, uptimeSec, conns, bytesUp, bytesDown}
    if (typeof s.running === "boolean" && s.running !== running) setRunning(s.running);
    if (running || s.running) {
      els.info.textContent = `${fmtUptime(s.uptimeSec)} · ${s.conns} conn · ↑${fmtBytes(s.bytesUp)} ↓${fmtBytes(s.bytesDown)}`;
    }
  } catch (e) {
    if (!(e && e.message === "no-ipc")) addLog("err", t("log.ipcFail") + "get_status): " + (e.message || e));
  }
}

/* ---------- Başlat ---------- */
function init() {
  // localStorage → kontroller
  els.profile.value = store.get("profile", "turk-telekom");
  els.mode.value = store.get("mode", "dengeli");
  els.delay.value = store.get("delay", "10");
  els.delayVal.textContent = els.delay.value + " ms";
  els.optTray.checked = store.get("tray", "0") === "1";
  els.optCloseProxy.checked = store.get("closeProxy", "0") === "1";

  applyTheme(store.get("theme", "system"));
  setLang(lang);

  const engine = store.get("engine", "rust");
  document.querySelectorAll('input[name="engine"]').forEach((r) => (r.checked = r.value === engine));
  els.windivertWarn.classList.toggle("hidden", engine !== "windivert");

  setRunning(false);

  // Kontrol dinleyicileri
  els.profile.addEventListener("change", () => store.set("profile", els.profile.value));
  els.mode.addEventListener("change", () => store.set("mode", els.mode.value));
  els.delay.addEventListener("input", () => {
    els.delayVal.textContent = els.delay.value + " ms";
    store.set("delay", els.delay.value);
  });

  els.runBtn.addEventListener("click", onRun);

  els.analyzeBtn.addEventListener("click", async () => {
    addLog("info", t("log.analyze"));
    try {
      const r = await safeInvoke("analyze"); // {verdict, detail}
      addLog(r && r.verdict === "clean" ? "ok" : "warn", (r && r.verdict + " — " + r.detail) || "?");
    } catch (e) {
      if (!(e && e.message === "no-ipc")) addLog("err", t("log.ipcFail") + "analyze): " + (e.message || e));
    }
  });

  els.lanBtn.addEventListener("click", () => {
    lanShare = !lanShare; // proxy_start'a parametre olarak gider
    els.lanBtn.classList.toggle("on", lanShare);
    addLog("info", "LAN: " + (lanShare ? "ON" : "OFF"));
  });

  els.benchBtn.addEventListener("click", async () => {
    addLog("info", t("log.bench"));
    try {
      const r = await safeInvoke("bench"); // string
      addLog("ok", String(r));
    } catch (e) {
      if (!(e && e.message === "no-ipc")) addLog("err", t("log.ipcFail") + "bench): " + (e.message || e));
    }
  });

  els.sysproxyBtn.addEventListener("click", async () => {
    const next = !sysproxyOn;
    try {
      await safeInvoke("sysproxy_set", { on: next });
      sysproxyOn = next;
      els.sysproxyBtn.classList.toggle("on", next);
      addLog("info", "sysproxy: " + (next ? "ON" : "OFF"));
    } catch (e) {
      if (!(e && e.message === "no-ipc")) addLog("err", t("log.ipcFail") + "sysproxy_set): " + (e.message || e));
    }
  });

  els.dnsBtn.addEventListener("click", async () => {
    const next = !dnsOn;
    try {
      await safeInvoke("dns_set", { on: next });
      dnsOn = next;
      els.dnsBtn.classList.toggle("on", next);
      addLog("info", "dns: " + (next ? "ON" : "OFF"));
    } catch (e) {
      if (!(e && e.message === "no-ipc")) addLog("err", t("log.ipcFail") + "dns_set): " + (e.message || e));
    }
  });

  els.quicBtn.addEventListener("click", async () => {
    const next = !quicOn;
    try {
      await safeInvoke("quic_set", { on: next });
      quicOn = next;
      els.quicBtn.classList.toggle("on", next);
      addLog("info", "quic: " + (next ? "ON" : "OFF"));
    } catch (e) {
      if (!(e && e.message === "no-ipc")) addLog("err", t("log.ipcFail") + "quic_set): " + (e.message || e));
    }
  });

  // Modal
  els.openSettings.addEventListener("click", () => els.settingsModal.classList.remove("hidden"));
  els.closeSettings.addEventListener("click", () => els.settingsModal.classList.add("hidden"));
  els.settingsModal.addEventListener("click", (e) => {
    if (e.target === els.settingsModal) els.settingsModal.classList.add("hidden");
  });

  document.querySelectorAll('input[name="theme"]').forEach((r) =>
    r.addEventListener("change", () => applyTheme(document.querySelector('input[name="theme"]:checked').value))
  );
  document.querySelectorAll('input[name="lang"]').forEach((r) =>
    r.addEventListener("change", () => setLang(document.querySelector('input[name="lang"]:checked').value))
  );
  els.optTray.addEventListener("change", () => store.set("tray", els.optTray.checked ? "1" : "0"));
  els.optCloseProxy.addEventListener("change", () => store.set("closeProxy", els.optCloseProxy.checked ? "1" : "0"));
  document.querySelectorAll('input[name="engine"]').forEach((r) =>
    r.addEventListener("change", () => {
      const v = document.querySelector('input[name="engine"]:checked').value;
      store.set("engine", v);
      els.windivertWarn.classList.toggle("hidden", v !== "windivert");
    })
  );

  // Backend log olayı
  try {
    const ev = window.__TAURI__ && window.__TAURI__.event;
    if (ev && ev.listen) ev.listen("log", (e) => {
      const p = e.payload || {};
      addLog(p.level || "info", p.text || "");
    });
  } catch {}

  // Başlangıç QUIC durumu
  safeInvoke("quic_status").then(
    (v) => { quicOn = v === true; els.quicBtn.classList.toggle("on", quicOn); },
    () => {}
  );

  // 5 sn'de bir durum
  setInterval(pollStatus, 5000);
}

document.addEventListener("DOMContentLoaded", init);
