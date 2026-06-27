// Keepsake desktop frontend. Talks to the Rust core via Tauri commands.
// When opened outside the app (a plain browser preview) it falls back to demo data
// so the design can be reviewed without the backend.

const core = window.__TAURI__ && window.__TAURI__.core;
const invoke = core ? (cmd, args) => core.invoke(cmd, args) : null;
const DEMO = !invoke;

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

// ---------- theme (light / dark / system) ----------
// On first run with no saved choice we follow the Mac's light/dark setting; once the user picks, we
// remember it. The only thing this touches is a `.dark` class on <html> + a localStorage value.
function currentThemeMode() {
  return localStorage.getItem("keepsake-theme") || "system";
}
function applyTheme(mode) {
  const prefersDark =
    window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
  const dark = mode === "dark" || (mode === "system" && prefersDark);
  document.documentElement.classList.toggle("dark", dark);
}
function setThemeMode(mode) {
  localStorage.setItem("keepsake-theme", mode);
  applyTheme(mode);
}
function refreshThemeButtons() {
  const mode = currentThemeMode();
  $$(".theme-btn").forEach((b) => {
    const active = b.dataset.theme === mode;
    b.classList.toggle("bg-brand-700", active);
    b.classList.toggle("text-white", active);
    b.classList.toggle("text-ink", !active);
  });
}
// Apply immediately so the first paint matches; re-follow the OS live while in "system" mode.
applyTheme(currentThemeMode());
if (window.matchMedia) {
  window
    .matchMedia("(prefers-color-scheme: dark)")
    .addEventListener("change", () => {
      if (currentThemeMode() === "system") applyTheme("system");
    });
}
$$(".theme-btn").forEach((b) =>
  b.addEventListener("click", () => {
    setThemeMode(b.dataset.theme);
    refreshThemeButtons();
  }),
);
refreshThemeButtons();

// Soft tile palettes (literal strings so Tailwind's scanner keeps them).
const TILES = [
  "bg-brand-50 text-brand-600",
  "bg-amber-50 text-amber-600",
  "bg-sky-50 text-sky-600",
  "bg-violet-50 text-violet-600",
  "bg-rose-50 text-rose-600",
];
const ICON_NOTE =
  '<svg class="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M16 13H8"/><path d="M16 17H8"/></svg>';
const ICON_LOCK_S =
  '<svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>';
const ICON_TRASH =
  '<svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>';
const ICON_PLANE =
  '<svg class="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.8 19.2 16 11l3.5-3.5C21 6 21.5 4 21 3c-1-.5-3 0-4.5 1.5L13 8 4.8 6.2c-.5-.1-.9.1-1.1.5l-.3.5c-.2.5-.1 1 .3 1.3L9 12l-2 3H4l-1 1 3 2 2 3 1-1v-3l3-2 3.5 5.3c.3.4.8.5 1.3.3l.5-.2c.4-.3.6-.7.5-1.2z"/></svg>';
const TRAVEL_RE = /\b(flight|fly|flying|travel|trip|berlin|hotel|airport|vacation)\b/i;

let SETTINGS_COUNT = 0;

const AUTH_SCREENS = ["onboarding", "unlock", "lostaccess", "reset"];
function show(id) {
  AUTH_SCREENS.forEach((s) => {
    const el = $("#" + s);
    if (el) el.classList.toggle("hidden", s !== id);
  });
  const authVisible = AUTH_SCREENS.includes(id);
  $("#auth").classList.toggle("hidden", !authVisible);
  $("#shell").classList.toggle("hidden", authVisible);
}

function showLoading(modelReady) {
  $("#loading-title").textContent = modelReady
    ? "Unlocking your vault…"
    : "Downloading local AI model…";
  $("#loading-sub").textContent = modelReady
    ? "Loading your local memory…"
    : "One-time setup (~500 MB). Everything stays on your device.";
  $("#loading").classList.remove("hidden");
}
function hideLoading() {
  $("#loading").classList.add("hidden");
}

// ---------- timeline / cards ----------
function hashIndex(str, mod) {
  let h = 0;
  for (let i = 0; i < str.length; i++) h = (h * 31 + str.charCodeAt(i)) >>> 0;
  return h % mod;
}

function fmtTime(ts) {
  return new Date(ts * 1000).toLocaleTimeString("en-US", {
    hour: "2-digit",
    minute: "2-digit",
  });
}

function dateLabel(ts) {
  const d = new Date(ts * 1000);
  const today = new Date();
  const y = new Date();
  y.setDate(today.getDate() - 1);
  const same = (a, b) => a.toDateString() === b.toDateString();
  const full = d.toLocaleDateString("en-US", {
    month: "long",
    day: "numeric",
    year: "numeric",
  });
  if (same(d, today)) return `Today, ${full}`;
  if (same(d, y)) return `Yesterday, ${full}`;
  return full;
}

function cardHtml(mem, palette) {
  const text = mem.text || "";
  const nl = text.indexOf("\n");
  const title = (nl === -1 ? text : text.slice(0, nl)).trim() || "(empty)";
  const desc = nl === -1 ? "" : text.slice(nl + 1).trim();
  const icon = TRAVEL_RE.test(text) ? ICON_PLANE : ICON_NOTE;
  const src = sourceLabel(mem.source);
  return `
    <div data-card="${mem.id}" data-text="${escapeHtml(title)}" class="group bg-surface border border-line/80 rounded-2xl px-4 py-3.5 flex items-start gap-3.5 hover:shadow-sm transition">
      <span class="w-10 h-10 rounded-xl ${palette} flex items-center justify-center shrink-0">${icon}</span>
      <div class="min-w-0 flex-1">
        <div class="flex items-start justify-between gap-3">
          <div class="font-medium text-ink text-[15px] truncate">${escapeHtml(title)}</div>
          <div class="flex items-center gap-2 shrink-0">
            <span class="text-xs text-muted tabular-nums">${fmtTime(mem.created_at)}</span>
            <button data-forget="${mem.id}" aria-label="Remove this memory" class="shrink-0 inline-flex items-center justify-center w-11 h-11 -mr-1 rounded-xl text-muted hover:bg-red-50 hover:text-red-600 transition">${ICON_TRASH}</button>
          </div>
        </div>
        ${desc ? `<div class="text-sm text-muted mt-0.5 line-clamp-2">${escapeHtml(desc)}</div>` : ""}
        <div class="mt-2 flex items-center gap-2.5 text-xs text-muted">
          <span class="inline-flex items-center gap-1.5">${ICON_LOCK_S} End-to-end encrypted</span>
          ${src ? `<span class="text-muted">·</span><span>${escapeHtml(src)}</span>` : ""}
        </div>
      </div>
    </div>`;
}

function escapeHtml(s) {
  return s.replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c],
  );
}

function countLabel(n) {
  return `${n} ${n === 1 ? "memory" : "memories"}`;
}

// A friendly provenance label from a raw source tag (e.g. "proxy:openai:gpt-4" -> "via GPT",
// "mcp:claude" -> "via Claude", "desktop" -> "added here"). Empty when unknown.
function sourceLabel(source) {
  if (!source) return "";
  if (source === "desktop") return "added here";
  if (source === "cli") return "terminal";
  const p = source.split(":");
  if (p[0] === "proxy") return "via " + niceModel(p[p.length - 1]);
  if (p[0] === "mcp") return "via " + niceModel(p[1] || "agent");
  return source;
}
function niceModel(m) {
  const s = (m || "").toLowerCase();
  if (s.includes("claude")) return "Claude";
  if (s.includes("gpt")) return "GPT";
  if (s.includes("llama")) return "Llama";
  if (s.includes("gemini")) return "Gemini";
  if (s.includes("mistral")) return "Mistral";
  return m ? m.charAt(0).toUpperCase() + m.slice(1) : "a model";
}

function renderTimeline(memories) {
  const el = $("#timeline");
  const has = memories.length > 0;
  $("#start-empty").classList.toggle("hidden", has);
  const rh = $("#recent-header");
  if (rh) rh.classList.toggle("hidden", !has);
  $("#start-count").textContent = has ? countLabel(SETTINGS_COUNT) : "";
  const groups = [];
  for (const m of memories) {
    const label = dateLabel(m.created_at);
    let g = groups.find((x) => x.label === label);
    if (!g) groups.push((g = { label, items: [] }));
    g.items.push(m);
  }
  el.innerHTML = groups
    .map((g, gi) => {
      const isToday = g.label.startsWith("Today");
      const cards = g.items
        .map(
          (m) => `
        <div class="relative">
          <span class="absolute -left-[1.6rem] top-5 w-2.5 h-2.5 rounded-full ${isToday ? "bg-brand-500" : "bg-line"} ring-4 ring-canvas"></span>
          ${cardHtml(m, TILES[hashIndex(m.id, TILES.length)])}
        </div>`,
        )
        .join("");
      return `
      <div class="${gi > 0 ? "mt-6" : ""}">
        <div class="text-sm font-semibold ${isToday ? "text-brand-600" : "text-ink"} mb-3">${g.label}</div>
        <div class="relative border-l border-line pl-6 space-y-3">${cards}</div>
      </div>`;
    })
    .join("");
  el.querySelectorAll("[data-forget]").forEach((b) =>
    b.addEventListener("click", () => doForget(b.getAttribute("data-forget"))),
  );
}

function renderAll(memories) {
  const el = $("#all-list");
  $("#all-empty").classList.toggle("hidden", memories.length > 0);
  el.innerHTML = memories
    .map((m) => cardHtml(m, TILES[hashIndex(m.id, TILES.length)]))
    .join("");
  el.querySelectorAll("[data-forget]").forEach((b) =>
    b.addEventListener("click", () => doForget(b.getAttribute("data-forget"))),
  );
}

// ---------- data ----------
async function refresh() {
  if (DEMO) {
    SETTINGS_COUNT = DEMO_MEMORIES.length;
    renderTimeline(DEMO_MEMORIES);
    renderAll(DEMO_MEMORIES);
    return;
  }
  try {
    const st = await invoke("status");
    SETTINGS_COUNT = st.memories;
    $("#set-count").textContent = String(st.memories);
  } catch (_) {}
  try {
    renderTimeline(await invoke("recent", { limit: 6 }));
  } catch (_) {}
  try {
    renderAll(await invoke("recent", { limit: 100 }));
  } catch (_) {}
}

async function doRemember() {
  const input = $("#remember-input");
  const text = input.value.trim();
  if (!text || DEMO) {
    input.value = "";
    return;
  }
  try {
    await invoke("remember", { text });
    input.value = "";
    await refresh();
    autoBackup();
  } catch (_) {}
}

// ---------- safe delete: confirm, then an 8-second "undo" window before the memory is erased ----------
const FORGET_DELAY_MS = 8000;
const pendingForgets = new Map(); // id -> setTimeout handle

function cardText(id) {
  const el = document.querySelector(`[data-card="${id}"]`);
  return (el && el.getAttribute("data-text")) || "this memory";
}

// Entry point from a card's remove button. Asks first — nothing is erased on this click.
function doForget(id) {
  const text = cardText(id);
  const overlay = document.createElement("div");
  overlay.className =
    "fixed inset-0 z-50 flex items-center justify-center p-6 bg-neutral-900/40";
  overlay.innerHTML = `
    <div class="w-full max-w-md rounded-2xl bg-surface shadow-2xl p-6">
      <h2 class="text-2xl font-bold text-ink">Remove this memory?</h2>
      <div class="mt-4 rounded-xl bg-canvas border border-line px-4 py-3 text-lg text-ink">${escapeHtml(text)}</div>
      <p class="mt-4 text-lg text-muted">You'll have a few seconds to undo this.</p>
      <div class="mt-6 flex gap-3">
        <button data-keep class="flex-1 min-h-[52px] rounded-xl border-2 border-line px-4 py-3 text-lg font-semibold text-ink hover:bg-canvas transition">Keep it</button>
        <button data-remove class="flex-1 min-h-[52px] rounded-xl bg-red-600 px-4 py-3 text-lg font-semibold text-white hover:bg-red-700 transition">Remove</button>
      </div>
    </div>`;
  document.body.appendChild(overlay);
  const close = () => overlay.remove();
  overlay.addEventListener("click", (e) => {
    if (e.target === overlay) close();
  });
  overlay.querySelector("[data-keep]").addEventListener("click", close);
  overlay.querySelector("[data-remove]").addEventListener("click", () => {
    close();
    beginForget(id, text);
  });
}

// Hide the card now; erase only after the undo window elapses.
function beginForget(id, text) {
  document
    .querySelectorAll(`[data-card="${id}"]`)
    .forEach((el) => (el.style.display = "none"));
  showUndoToast(id, text);
  const handle = setTimeout(async () => {
    pendingForgets.delete(id);
    dismissToast();
    if (!DEMO && invoke) {
      try {
        await invoke("forget", { id });
        await refresh();
        autoBackup();
      } catch (_) {}
      if ($("#search-input") && $("#search-input").value.trim()) doSearch();
    }
  }, FORGET_DELAY_MS);
  pendingForgets.set(id, handle);
}

function undoForget(id) {
  const handle = pendingForgets.get(id);
  if (handle === undefined) return;
  clearTimeout(handle);
  pendingForgets.delete(id);
  document
    .querySelectorAll(`[data-card="${id}"]`)
    .forEach((el) => (el.style.display = ""));
  dismissToast();
}

function dismissToast() {
  const t = document.getElementById("undo-toast");
  if (t) t.remove();
}

function showUndoToast(id, text) {
  dismissToast();
  const short = text.length > 38 ? text.slice(0, 36) + "…" : text;
  const toast = document.createElement("div");
  toast.id = "undo-toast";
  toast.className =
    "fixed bottom-6 left-1/2 -translate-x-1/2 z-50 w-[min(92vw,30rem)] rounded-2xl bg-neutral-900 text-white shadow-2xl overflow-hidden";
  toast.innerHTML = `
    <div class="flex items-center gap-4 px-5 py-4">
      <span class="flex-1 text-lg">Removed "<span class="font-semibold">${escapeHtml(short)}</span>"</span>
      <button data-undo class="shrink-0 min-h-[44px] rounded-xl bg-surface/15 hover:bg-surface/25 px-4 py-2 text-lg font-semibold transition">Undo</button>
    </div>
    <div data-bar class="h-1.5 bg-brand-500" style="width:100%;transition:width ${FORGET_DELAY_MS}ms linear"></div>`;
  document.body.appendChild(toast);
  toast.querySelector("[data-undo]").addEventListener("click", () => undoForget(id));
  requestAnimationFrame(() => {
    const bar = toast.querySelector("[data-bar]");
    if (bar) bar.style.width = "0%";
  });
}

function renderHit(h) {
  const palette = TILES[hashIndex(h.id, TILES.length)];
  const icon = TRAVEL_RE.test(h.text) ? ICON_PLANE : ICON_NOTE;
  const oneLine = h.text.replace(/\s*\n\s*/g, " — ");
  return `
    <li class="bg-surface border border-line/80 rounded-2xl px-5 py-4 flex items-center gap-4 hover:shadow-sm transition">
      <span class="w-12 h-12 rounded-xl ${palette} flex items-center justify-center shrink-0">${icon}</span>
      <div class="min-w-0 flex-1">
        <div class="text-lg font-semibold text-ink truncate">${escapeHtml(oneLine)}</div>
        <div class="mt-1.5 flex items-center gap-2">
          <span class="inline-flex items-center gap-1.5 rounded-md bg-brand-50 px-2 py-0.5 text-sm font-medium text-brand-800">${ICON_LOCK_S} Only on your device</span>
          ${sourceLabel(h.source) ? `<span class="text-sm text-muted">· ${escapeHtml(sourceLabel(h.source))}</span>` : ""}
        </div>
      </div>
      <svg class="w-5 h-5 text-muted shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m9 18 6-6-6-6"/></svg>
    </li>`;
}

async function doSearch() {
  const q = $("#search-input").value.trim();
  $("#search-clear").classList.toggle("hidden", !q);
  const examples = $("#search-examples");
  const empty = $("#search-empty");
  const results = $("#search-results");
  if (!q) {
    results.innerHTML = "";
    if (examples) examples.classList.remove("hidden");
    if (empty) empty.classList.add("hidden");
    return;
  }
  if (examples) examples.classList.add("hidden");
  let hits = [];
  if (DEMO) {
    hits = DEMO_MEMORIES.filter((m) =>
      m.text.toLowerCase().includes(q.toLowerCase()),
    ).map((m) => ({ id: m.id, text: m.text, source: m.source }));
  } else {
    try {
      hits = await invoke("recall", { query: q, k: 8 });
    } catch (_) {
      hits = [];
    }
  }
  if (hits.length) {
    if (empty) empty.classList.add("hidden");
    results.innerHTML = hits.map(renderHit).join("");
  } else {
    results.innerHTML = "";
    await showNoResult(q);
  }
}

// A no-result that never dead-ends: explain kindly, offer to save it, and show recent memories.
async function showNoResult(q) {
  const empty = $("#search-empty");
  if (!empty) return;
  let recent = [];
  if (DEMO) recent = DEMO_MEMORIES.slice(0, 3);
  else {
    try {
      recent = await invoke("recent", { limit: 3 });
    } catch (_) {}
  }
  empty.classList.remove("hidden");
  empty.innerHTML = `
    <div class="text-center py-8">
      <p class="text-xl font-semibold text-ink">I couldn't find anything for that.</p>
      <p class="mt-2 text-lg text-muted">Try simpler words — like just a name or a place.</p>
      <button id="save-as-memory" class="mt-5 inline-flex min-h-[48px] items-center rounded-xl bg-brand-700 px-5 text-lg font-semibold text-white hover:bg-brand-800 transition">Save “${escapeHtml(q)}” as a new memory</button>
    </div>
    ${recent.length ? `<div class="mt-2"><p class="text-base font-semibold text-ink mb-3">Your most recent memories:</p><ul class="space-y-3">${recent.map(renderHit).join("")}</ul></div>` : ""}`;
  const save = $("#save-as-memory");
  if (save)
    save.addEventListener("click", () => {
      navTo("start");
      const i = $("#remember-input");
      if (i) {
        i.value = q;
        i.focus();
      }
    });
}

// ---------- onboarding / unlock ----------
async function startOnboarding() {
  let phrase;
  if (DEMO || !invoke) {
    phrase = DEMO_SEED;
  } else {
    try {
      phrase = await invoke("generate_seed");
    } catch (_) {
      $("#onboard-error").textContent =
        "Sorry — couldn't create your key just now. Please reopen the app.";
      $("#onboard-error").classList.remove("hidden");
      return;
    }
  }
  window.__SEED__ = phrase;
  const words = phrase.split(/\s+/);
  $("#seed-grid").innerHTML = words
    .map(
      (w, i) => `
      <div class="flex items-center gap-3 rounded-xl border border-line bg-canvas/60 px-4 py-3">
        <span class="w-6 text-right text-base tabular-nums text-muted">${i + 1}</span>
        <span class="text-lg font-medium text-ink">${escapeHtml(w)}</span>
      </div>`,
    )
    .join("");
  buildPrintSheet(words);
  setupVerify(words);
  $("#onboard-continue").disabled = true;
  $("#onboard-error").classList.add("hidden");
  show("onboarding");
}

// A clean one-page sheet the user can put with their papers (shown only when printing).
function buildPrintSheet(words) {
  const sheet = $("#seed-print-sheet");
  if (!sheet) return;
  sheet.innerHTML = `
    <h1 style="font-size:22px;font-weight:700;margin:0 0 6px">Your Keepsake key</h1>
    <p style="margin:0 0 16px;color:#444">These 24 words are the only way to open your Keepsake. Keep this page somewhere safe, like with your important papers. Never share it.</p>
    <ol style="columns:2;font-size:16px;line-height:2;padding-left:24px">${words.map((w) => `<li>${escapeHtml(w)}</li>`).join("")}</ol>`;
}

// A real check (replaces the old "I wrote them down" checkbox): tap the correct word.
function setupVerify(words) {
  const n = 1 + Math.floor(Math.random() * words.length); // 1-based position
  const correct = words[n - 1];
  const decoys = [];
  while (decoys.length < 2) {
    const w = words[Math.floor(Math.random() * words.length)];
    if (w !== correct && !decoys.includes(w)) decoys.push(w);
  }
  const options = [correct, ...decoys].sort(() => Math.random() - 0.5);
  $("#verify-n").textContent = "number " + n;
  const msg = $("#verify-msg");
  if (msg) msg.classList.add("hidden");
  const box = $("#verify-options");
  box.innerHTML = options
    .map(
      (w) =>
        `<button class="verify-opt min-h-[52px] rounded-xl border-2 border-line px-6 text-lg font-semibold text-ink hover:bg-canvas transition" data-word="${escapeHtml(w)}">${escapeHtml(w)}</button>`,
    )
    .join("");
  box.querySelectorAll(".verify-opt").forEach((b) =>
    b.addEventListener("click", () => {
      if (b.dataset.word === correct) {
        box.querySelectorAll(".verify-opt").forEach((x) => (x.disabled = true));
        b.classList.add("border-brand-500", "bg-brand-50", "text-brand-800");
        if (msg) {
          msg.textContent = "✓ Perfect. Your key is saved correctly.";
          msg.className = "mt-3 text-center text-base font-medium text-brand-700";
          msg.classList.remove("hidden");
        }
        $("#onboard-continue").disabled = false;
      } else {
        b.classList.add("border-red-300", "bg-red-50");
        if (msg) {
          msg.textContent = "That's not the one. Check your copy, then try again.";
          msg.className = "mt-3 text-center text-base font-medium text-red-700";
          msg.classList.remove("hidden");
        }
      }
    }),
  );
}

// Run unlock with a loading overlay; message depends on whether the model is local yet.
// ---------- 24-word seed boxes (unlock) ----------
const BIP39 = window.BIP39_WORDS || [];
const BIP39_SET = new Set(BIP39);

function seedBoxInputs() {
  return $$("#seed-boxes input");
}
function seedBoxWords() {
  return seedBoxInputs().map((i) => i.value.trim().toLowerCase());
}
function validateSeedBox(input) {
  const v = input.value.trim().toLowerCase();
  const bad = v !== "" && !BIP39_SET.has(v);
  input.classList.toggle("border-red-400", bad);
  input.classList.toggle("border-line", !bad);
}
function updateUnlockState() {
  const words = seedBoxWords();
  const ready = words.length === 24 && words.every((w) => BIP39_SET.has(w));
  const btn = $("#unlock-btn");
  if (btn) btn.disabled = !ready;
}
function fillSeedBoxes(words, startIdx) {
  const inputs = seedBoxInputs();
  words.forEach((w, k) => {
    const idx = (startIdx || 0) + k;
    if (idx < inputs.length) inputs[idx].value = w.toLowerCase();
  });
  inputs.forEach(validateSeedBox);
  updateUnlockState();
  const firstEmpty = inputs.find((i) => !i.value.trim());
  (firstEmpty || inputs[inputs.length - 1]).focus();
}
function setupSeedBoxes() {
  const wrap = $("#seed-boxes");
  if (!wrap) return;
  const dl = $("#bip39-list");
  if (dl && !dl.children.length && BIP39.length) {
    dl.innerHTML = BIP39.map((w) => `<option value="${w}"></option>`).join("");
  }
  wrap.innerHTML = "";
  for (let i = 0; i < 24; i++) {
    const cell = document.createElement("div");
    cell.className = "relative";
    cell.innerHTML =
      `<span class="absolute left-2 top-1/2 -translate-y-1/2 text-xs text-muted tabular-nums select-none pointer-events-none">${i + 1}</span>` +
      `<input data-i="${i}" list="bip39-list" autocapitalize="off" autocomplete="off" autocorrect="off" spellcheck="false" aria-label="Word ${i + 1}" class="w-full pl-7 pr-2 py-2 rounded-lg border-2 border-line text-base text-ink bg-surface focus:outline-none focus:border-brand-400 focus:ring-2 focus:ring-brand-500/30" />`;
    wrap.appendChild(cell);
  }
  seedBoxInputs().forEach((input, i, inputs) => {
    input.addEventListener("input", () => {
      validateSeedBox(input);
      updateUnlockState();
    });
    input.addEventListener("paste", (e) => {
      const text = (e.clipboardData || window.clipboardData).getData("text") || "";
      const words = text.trim().split(/\s+/).filter(Boolean);
      if (words.length > 1) {
        e.preventDefault();
        fillSeedBoxes(words, i);
      }
    });
    input.addEventListener("keydown", (e) => {
      if ((e.key === " " || e.key === "Enter") && input.value.trim()) {
        e.preventDefault();
        if (i < inputs.length - 1) inputs[i + 1].focus();
        else if (!$("#unlock-btn").disabled) doUnlock();
      } else if (e.key === "Backspace" && !input.value && i > 0) {
        e.preventDefault();
        inputs[i - 1].focus();
      }
    });
  });
}
setupSeedBoxes();

(() => {
  const sp = $("#seed-paste");
  if (sp)
    sp.addEventListener("click", async () => {
      try {
        const text = await navigator.clipboard.readText();
        const words = (text || "").trim().split(/\s+/).filter(Boolean);
        if (words.length) fillSeedBoxes(words, 0);
      } catch (_) {}
    });
  // Updates must be reachable BEFORE login, so a locked-out user is never trapped — a visible,
  // user-initiated check (never a silent ping), placed on the unlock screen itself.
  const uc = $("#unlock-update-check");
  if (uc)
    uc.addEventListener("click", async () => {
      const status = $("#unlock-update-status");
      if (DEMO || !invoke) {
        if (status) status.textContent = "You're up to date.";
        return;
      }
      uc.textContent = "Checking…";
      try {
        const v = await invoke("check_update");
        if (v) {
          showUpdateBanner(v);
          if (status) status.textContent = "Update " + v + " is available — see the banner up top.";
        } else if (status) {
          status.textContent = "You're up to date.";
        }
      } catch (_) {
        if (status) status.textContent = "Couldn't check — check your internet.";
      } finally {
        uc.textContent = "Check for updates";
      }
    });
})();

async function runUnlock(mnemonic) {
  let ready = true;
  try {
    ready = await invoke("model_ready");
  } catch (_) {
    ready = true;
  }
  showLoading(ready);
  try {
    await invoke("unlock", { mnemonic });
    hideLoading();
    enterShell();
  } catch (e) {
    hideLoading();
    throw e;
  }
}

async function doOnboardContinue() {
  if (DEMO) {
    showLoading(false);
    setTimeout(() => {
      hideLoading();
      enterShell();
    }, 1400);
    return;
  }
  const btn = $("#onboard-continue");
  btn.disabled = true;
  try {
    await runUnlock(window.__SEED__);
  } catch (e) {
    $("#onboard-error").textContent = String(e);
    $("#onboard-error").classList.remove("hidden");
    btn.disabled = false;
  }
}

async function doUnlock() {
  const mnemonic = seedBoxWords().join(" ").trim();
  if (!mnemonic) return;
  const btn = $("#unlock-btn");
  btn.disabled = true;
  $("#unlock-error").classList.add("hidden");
  try {
    await runUnlock(mnemonic);
    seedBoxInputs().forEach((i) => {
      i.value = "";
    });
  } catch (e) {
    $("#unlock-error").textContent =
      "Those 24 words didn't open your memories. Check the spelling, or tap “I can't find my 24 words” below.";
    $("#unlock-error").classList.remove("hidden");
  } finally {
    updateUnlockState();
  }
}

async function doLock() {
  if (invoke) {
    try {
      await invoke("lock");
    } catch (_) {}
  }
  if (DEMO || !invoke) {
    show("unlock");
    return;
  }
  show((await invoke("vault_exists")) ? "unlock" : "onboarding");
}

function enterShell() {
  show("shell-only"); // any non-auth id hides auth + shows shell
  navTo("start");
  refresh();
  loadSyncConfig();
  loadRecoveryStatus();
  loadBackupStatus();
}

// ---------- sync server setting ----------
function paintSyncOptions(mode) {
  $$(".sync-opt").forEach((b) => {
    const active = b.dataset.sync === mode;
    b.classList.toggle("border-brand-500", active);
    b.classList.toggle("bg-brand-50", active);
    b.classList.toggle("text-brand-700", active);
    b.classList.toggle("border-line", !active);
    b.classList.toggle("text-muted", !active);
  });
  $("#sync-own-row").classList.toggle("hidden", mode !== "own");
}

function setSyncStatus(mode) {
  const el = $("#sync-status");
  if (el) {
    el.textContent =
      mode === "hosted"
        ? "On — your devices share the same notes, privately. The place in the middle can never read them."
        : mode === "own"
          ? "On — syncing through your own server."
          : "Off — your notes stay only on this computer.";
  }
  // Keep the honest line on the Home screen in step with the real setting.
  const home = $("#home-status-text");
  if (home) {
    home.textContent =
      mode === "off"
        ? "Saved only on this computer. Nothing is sent anywhere."
        : "Saved on this computer and your other devices — privately.";
  }
}

async function loadSyncConfig() {
  if (DEMO) {
    paintSyncOptions("off");
    setSyncStatus("off");
    return;
  }
  let cfg;
  try {
    cfg = await invoke("get_sync_config");
  } catch (_) {
    cfg = { mode: "off" };
  }
  if (cfg.mode === "own" && cfg.url) $("#sync-url").value = cfg.url;
  paintSyncOptions(cfg.mode);
  setSyncStatus(cfg.mode);
}

async function applySync(config) {
  if (DEMO) return;
  try {
    await invoke("set_sync_config", { config });
  } catch (e) {
    console.error("set_sync_config", e);
  }
}

function wireSyncControls() {
  $$(".sync-opt").forEach((b) =>
    b.addEventListener("click", async () => {
      const mode = b.dataset.sync;
      paintSyncOptions(mode);
      if (mode === "own") {
        $("#sync-url").focus();
        return; // wait for a URL + Save
      }
      setSyncStatus(mode);
      await applySync({ mode });
    }),
  );
  const save = $("#sync-url-save");
  if (save)
    save.addEventListener("click", async () => {
      const url = ($("#sync-url").value || "").trim();
      if (!url) return;
      setSyncStatus("own");
      await applySync({ mode: "own", url });
    });
}

// ---------- nav ----------
function navTo(view) {
  $$(".nav-item").forEach((b) => {
    const active = b.getAttribute("data-view") === view;
    b.classList.toggle("bg-brand-50", active);
    b.classList.toggle("text-brand-700", active);
    b.classList.toggle("text-muted", !active);
  });
  $$(".view").forEach((s) =>
    s.classList.toggle("hidden", s.getAttribute("data-screen") !== view),
  );
  if (view === "suchen") setTimeout(() => $("#search-input").focus(), 30);
}

// ---------- wire events ----------
$("#onboard-continue").addEventListener("click", doOnboardContinue);
$("#unlock-btn").addEventListener("click", doUnlock);
$("#remember-btn").addEventListener("click", doRemember);
$("#remember-input").addEventListener("keydown", (e) => {
  if (e.key === "Enter") doRemember();
});
$("#search-input").addEventListener("input", debounce(doSearch, 160));
$("#search-clear").addEventListener("click", () => {
  $("#search-input").value = "";
  doSearch();
});
$("#lock-btn").addEventListener("click", doLock);
$("#lock-btn-2").addEventListener("click", doLock);
$$(".nav-item").forEach((b) =>
  b.addEventListener("click", () => navTo(b.getAttribute("data-view"))),
);
wireSyncControls();

// ---------- lost-access + start-fresh (never get stuck on the unlock screen) ----------
const on = (sel, ev, fn) => {
  const el = $(sel);
  if (el) el.addEventListener(ev, fn);
};
on("#lostaccess-link", "click", () => show("lostaccess"));
on("#lostaccess-back", "click", () => show("unlock"));
on("#startfresh-link", "click", () => show("reset"));
on("#reset-cancel", "click", () => show("unlock"));

// Example chips on Home: tap to pre-fill the box (the user still presses Remember).
$$(".example-chip").forEach((b) =>
  b.addEventListener("click", () => {
    const i = $("#remember-input");
    if (!i) return;
    i.value = b.dataset.fill || b.textContent.trim();
    i.focus();
  }),
);
// Search example chips: tap to run the question.
$$(".search-chip").forEach((b) =>
  b.addEventListener("click", () => {
    const i = $("#search-input");
    if (!i) return;
    i.value = b.dataset.q || b.textContent.trim();
    doSearch();
  }),
);
// "Start over" is also reachable from Settings (locks + shows the gated reset screen).
on("#settings-startover", "click", () => show("reset"));

// Show my 24 words again — gated by a "no one is looking" step, like a hardware wallet.
const DEMO_SEED =
  "apple river cloud stone meadow lamp window quiet garden silver paper ocean bridge candle forest gentle sunrise pocket mirror violet harbor cotton ladder compass";
on("#reveal-seed-btn", "click", async () => {
  let phrase = "";
  if (DEMO || !invoke) {
    phrase = DEMO_SEED;
  } else {
    try {
      phrase = await invoke("reveal_seed");
    } catch (_) {
      return;
    }
  }
  const grid = $("#reveal-seed-grid");
  if (grid)
    grid.innerHTML = phrase
      .split(/\s+/)
      .map(
        (w, i) =>
          `<div class="flex items-center gap-2 rounded-lg border border-line bg-canvas px-3 py-2"><span class="w-5 text-right text-sm tabular-nums text-muted">${i + 1}</span><span class="text-base font-medium text-ink">${escapeHtml(w)}</span></div>`,
      )
      .join("");
  const area = $("#reveal-seed-area");
  if (area) area.classList.remove("hidden");
  const btn = $("#reveal-seed-btn");
  if (btn) btn.classList.add("hidden");
});
on("#reveal-seed-hide", "click", () => {
  const grid = $("#reveal-seed-grid");
  if (grid) grid.innerHTML = "";
  const area = $("#reveal-seed-area");
  if (area) area.classList.add("hidden");
  const btn = $("#reveal-seed-btn");
  if (btn) btn.classList.remove("hidden");
});

// Onboarding: save your key by copying or printing it.
on("#seed-copy", "click", async () => {
  const phrase = window.__SEED__ || "";
  try {
    await navigator.clipboard.writeText(phrase);
    const l = $("#seed-copy-label");
    if (l) {
      l.textContent = "Copied ✓";
      setTimeout(() => (l.textContent = "Copy the words"), 2000);
    }
  } catch (_) {}
});
on("#seed-print", "click", () => window.print());

// ---------- social recovery: give sealed pieces to people you trust ----------
function modalShell(innerHtml) {
  const o = document.createElement("div");
  o.className =
    "fixed inset-0 z-50 flex items-center justify-center p-6 bg-neutral-900/40 overflow-y-auto";
  o.innerHTML = `<div class="w-full max-w-lg rounded-2xl bg-surface shadow-2xl p-6 my-8">${innerHtml}</div>`;
  document.body.appendChild(o);
  return o;
}

function downloadText(filename, text) {
  const blob = new Blob([text], { type: "text/plain" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

async function loadRecoveryStatus() {
  const el = $("#safetynet-status");
  if (!el) return;
  let meta = null;
  if (!DEMO && invoke) {
    try {
      meta = await invoke("get_recovery_meta");
    } catch (_) {}
  }
  if (meta && meta.names && meta.names.length) {
    el.textContent = "On — pieces are with: " + meta.names.join(", ");
    el.className = "mt-2 text-base font-medium text-brand-700";
  } else {
    el.textContent = "Not set up yet.";
    el.className = "mt-2 text-base font-medium text-amber-700";
  }
}

function openRecoverySetup() {
  const o = modalShell(`
    <h2 class="text-2xl font-bold text-ink">Set up your safety net</h2>
    <p class="mt-2 text-lg text-muted">We'll make 3 secret pieces. Give one to each of 3 people you trust. Any two of them together can bring your memories back — one alone can't read anything.</p>
    <div class="mt-5 space-y-3">
      ${[1, 2, 3].map((i) => `<input class="rec-name w-full min-h-[52px] rounded-xl border-2 border-line px-4 text-lg" placeholder="Person ${i} — e.g. My daughter Anna">`).join("")}
    </div>
    <div class="mt-6 flex gap-3">
      <button data-cancel class="flex-1 min-h-[52px] rounded-xl border-2 border-line text-lg font-semibold text-ink hover:bg-canvas transition">Cancel</button>
      <button data-next class="flex-1 min-h-[52px] rounded-xl bg-brand-700 text-white text-lg font-semibold hover:bg-brand-800 transition">Create the pieces</button>
    </div>`);
  o.querySelector("[data-cancel]").addEventListener("click", () => o.remove());
  o.querySelector("[data-next]").addEventListener("click", async () => {
    const names = [...o.querySelectorAll(".rec-name")]
      .map((i) => i.value.trim())
      .filter(Boolean);
    if (names.length < 2) return;
    let pieces = [];
    if (DEMO || !invoke) {
      pieces = names.map((_, i) => `${i + 1}-demopiece${i}`);
    } else {
      try {
        pieces = await invoke("recovery_split", { threshold: 2, shares: names.length });
      } catch (_) {
        return;
      }
    }
    o.remove();
    showRecoveryPieces(names, pieces);
  });
}

function showRecoveryPieces(names, pieces) {
  const o = modalShell(`
    <h2 class="text-2xl font-bold text-ink">Give each person their piece</h2>
    <p class="mt-2 text-lg text-muted">Save each piece and give it to that person. Don't keep them together with your 24 words.</p>
    <div class="mt-5 space-y-3">
      ${names
        .map(
          (n, i) => `
        <div class="rounded-xl border-2 border-line p-4">
          <div class="text-lg font-semibold text-ink">${escapeHtml(n)}</div>
          <div class="mt-2 flex gap-2">
            <button class="rec-save min-h-[44px] rounded-lg border-2 border-line px-4 text-base font-semibold hover:bg-canvas transition" data-i="${i}">Save this piece</button>
            <button class="rec-copy min-h-[44px] rounded-lg border-2 border-line px-4 text-base font-semibold hover:bg-canvas transition" data-i="${i}">Copy</button>
          </div>
        </div>`,
        )
        .join("")}
    </div>
    <button data-done class="mt-6 w-full min-h-[52px] rounded-xl bg-brand-700 text-white text-lg font-semibold hover:bg-brand-800 transition">Done — my safety net is on</button>`);
  o.querySelectorAll(".rec-save").forEach((b) =>
    b.addEventListener("click", () => {
      const i = +b.dataset.i;
      const body = `Keepsake recovery piece for ${names[i]}\n\nKeep this safe and private. If they ever lose their 24 words, they will ask you and one other person for your pieces to bring their memories back. This piece alone reveals nothing.\n\nYour piece:\n${pieces[i]}\n`;
      downloadText(`keepsake-piece-${names[i].replace(/\s+/g, "-")}.txt`, body);
    }),
  );
  o.querySelectorAll(".rec-copy").forEach((b) =>
    b.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(pieces[+b.dataset.i]);
        b.textContent = "Copied ✓";
        setTimeout(() => (b.textContent = "Copy"), 1500);
      } catch (_) {}
    }),
  );
  o.querySelector("[data-done]").addEventListener("click", async () => {
    if (!DEMO && invoke) {
      try {
        await invoke("save_recovery_meta", { threshold: 2, names });
      } catch (_) {}
    }
    o.remove();
    loadRecoveryStatus();
  });
}

// Use: rebuild the words from collected pieces (reached from the lost-access triage).
function openRecoveryUse() {
  const o = modalShell(`
    <h2 class="text-2xl font-bold text-ink">Get back in with your trusted people</h2>
    <p class="mt-2 text-lg text-muted">Ask two of the people you trust for the piece you gave them, and paste both here.</p>
    <div class="mt-5 space-y-3">
      <textarea class="rec-piece w-full rounded-xl border-2 border-line px-4 py-3 text-base" rows="2" placeholder="Paste the first piece here"></textarea>
      <textarea class="rec-piece w-full rounded-xl border-2 border-line px-4 py-3 text-base" rows="2" placeholder="Paste the second piece here"></textarea>
    </div>
    <p data-msg class="mt-3 text-base text-red-700 hidden"></p>
    <div class="mt-6 flex gap-3">
      <button data-cancel class="flex-1 min-h-[52px] rounded-xl border-2 border-line text-lg font-semibold text-ink hover:bg-canvas transition">Back</button>
      <button data-go class="flex-1 min-h-[52px] rounded-xl bg-brand-700 text-white text-lg font-semibold hover:bg-brand-800 transition">Bring my memories back</button>
    </div>`);
  o.querySelector("[data-cancel]").addEventListener("click", () => o.remove());
  o.querySelector("[data-go]").addEventListener("click", async () => {
    const pieces = [...o.querySelectorAll(".rec-piece")]
      .map((t) => t.value.trim())
      .filter(Boolean);
    const msg = o.querySelector("[data-msg]");
    if (pieces.length < 2) {
      msg.textContent = "Please paste two pieces, from two different people.";
      msg.classList.remove("hidden");
      return;
    }
    if (DEMO || !invoke) {
      o.remove();
      enterShell();
      return;
    }
    let mnemonic;
    try {
      mnemonic = await invoke("recovery_combine", { shares: pieces });
    } catch (e) {
      msg.textContent = String(e).replace(/^Error:\s*/, "");
      msg.classList.remove("hidden");
      return;
    }
    o.remove();
    try {
      await runUnlock(mnemonic);
    } catch (_) {}
  });
}

on("#safetynet-setup", "click", openRecoverySetup);
on("#recovery-use-link", "click", openRecoveryUse);

// ---------- a safe copy (encrypted backup) ----------
function fmtDate(ts) {
  if (!ts) return "";
  const d = new Date(ts * 1000);
  return (
    d.toLocaleDateString("en-US", { month: "short", day: "numeric" }) +
    ", " +
    d.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" })
  );
}

async function loadBackupStatus() {
  const status = $("#backup-status");
  const toggle = $("#backup-toggle");
  if (!status || !toggle) return;
  let meta = { on: false, last_saved: 0 };
  if (!DEMO && invoke) {
    try {
      meta = await invoke("backup_status");
    } catch (_) {}
  }
  if (meta && meta.on) {
    status.textContent = meta.last_saved
      ? "On — last saved " + fmtDate(meta.last_saved)
      : "On.";
    status.className = "mt-2 text-base font-medium text-brand-700";
    toggle.textContent = "Save a fresh copy now";
  } else {
    status.textContent = "Off.";
    status.className = "mt-2 text-base font-medium text-amber-700";
    toggle.textContent = "Keep a safe copy";
  }
}

function backupPasswordModal({ title, intro, action, run }) {
  const o = modalShell(`
    <h2 class="text-2xl font-bold text-ink">${title}</h2>
    <p class="mt-2 text-lg text-muted">${intro}</p>
    <input data-pw type="password" class="mt-4 w-full min-h-[52px] rounded-xl border-2 border-line px-4 text-lg" placeholder="Your safe-copy password">
    <p data-msg class="mt-3 text-base text-red-700 hidden"></p>
    <div class="mt-6 flex gap-3">
      <button data-cancel class="flex-1 min-h-[52px] rounded-xl border-2 border-line text-lg font-semibold text-ink hover:bg-canvas transition">Cancel</button>
      <button data-go class="flex-1 min-h-[52px] rounded-xl bg-brand-700 text-white text-lg font-semibold hover:bg-brand-800 transition">${action}</button>
    </div>`);
  const pw = o.querySelector("[data-pw]");
  const msg = o.querySelector("[data-msg]");
  o.querySelector("[data-cancel]").addEventListener("click", () => o.remove());
  o.querySelector("[data-go]").addEventListener("click", async () => {
    const v = pw.value.trim();
    if (v.length < 4) {
      msg.textContent = "Please choose a password (at least 4 characters).";
      msg.classList.remove("hidden");
      return;
    }
    const btn = o.querySelector("[data-go]");
    btn.disabled = true;
    btn.textContent = "Working…";
    try {
      await run(v);
      o.remove();
    } catch (e) {
      msg.textContent = String(e).replace(/^Error:\s*/, "");
      msg.classList.remove("hidden");
      btn.disabled = false;
      btn.textContent = action;
    }
  });
}

function openBackupEnable() {
  backupPasswordModal({
    title: "Keep a safe copy",
    intro: "Choose a password for your safe copy. It's different from your 24 words. Write it down too — we can't reset it for you.",
    action: "Turn on safe copy",
    run: async (pw) => {
      if (DEMO || !invoke) return;
      await invoke("backup_enable", { password: pw });
      loadBackupStatus();
    },
  });
}

function openBackupRestore() {
  backupPasswordModal({
    title: "Bring back your memories",
    intro: "Enter your safe-copy password to bring all your memories back onto this computer.",
    action: "Bring them back",
    run: async (pw) => {
      if (DEMO || !invoke) return;
      await invoke("backup_restore", { password: pw });
      await refresh();
      loadBackupStatus();
    },
  });
}

on("#backup-toggle", "click", async () => {
  let meta = { on: false };
  if (!DEMO && invoke) {
    try {
      meta = await invoke("backup_status");
    } catch (_) {}
  }
  if (meta && meta.on) {
    if (!DEMO && invoke) {
      try {
        await invoke("backup_now");
        loadBackupStatus();
      } catch (_) {}
    }
  } else {
    openBackupEnable();
  }
});
on("#backup-restore-btn", "click", openBackupRestore);

// ---------- bring your memories in (import from other AI systems) ----------
const DEMO_IMPORT_PREVIEW = { total: 6, by_role: [["rule", 4], ["memory", 2]], items: [] };
const pluralWord = (w, c) => (c === 1 ? w : w === "memory" ? "memories" : w + "s");

function importResultHtml(res) {
  const extra =
    (res.skipped
      ? `${res.skipped} ${res.skipped === 1 ? "was" : "were"} already in your vault`
      : "") +
    (res.merged
      ? `${res.skipped ? ", and " : ""}${res.merged} near-duplicate${res.merged === 1 ? " was" : "s were"} merged`
      : "");
  return `<div class="rounded-xl border-2 border-brand-200 bg-brand-50 p-4">
      <p class="text-lg font-semibold text-brand-800">Brought in ${res.added} ${res.added === 1 ? "memory" : "memories"}.</p>
      ${extra ? `<p class="mt-1 text-base text-ink">${extra}.</p>` : ""}
    </div>`;
}

// Render a preview into `host` with an Import button that commits it through the existing engine.
function reviewAndImport(label, preview, host) {
  const n = preview.total || 0;
  if (n === 0) {
    host.innerHTML = `<p class="text-base text-muted">No memories found there.</p>`;
    return;
  }
  const roles = (preview.by_role || []).map(([r, c]) => `${c} ${pluralWord(r, c)}`).join(" · ");
  host.innerHTML = `
    <div class="rounded-xl border-2 border-line p-4">
      <div class="flex items-center justify-between">
        <span class="text-lg font-semibold text-ink">${escapeHtml(label)}</span>
        <span class="text-lg font-bold text-brand-700">${n} found</span>
      </div>
      ${roles ? `<p class="mt-1 text-base text-muted">${roles}</p>` : ""}
      <button data-do class="mt-3 min-h-[48px] w-full rounded-xl bg-brand-700 text-white text-base font-semibold hover:bg-brand-800 transition">Import ${n}</button>
    </div>`;
  host.querySelector("[data-do]").addEventListener("click", async (ev) => {
    const b = ev.currentTarget;
    b.disabled = true;
    b.textContent = "Importing…";
    let res = { added: n, skipped: 0, merged: 0, total: n };
    if (!DEMO && invoke) {
      try {
        res = await invoke("import_commit", { items: preview.items });
      } catch (e) {
        host.innerHTML += `<p class="mt-2 text-base text-red-700">${escapeHtml(String(e))}</p>`;
        return;
      }
    }
    host.innerHTML = importResultHtml(res);
    if (typeof refresh === "function") refresh();
  });
}

async function openImport() {
  const o = modalShell(`
    <h2 class="text-2xl font-bold text-ink">Bring your memories in</h2>
    <p class="mt-2 text-base text-muted">Pull in the memory you built up in other AI tools — deduplicated and tidied automatically. Everything stays on this computer; nothing is uploaded.</p>
    <div class="mt-4">
      <h3 class="text-sm font-semibold uppercase tracking-wide text-muted">On this Mac</h3>
      <div data-mac class="mt-2 space-y-2"><p class="text-base text-muted">Looking…</p></div>
    </div>
    <div class="mt-5">
      <h3 class="text-sm font-semibold uppercase tracking-wide text-muted">Bring in anything else</h3>
      <div class="mt-2 flex flex-wrap gap-2">
        <button data-pick-folder class="min-h-[48px] rounded-xl border-2 border-line px-4 text-base font-semibold text-ink hover:bg-canvas transition">Choose a folder…</button>
        <button data-pick-file class="min-h-[48px] rounded-xl border-2 border-line px-4 text-base font-semibold text-ink hover:bg-canvas transition">Choose a file…</button>
      </div>
      <textarea data-paste rows="3" class="mt-2 w-full rounded-xl border-2 border-line p-3 text-base" placeholder="…or paste your saved memory here — one fact per line"></textarea>
      <button data-paste-go class="min-h-[44px] text-base font-semibold text-brand-700 hover:text-brand-800 transition">Bring in pasted text</button>
      <div data-other class="mt-2"></div>
    </div>
    <div class="mt-6"><button data-close class="min-h-[48px] w-full rounded-xl border-2 border-line text-lg font-semibold text-ink hover:bg-canvas transition">Close</button></div>`);
  o.querySelector("[data-close]").addEventListener("click", () => o.remove());
  const other = o.querySelector("[data-other]");

  // 1. Auto-detect the common systems on this Mac.
  const MAC_SOURCES = [
    { id: "claude-code", label: "Claude Code" },
    { id: "coding-agents", label: "Cursor, Codex, Copilot & co." },
    { id: "obsidian", label: "Obsidian" },
  ];
  const macWrap = o.querySelector("[data-mac]");
  macWrap.innerHTML = "";
  let anyFound = false;
  for (const src of MAC_SOURCES) {
    let pv = { total: 0 };
    if (DEMO) {
      pv = src.id === "claude-code" ? DEMO_IMPORT_PREVIEW : { total: 0 };
    } else if (invoke) {
      try {
        pv = await invoke("import_preview", { source: src.id });
      } catch (_) {
        pv = { total: 0 };
      }
    }
    if ((pv.total || 0) > 0) {
      anyFound = true;
      const host = document.createElement("div");
      macWrap.appendChild(host);
      reviewAndImport(src.label, pv, host);
    }
  }
  if (!anyFound) {
    macWrap.innerHTML = `<p class="text-base text-muted">Nothing detected automatically — bring it in with the options below.</p>`;
  }

  // 2. Folder / file picker (native dialog → Rust reads the path).
  const pick = async (directory) => {
    const dlg = window.__TAURI__ && window.__TAURI__.dialog;
    if (!dlg || !invoke) {
      other.innerHTML = `<p class="text-base text-muted">Picking files works in the installed Keepsake app.</p>`;
      return;
    }
    const path = await dlg.open({ directory, multiple: false });
    if (!path) return;
    other.innerHTML = `<p class="text-base text-muted">Reading…</p>`;
    try {
      const pv = await invoke("import_path", { path });
      const label = String(path).split("/").filter(Boolean).pop() || "Selection";
      reviewAndImport(label, pv, other);
    } catch (e) {
      other.innerHTML = `<p class="text-base text-red-700">${escapeHtml(String(e))}</p>`;
    }
  };
  o.querySelector("[data-pick-folder]").addEventListener("click", () => pick(true));
  o.querySelector("[data-pick-file]").addEventListener("click", () => pick(false));

  // 3. Paste box.
  o.querySelector("[data-paste-go]").addEventListener("click", async () => {
    const text = o.querySelector("[data-paste]").value;
    if (!text.trim()) return;
    let pv;
    if (!DEMO && invoke) {
      try {
        pv = await invoke("import_paste", { text });
      } catch (e) {
        other.innerHTML = `<p class="text-base text-red-700">${escapeHtml(String(e))}</p>`;
        return;
      }
    } else {
      const lines = text
        .split("\n")
        .map((s) => s.replace(/^[-*•\s]+/, "").trim())
        .filter((s) => s.length >= 3);
      pv = { total: lines.length, by_role: [["memory", lines.length]], items: [] };
    }
    reviewAndImport("Pasted text", pv, other);
  });
}

on("#import-open", "click", openImport);

// Auto-save a fresh copy after a change (no-op if backup is off or no password is held this session).
function autoBackup() {
  if (!DEMO && invoke) invoke("backup_now").catch(() => {});
}

// "Start fresh" needs a deliberate press-and-hold — easy for a senior, hard to trigger by accident.
(function wireResetHold() {
  const btn = $("#reset-hold");
  if (!btn) return;
  const fill = $("#reset-hold-fill");
  const HOLD_MS = 1600;
  let timer, raf, start;
  const stop = () => {
    clearTimeout(timer);
    cancelAnimationFrame(raf);
    if (fill) fill.style.width = "0%";
  };
  const tick = () => {
    const p = Math.min(1, (performance.now() - start) / HOLD_MS);
    if (fill) fill.style.width = p * 100 + "%";
    if (p < 1) raf = requestAnimationFrame(tick);
  };
  btn.addEventListener("pointerdown", (e) => {
    e.preventDefault();
    start = performance.now();
    raf = requestAnimationFrame(tick);
    timer = setTimeout(() => {
      stop();
      doReset();
    }, HOLD_MS);
  });
  ["pointerup", "pointerleave", "pointercancel"].forEach((ev) =>
    btn.addEventListener(ev, stop),
  );
})();

async function doReset() {
  if (DEMO || !invoke) {
    await startOnboarding();
    return;
  }
  try {
    await invoke("reset_vault");
    await startOnboarding();
  } catch (_) {
    const err = $("#reset-error");
    if (err) {
      err.textContent = "Sorry — that didn't work just now. Please try again.";
      err.classList.remove("hidden");
    }
  }
}

function debounce(fn, ms) {
  let t;
  return (...a) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...a), ms);
  };
}

// ---------- demo data (browser preview only) ----------
const DEMO_MEMORIES = (() => {
  const day = 86400;
  const now = Math.floor(Date.now() / 1000);
  return [
    {
      id: "a1",
      created_at: now - 3600,
      text: "Dentist appointment: Dr. Berger\nMonday, July 3 at 2:00 PM — practice on the market square",
      source: "mcp:claude",
    },
    {
      id: "b2",
      created_at: now - 7200,
      text: "Idea for a weekend project\nBuild a minimalist, privacy-first habit tracker.",
      source: "desktop",
    },
    {
      id: "c3",
      created_at: now - day - 3600,
      text: "Berlin trip\nArrive Friday, July 4 — return Sunday, July 6. Hotel still to book.",
      source: "proxy:openai:gpt-4",
    },
    {
      id: "d4",
      created_at: now - 2 * day,
      text: "Password hint for my notebook\nThird line, second word — you know the one.",
    },
  ];
})();

// ---------- self-update (manual only — the app never checks on its own) ----------
// Triggered solely by the "Check for updates" button in Settings, so the only network call the
// app ever makes is one the user explicitly asked for. Keeps the no-telemetry promise honest.
async function runUpdateCheck() {
  const status = $("#update-status");
  const btn = $("#update-check-btn");
  if (DEMO || !invoke) {
    if (status) {
      status.textContent = "You're up to date.";
      status.classList.remove("hidden");
    }
    return;
  }
  if (btn) {
    btn.disabled = true;
    btn.textContent = "Checking…";
  }
  try {
    const version = await invoke("check_update");
    if (version) {
      if (status) {
        status.textContent = "Update " + version + " is available.";
        status.className = "mt-2 text-base font-medium text-brand-700";
      }
      showUpdateBanner(version);
    } else if (status) {
      status.textContent = "You're up to date.";
      status.className = "mt-2 text-base font-medium text-muted";
    }
  } catch (_) {
    if (status) {
      status.textContent = "Couldn't check right now — check your internet and try again.";
      status.className = "mt-2 text-base font-medium text-red-700";
    }
  } finally {
    if (status) status.classList.remove("hidden");
    if (btn) {
      btn.disabled = false;
      btn.textContent = "Check for updates";
    }
  }
}

function showUpdateBanner(version) {
  if (document.getElementById("update-banner")) return;
  const bar = document.createElement("div");
  bar.id = "update-banner";
  bar.className =
    "fixed top-0 inset-x-0 z-50 flex items-center justify-center gap-3 bg-brand-600 text-white text-sm py-2 px-4 shadow-md";
  bar.innerHTML =
    `<span>Update <b>${escapeHtml(version)}</b> is available.</span>` +
    `<button id="update-now" class="rounded-md bg-surface text-brand-700 hover:bg-brand-50 px-3 py-1 font-medium transition">Update now</button>` +
    `<button id="update-later" class="text-white text-xs hover:underline">Later</button>`;
  document.body.appendChild(bar);
  $("#update-now").addEventListener("click", async () => {
    const btn = $("#update-now");
    btn.textContent = "Downloading & installing…";
    btn.disabled = true;
    try {
      // On success the app downloads, verifies the signature, installs, and restarts.
      await invoke("install_update");
    } catch (_) {
      btn.textContent = "Failed — try again later";
      btn.disabled = false;
    }
  });
  $("#update-later").addEventListener("click", () => bar.remove());
}

on("#update-check-btn", "click", runUpdateCheck);

// ---------- boot ----------
(async () => {
  if (DEMO) {
    // Demo/preview affordance: deep-link a screen via the URL hash (used for docs).
    if (location.hash === "#onboarding") {
      startOnboarding();
      return;
    }
    enterShell();
    if (location.hash === "#search") {
      navTo("suchen");
      $("#search-input").value = "Berlin";
      doSearch();
    }
    return;
  }
  // No automatic update check on startup — updates are checked only when the user presses the
  // "Check for updates" button in Settings, so the app makes no network call it wasn't asked to.
  try {
    const isLocked = await invoke("locked");
    if (!isLocked) {
      enterShell();
      return;
    }
    const exists = await invoke("vault_exists");
    if (exists) {
      show("unlock");
    } else {
      await startOnboarding();
    }
  } catch (_) {
    show("unlock");
  }
})();
