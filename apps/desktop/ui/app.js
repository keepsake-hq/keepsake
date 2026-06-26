// Keepsake desktop frontend. Talks to the Rust core via Tauri commands.
// When opened outside the app (a plain browser preview) it falls back to demo data
// so the design can be reviewed without the backend.

const core = window.__TAURI__ && window.__TAURI__.core;
const invoke = core ? (cmd, args) => core.invoke(cmd, args) : null;
const DEMO = !invoke;

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

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
    <div data-card="${mem.id}" data-text="${escapeHtml(title)}" class="group bg-white border border-neutral-200/80 rounded-2xl px-4 py-3.5 flex items-start gap-3.5 hover:shadow-sm transition">
      <span class="w-10 h-10 rounded-xl ${palette} flex items-center justify-center shrink-0">${icon}</span>
      <div class="min-w-0 flex-1">
        <div class="flex items-start justify-between gap-3">
          <div class="font-medium text-neutral-900 text-[15px] truncate">${escapeHtml(title)}</div>
          <div class="flex items-center gap-2 shrink-0">
            <span class="text-xs text-neutral-400 tabular-nums">${fmtTime(mem.created_at)}</span>
            <button data-forget="${mem.id}" aria-label="Remove this memory" class="shrink-0 inline-flex items-center justify-center w-11 h-11 -mr-1 rounded-xl text-neutral-500 hover:bg-red-50 hover:text-red-600 transition">${ICON_TRASH}</button>
          </div>
        </div>
        ${desc ? `<div class="text-sm text-neutral-500 mt-0.5 line-clamp-2">${escapeHtml(desc)}</div>` : ""}
        <div class="mt-2 flex items-center gap-2.5 text-xs text-neutral-400">
          <span class="inline-flex items-center gap-1.5">${ICON_LOCK_S} End-to-end encrypted</span>
          ${src ? `<span class="text-neutral-300">·</span><span>${escapeHtml(src)}</span>` : ""}
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
          <span class="absolute -left-[1.6rem] top-5 w-2.5 h-2.5 rounded-full ${isToday ? "bg-brand-500" : "bg-neutral-300"} ring-4 ring-canvas"></span>
          ${cardHtml(m, TILES[hashIndex(m.id, TILES.length)])}
        </div>`,
        )
        .join("");
      return `
      <div class="${gi > 0 ? "mt-6" : ""}">
        <div class="text-sm font-semibold ${isToday ? "text-brand-600" : "text-neutral-700"} mb-3">${g.label}</div>
        <div class="relative border-l border-neutral-200 pl-6 space-y-3">${cards}</div>
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
    <div class="w-full max-w-md rounded-2xl bg-white shadow-2xl p-6">
      <h2 class="text-2xl font-bold text-neutral-900">Remove this memory?</h2>
      <div class="mt-4 rounded-xl bg-neutral-50 border border-neutral-200 px-4 py-3 text-lg text-neutral-700">${escapeHtml(text)}</div>
      <p class="mt-4 text-lg text-neutral-600">You'll have a few seconds to undo this.</p>
      <div class="mt-6 flex gap-3">
        <button data-keep class="flex-1 min-h-[52px] rounded-xl border-2 border-neutral-300 px-4 py-3 text-lg font-semibold text-neutral-800 hover:bg-neutral-50 transition">Keep it</button>
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
      <button data-undo class="shrink-0 min-h-[44px] rounded-xl bg-white/15 hover:bg-white/25 px-4 py-2 text-lg font-semibold transition">Undo</button>
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
    <li class="bg-white border border-neutral-200/80 rounded-2xl px-5 py-4 flex items-center gap-4 hover:shadow-sm transition">
      <span class="w-12 h-12 rounded-xl ${palette} flex items-center justify-center shrink-0">${icon}</span>
      <div class="min-w-0 flex-1">
        <div class="text-lg font-semibold text-neutral-900 truncate">${escapeHtml(oneLine)}</div>
        <div class="mt-1.5 flex items-center gap-2">
          <span class="inline-flex items-center gap-1.5 rounded-md bg-brand-50 px-2 py-0.5 text-sm font-medium text-brand-800">${ICON_LOCK_S} Only on your device</span>
          ${sourceLabel(h.source) ? `<span class="text-sm text-neutral-500">· ${escapeHtml(sourceLabel(h.source))}</span>` : ""}
        </div>
      </div>
      <svg class="w-5 h-5 text-neutral-300 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m9 18 6-6-6-6"/></svg>
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
      <p class="text-xl font-semibold text-neutral-800">I couldn't find anything for that.</p>
      <p class="mt-2 text-lg text-neutral-600">Try simpler words — like just a name or a place.</p>
      <button id="save-as-memory" class="mt-5 inline-flex min-h-[48px] items-center rounded-xl bg-brand-700 px-5 text-lg font-semibold text-white hover:bg-brand-800 transition">Save “${escapeHtml(q)}” as a new memory</button>
    </div>
    ${recent.length ? `<div class="mt-2"><p class="text-base font-semibold text-neutral-700 mb-3">Your most recent memories:</p><ul class="space-y-3">${recent.map(renderHit).join("")}</ul></div>` : ""}`;
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
  if (DEMO) {
    phrase =
      "apple river cloud stone meadow lamp window quiet garden silver paper ocean bridge candle forest gentle sunrise pocket mirror violet harbor cotton ladder compass";
  } else {
    try {
      phrase = await invoke("generate_seed");
    } catch (e) {
      $("#onboard-error").textContent = String(e);
      $("#onboard-error").classList.remove("hidden");
      return;
    }
  }
  window.__SEED__ = phrase;
  const words = phrase.split(/\s+/);
  $("#seed-grid").innerHTML = words
    .map(
      (w, i) => `
      <div class="flex items-center gap-3 rounded-xl border border-neutral-200 bg-neutral-50/60 px-3.5 py-3">
        <span class="text-xs text-neutral-400 w-5 tabular-nums text-right">${i + 1}</span>
        <span class="text-sm font-medium text-neutral-800">${w}</span>
      </div>`,
    )
    .join("");
  show("onboarding");
}

// Run unlock with a loading overlay; message depends on whether the model is local yet.
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
  const mnemonic = $("#seed-input").value.trim();
  if (!mnemonic) return;
  const btn = $("#unlock-btn");
  btn.disabled = true;
  $("#unlock-error").classList.add("hidden");
  try {
    await runUnlock(mnemonic);
    $("#seed-input").value = "";
  } catch (e) {
    $("#unlock-error").textContent =
      "Those 24 words didn't open your memories. Check the spelling, or tap “I can't find my 24 words” below.";
    $("#unlock-error").classList.remove("hidden");
  } finally {
    btn.disabled = false;
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
}

// ---------- sync server setting ----------
function paintSyncOptions(mode) {
  $$(".sync-opt").forEach((b) => {
    const active = b.dataset.sync === mode;
    b.classList.toggle("border-brand-500", active);
    b.classList.toggle("bg-brand-50", active);
    b.classList.toggle("text-brand-700", active);
    b.classList.toggle("border-neutral-200", !active);
    b.classList.toggle("text-neutral-600", !active);
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
    b.classList.toggle("text-neutral-600", !active);
  });
  $$(".view").forEach((s) =>
    s.classList.toggle("hidden", s.getAttribute("data-screen") !== view),
  );
  if (view === "suchen") setTimeout(() => $("#search-input").focus(), 30);
}

// ---------- wire events ----------
$("#seed-confirm").addEventListener("change", (e) => {
  $("#onboard-continue").disabled = !e.target.checked;
});
$("#onboard-continue").addEventListener("click", doOnboardContinue);
$("#unlock-btn").addEventListener("click", doUnlock);
$("#seed-input").addEventListener("keydown", (e) => {
  if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) doUnlock();
});
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
          `<div class="flex items-center gap-2 rounded-lg border border-neutral-200 bg-neutral-50 px-3 py-2"><span class="w-5 text-right text-sm tabular-nums text-neutral-400">${i + 1}</span><span class="text-base font-medium text-neutral-800">${escapeHtml(w)}</span></div>`,
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

// ---------- self-update ----------
async function checkForUpdate() {
  if (DEMO || !invoke) return;
  try {
    const version = await invoke("check_update");
    if (version) showUpdateBanner(version);
  } catch (_) {}
}

function showUpdateBanner(version) {
  if (document.getElementById("update-banner")) return;
  const bar = document.createElement("div");
  bar.id = "update-banner";
  bar.className =
    "fixed top-0 inset-x-0 z-50 flex items-center justify-center gap-3 bg-brand-600 text-white text-sm py-2 px-4 shadow-md";
  bar.innerHTML =
    `<span>Update <b>${escapeHtml(version)}</b> ist verfügbar.</span>` +
    `<button id="update-now" class="rounded-md bg-white text-brand-700 hover:bg-brand-50 px-3 py-1 font-medium transition">Jetzt aktualisieren</button>` +
    `<button id="update-later" class="text-white text-xs hover:underline">Später</button>`;
  document.body.appendChild(bar);
  $("#update-now").addEventListener("click", async () => {
    const btn = $("#update-now");
    btn.textContent = "Lädt & installiert…";
    btn.disabled = true;
    try {
      // On success the app downloads, verifies the signature, installs, and restarts.
      await invoke("install_update");
    } catch (_) {
      btn.textContent = "Fehler — später erneut";
      btn.disabled = false;
    }
  });
  $("#update-later").addEventListener("click", () => bar.remove());
}

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
  checkForUpdate(); // fire-and-forget: show a banner if a signed update is available
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
