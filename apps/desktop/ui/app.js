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

function show(id) {
  ["onboarding", "unlock"].forEach((s) =>
    $("#" + s).classList.toggle("hidden", s !== id),
  );
  const authVisible = id === "onboarding" || id === "unlock";
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
    <div class="group bg-white border border-neutral-200/80 rounded-2xl px-4 py-3.5 flex items-start gap-3.5 hover:shadow-sm transition">
      <span class="w-10 h-10 rounded-xl ${palette} flex items-center justify-center shrink-0">${icon}</span>
      <div class="min-w-0 flex-1">
        <div class="flex items-start justify-between gap-3">
          <div class="font-medium text-neutral-900 text-[15px] truncate">${escapeHtml(title)}</div>
          <div class="flex items-center gap-2 shrink-0">
            <span class="text-xs text-neutral-400 tabular-nums">${fmtTime(mem.created_at)}</span>
            <button data-forget="${mem.id}" title="Forget" class="opacity-0 group-hover:opacity-100 text-neutral-300 hover:text-red-500 transition">${ICON_TRASH}</button>
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
  $("#start-empty").classList.toggle("hidden", memories.length > 0);
  $("#start-count").textContent = memories.length ? countLabel(SETTINGS_COUNT) : "";
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
    $("#set-profile").textContent = st.profile;
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

async function doForget(id) {
  if (DEMO) return;
  try {
    await invoke("forget", { id });
    await refresh();
    if ($("#search-input").value.trim()) doSearch();
  } catch (_) {}
}

async function doSearch() {
  const q = $("#search-input").value.trim();
  $("#search-clear").classList.toggle("hidden", !q);
  if (!q) {
    $("#search-results").innerHTML = "";
    $("#search-hint").classList.remove("hidden");
    $("#search-empty").classList.add("hidden");
    return;
  }
  $("#search-hint").classList.add("hidden");
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
  $("#search-empty").classList.toggle("hidden", hits.length > 0);
  $("#search-results").innerHTML = hits
    .map((h) => {
      const palette = TILES[hashIndex(h.id, TILES.length)];
      const icon = TRAVEL_RE.test(h.text) ? ICON_PLANE : ICON_NOTE;
      const oneLine = h.text.replace(/\s*\n\s*/g, " — ");
      return `
      <li class="bg-white border border-neutral-200/80 rounded-2xl px-5 py-4 flex items-center gap-4 hover:shadow-sm transition">
        <span class="w-12 h-12 rounded-xl ${palette} flex items-center justify-center shrink-0">${icon}</span>
        <div class="min-w-0 flex-1">
          <div class="text-[15px] font-semibold text-neutral-900 truncate">${escapeHtml(oneLine)}</div>
          <div class="mt-1.5 flex items-center gap-2">
            <span class="inline-flex items-center gap-1.5 rounded-md bg-brand-50 px-2 py-0.5 text-xs font-medium text-brand-700">${ICON_LOCK_S} Found locally via Nomic</span>
            ${sourceLabel(h.source) ? `<span class="text-xs text-neutral-400">· ${escapeHtml(sourceLabel(h.source))}</span>` : ""}
          </div>
        </div>
        <svg class="w-5 h-5 text-neutral-300 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m9 18 6-6-6-6"/></svg>
      </li>`;
    })
    .join("");
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
    $("#unlock-error").textContent = String(e);
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
