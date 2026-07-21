// app.js — bootstrap. Fetches /api/meta once, opens EventSource("/stream"),
// wires the "chain"/"status" events (CONTRACT.md §4) into the two renderers
// and the status bar. In `?demo=1` mode, meta and the event source come from
// demo.js's synthetic generator instead — everything downstream is identical.

import { createBeeswarm } from "./beeswarm.js";
import { createPropagation } from "./propagation.js";

const DEMO_MODE = new URLSearchParams(location.search).get("demo") === "1";

function renderStatusBar(nodes) {
  const bar = document.getElementById("status-bar");
  bar.innerHTML = "";
  const chips = new Map();
  for (const node of nodes) {
    const chip = document.createElement("div");
    chip.className = "status-chip status-unknown";

    const dot = document.createElement("span");
    dot.className = "status-dot";

    const name = document.createElement("span");
    name.className = "status-name";
    name.textContent = node.name;

    const rate = document.createElement("span");
    rate.className = "status-rate";
    rate.textContent = "—";

    chip.append(dot, name, rate);
    bar.appendChild(chip);
    chips.set(node.name, chip);
  }
  return chips;
}

function applyStatus(chips, status) {
  const chip = chips.get(status.node);
  if (!chip) return;
  chip.classList.remove("status-connected", "status-reconnecting", "status-down", "status-unknown");
  chip.classList.add(`status-${status.state}`);
  const rate = chip.querySelector(".status-rate");
  if (rate && typeof status.events_per_sec === "number") {
    rate.textContent = `${status.events_per_sec.toFixed(1)}/s`;
  }
}

// Wraps a real EventSource("/stream") and surfaces connection loss via the
// #conn-banner element. EventSource itself retries the connection
// automatically on drop (readyState goes to CONNECTING, then back to OPEN);
// we just reflect that state so the user isn't left guessing.
function createLiveSource() {
  const es = new EventSource("/stream");
  const banner = document.getElementById("conn-banner");
  es.addEventListener("open", () => {
    banner.hidden = true;
  });
  es.addEventListener("error", () => {
    if (es.readyState !== EventSource.OPEN) banner.hidden = false;
  });
  return es;
}

async function fetchMeta() {
  const res = await fetch("/api/meta");
  if (!res.ok) throw new Error(`GET /api/meta failed: ${res.status}`);
  return res.json();
}

async function fetchHistory() {
  const res = await fetch("/api/history");
  if (!res.ok) throw new Error(`GET /api/history failed: ${res.status}`);
  return res.json();
}

// Composite key to de-dup the small overlap between the history snapshot and
// the live stream during startup (an event can appear in both).
function eventKey(e) {
  return `${e.node}|${e.topic}|${e.slot}|${e.id ?? ""}|${e.validator_id ?? ""}|${e.arrival_ms}`;
}

function wireWindowControl(meta, renderers) {
  const input = document.getElementById("window-slots");
  if (!input) return;
  input.value = String(meta.window_slots || 30);
  const apply = () => {
    let n = parseInt(input.value, 10);
    if (!Number.isFinite(n)) return;
    n = Math.min(500, Math.max(1, n));
    if (String(n) !== input.value) input.value = String(n);
    for (const r of renderers) r.setWindowSlots(n);
  };
  input.addEventListener("input", apply);
  input.addEventListener("change", apply);
}

async function boot() {
  const modeIndicator = document.getElementById("mode-indicator");
  let meta;
  let source;

  if (DEMO_MODE) {
    const demo = await import("./demo.js");
    meta = demo.createDemoMeta();
    source = demo.createDemoSource(meta);
    modeIndicator.textContent = "demo mode — synthetic data (?demo=1)";
  } else {
    meta = await fetchMeta();
    source = createLiveSource();
  }

  const chips = renderStatusBar(meta.nodes);

  const beeswarm = createBeeswarm({
    canvas: document.getElementById("beeswarm-canvas"),
    legendEl: document.getElementById("beeswarm-legend"),
    noteEl: document.getElementById("beeswarm-note"),
    meta,
  });

  const propagation = createPropagation({
    toggleEl: document.getElementById("propagation-toggle"),
    canvas: document.getElementById("propagation-canvas"),
    legendEl: document.getElementById("propagation-legend"),
    noteEl: document.getElementById("propagation-note"),
    meta,
  });

  wireWindowControl(meta, [beeswarm, propagation]);

  const ingest = (ev) => {
    beeswarm.addEvent(ev);
    propagation.addEvent(ev);
  };

  // Startup backfill (live mode only): open the stream first and buffer, so no
  // live event is dropped in the gap while /api/history is fetched; then seed
  // history, flush the buffer, and de-dup the overlap. Demo mode has no
  // history endpoint and streams synthetic data straight through.
  const backfilling = !DEMO_MODE;
  const seen = new Set();
  const liveBuffer = [];
  let loading = backfilling;

  const ingestDeduped = (ev) => {
    const key = eventKey(ev);
    if (seen.has(key)) return;
    seen.add(key);
    ingest(ev);
  };

  source.addEventListener("chain", (evt) => {
    let ev;
    try {
      ev = JSON.parse(evt.data);
    } catch {
      return; // malformed frame; drop silently, never fatal to the page
    }
    if (loading) {
      liveBuffer.push(ev);
      return;
    }
    ingest(ev);
  });

  source.addEventListener("status", (evt) => {
    let status;
    try {
      status = JSON.parse(evt.data);
    } catch {
      return;
    }
    applyStatus(chips, status);
  });

  if (backfilling) {
    try {
      const history = await fetchHistory();
      if (Array.isArray(history.status)) {
        history.status.forEach((s) => applyStatus(chips, s));
      }
      if (Array.isArray(history.events)) {
        history.events.forEach(ingestDeduped);
      }
    } catch (err) {
      console.warn("history backfill failed; starting with an empty view", err);
    }
    // Flush live events that arrived during the fetch, de-duping the overlap,
    // then switch to direct ingest (the overlap window is over).
    liveBuffer.forEach(ingestDeduped);
    liveBuffer.length = 0;
    loading = false;
    seen.clear();
  }
}

boot().catch((err) => {
  console.error("event-monitor failed to start", err);
  const main = document.querySelector("main");
  if (main) {
    const banner = document.createElement("p");
    banner.className = "fatal-error";
    banner.textContent = `Failed to start: ${err.message}`;
    main.prepend(banner);
  }
});
