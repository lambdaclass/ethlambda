// propagation.js — bottom panel: propagation delta as a rolling per-node
// beeswarm. See CONTRACT.md §6. Groups NormalizedEvents (§3) by their `id`
// field per topic; each point is one node's arrival delay relative to the
// first node to see that id, on a fixed 0…ms_per_slot x-axis. A delta beyond
// one slot saturates at the right edge and turns magenta.
//
// Canvas scaffolding intentionally mirrors beeswarm.js (lanes, jitter, fade,
// rAF loop) rather than sharing a core, to keep each panel independently
// readable; keep the two in sync when changing the visual language.

const TOPICS = ["block", "aggregate", "head"];
const MAX_IDS_PER_TOPIC = 400;

const LANE_HEIGHT = 40;
const TOP_MARGIN = 14;
const BOTTOM_MARGIN = 30;
const LEFT_MARGIN = 92;
const RIGHT_MARGIN = 16;
const JITTER_RANGE = 11; // px, +/- around the lane center
const DOT_RADIUS = 2.6;

// Fade older slots non-linearly: the newest slot is fully opaque and each
// older slot drops geometrically toward a faint floor (front-loaded, so
// recent ids pop). Kept identical to beeswarm.js's fade for a consistent feel.
const FADE_DECAY = 0.7;
const FADE_FLOOR = 0.15;

// Deterministic pseudo-random in [-1, 1) from a string seed, so a dot's
// jitter stays put across animation frames instead of flickering.
function hashJitter(seed) {
  let h = 2166136261;
  for (let i = 0; i < seed.length; i++) {
    h ^= seed.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  h >>>= 0;
  return ((h % 2000) / 1000) - 1;
}

function readTheme() {
  const cs = getComputedStyle(document.documentElement);
  const get = (name, fallback) => {
    const v = cs.getPropertyValue(name);
    return v && v.trim() ? v.trim() : fallback;
  };
  return {
    grid: get("--grid", "#d0d3d9"),
    text: get("--muted", "#6b7280"),
    laneAlt: get("--lane-alt", "rgba(0,0,0,0.04)"),
    first: get("--prop-first", "#7048e8"),
    normal: get("--prop-normal", "#1098ad"),
    over: get("--prop-over", "#e64980"),
  };
}

/**
 * @param {{toggleEl: Element, canvas: HTMLCanvasElement, legendEl?: Element, noteEl?: Element, meta: object}} opts
 */
export function createPropagation({ toggleEl, canvas, legendEl, noteEl, meta }) {
  const ctx = canvas.getContext("2d");
  const nodeNames = meta.nodes.map((n) => n.name);
  const laneIndex = new Map(nodeNames.map((name, i) => [name, i]));

  // topic -> Map<id, { slot, arrivals: Map<node, arrival_ms> }>
  const groups = new Map(TOPICS.map((t) => [t, new Map()]));
  // topic -> [id, ...] in first-seen order, for the per-topic id cap.
  const insertionOrder = new Map(TOPICS.map((t) => [t, []]));

  let selectedTopic = "block";
  let windowSlots = meta.window_slots || 30;
  const msPerSlot = meta.ms_per_slot || 4000;
  const intervals = meta.intervals_per_slot || 5;

  let maxSlotSeen = 0;
  let theme = readTheme();
  let dpr = window.devicePixelRatio || 1;
  let cssWidth = 0;
  let cssHeight = 0;
  let stopped = false;

  function resize() {
    const rect = canvas.parentElement.getBoundingClientRect();
    cssWidth = Math.max(320, Math.floor(rect.width));
    cssHeight = TOP_MARGIN + BOTTOM_MARGIN + LANE_HEIGHT * Math.max(1, nodeNames.length);
    dpr = window.devicePixelRatio || 1;
    canvas.style.width = `${cssWidth}px`;
    canvas.style.height = `${cssHeight}px`;
    canvas.width = Math.round(cssWidth * dpr);
    canvas.height = Math.round(cssHeight * dpr);
  }

  let ro = null;
  if (typeof ResizeObserver !== "undefined") {
    ro = new ResizeObserver(() => resize());
    ro.observe(canvas.parentElement);
  } else {
    window.addEventListener("resize", resize);
  }

  let mq = null;
  const onThemeChange = () => {
    theme = readTheme();
  };
  if (window.matchMedia) {
    mq = window.matchMedia("(prefers-color-scheme: dark)");
    if (mq.addEventListener) mq.addEventListener("change", onThemeChange);
    else if (mq.addListener) mq.addListener(onThemeChange);
  }

  function addEvent(ev) {
    if (!TOPICS.includes(ev.topic)) return;
    if (ev.id == null) return; // ungroupable (e.g. attestation)

    const group = groups.get(ev.topic);
    const order = insertionOrder.get(ev.topic);
    let entry = group.get(ev.id);
    if (!entry) {
      entry = { slot: ev.slot, arrivals: new Map() };
      group.set(ev.id, entry);
      order.push(ev.id);
      if (order.length > MAX_IDS_PER_TOPIC) {
        const dropped = order.shift();
        group.delete(dropped);
      }
    }
    // Keep the earliest arrival per node for this id (first sighting wins).
    const prior = entry.arrivals.get(ev.node);
    if (prior === undefined || ev.arrival_ms < prior) {
      entry.arrivals.set(ev.node, ev.arrival_ms);
    }
    if (ev.slot > maxSlotSeen) maxSlotSeen = ev.slot;
  }

  function xForDelta(deltaMs) {
    const plotWidth = cssWidth - LEFT_MARGIN - RIGHT_MARGIN;
    const clamped = Math.min(Math.max(deltaMs, 0), msPerSlot);
    return LEFT_MARGIN + (clamped / msPerSlot) * plotWidth;
  }

  function laneY(nodeName) {
    const idx = laneIndex.get(nodeName);
    return TOP_MARGIN + idx * LANE_HEIGHT + LANE_HEIGHT / 2;
  }

  function drawFrame(plotBottom) {
    // alternating lane backgrounds
    nodeNames.forEach((_, idx) => {
      if (idx % 2 === 1) {
        ctx.fillStyle = theme.laneAlt;
        ctx.fillRect(
          LEFT_MARGIN,
          TOP_MARGIN + idx * LANE_HEIGHT,
          cssWidth - LEFT_MARGIN - RIGHT_MARGIN,
          LANE_HEIGHT
        );
      }
    });

    // gridlines every ms_per_slot / intervals_per_slot, plus axis labels
    const step = msPerSlot / intervals;
    ctx.strokeStyle = theme.grid;
    ctx.lineWidth = 1;
    ctx.font = "10px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace";
    ctx.fillStyle = theme.text;
    ctx.textAlign = "center";
    ctx.textBaseline = "top";
    for (let ms = 0; ms <= msPerSlot + 0.001; ms += step) {
      const x = xForDelta(ms);
      ctx.beginPath();
      ctx.moveTo(x, TOP_MARGIN);
      ctx.lineTo(x, plotBottom);
      ctx.stroke();
      ctx.fillText(`${Math.round(ms)}`, x, plotBottom + 6);
    }
    ctx.textAlign = "left";
    ctx.fillText("delta ms (from first node)", LEFT_MARGIN, plotBottom + 18);

    // lane labels
    ctx.textAlign = "right";
    ctx.textBaseline = "middle";
    nodeNames.forEach((name) => {
      ctx.fillStyle = theme.text;
      ctx.fillText(name, LEFT_MARGIN - 10, laneY(name));
    });
  }

  function draw() {
    if (cssWidth === 0) return;
    ctx.save();
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, cssWidth, cssHeight);

    const plotBottom = TOP_MARGIN + LANE_HEIGHT * nodeNames.length;
    drawFrame(plotBottom);

    const group = groups.get(selectedTopic);
    let plotted = 0;
    for (const [id, entry] of group) {
      const age = maxSlotSeen - entry.slot;
      if (age >= windowSlots) continue;
      if (entry.arrivals.size === 0) continue;
      const minArrival = Math.min(...entry.arrivals.values());
      const alpha = FADE_FLOOR + (1 - FADE_FLOOR) * Math.pow(FADE_DECAY, age);

      for (const [node, arrival] of entry.arrivals) {
        const y = laneY(node);
        if (y === undefined) continue;
        const delta = arrival - minArrival;
        const x = xForDelta(delta);
        const color = delta === 0 ? theme.first : delta > msPerSlot ? theme.over : theme.normal;
        const jitter = hashJitter(`${id}|${node}`) * JITTER_RANGE;
        ctx.globalAlpha = alpha;
        ctx.fillStyle = color;
        ctx.beginPath();
        ctx.arc(x, y + jitter, DOT_RADIUS, 0, Math.PI * 2);
        ctx.fill();
        plotted++;
      }
    }
    ctx.globalAlpha = 1;

    if (plotted === 0) {
      ctx.fillStyle = theme.text;
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";
      ctx.font = "13px -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif";
      ctx.fillText(
        `Waiting for ${selectedTopic} events…`,
        LEFT_MARGIN + (cssWidth - LEFT_MARGIN - RIGHT_MARGIN) / 2,
        TOP_MARGIN + (LANE_HEIGHT * nodeNames.length) / 2
      );
    }
    ctx.restore();
  }

  // Drop ids that have fully aged out of the window from every topic, so the
  // group maps don't retain stale ids just because they're under the cap.
  function prune() {
    for (const topic of TOPICS) {
      const group = groups.get(topic);
      const order = insertionOrder.get(topic);
      let kept = [];
      for (const id of order) {
        const entry = group.get(id);
        if (entry && maxSlotSeen - entry.slot >= windowSlots) {
          group.delete(id);
        } else if (entry) {
          kept.push(id);
        }
      }
      insertionOrder.set(topic, kept);
    }
  }

  function renderLegend() {
    if (!legendEl) return;
    legendEl.innerHTML = "";
    const items = [
      [theme.first, "first to see"],
      [theme.normal, "lag"],
      [theme.over, "> 1 slot behind"],
    ];
    for (const [color, label] of items) {
      const chip = document.createElement("span");
      chip.className = "legend-item";
      const swatch = document.createElement("span");
      swatch.className = "legend-swatch";
      swatch.style.background = color;
      chip.appendChild(swatch);
      chip.appendChild(document.createTextNode(label));
      legendEl.appendChild(chip);
    }
  }

  function updateNote() {
    if (noteEl) {
      noteEl.textContent =
        `Each dot is one node's delay behind the first node to see an id, ` +
        `over the last ${windowSlots} slots. Fixed 0–${msPerSlot}ms scale.`;
    }
  }

  function buildToggle() {
    toggleEl.innerHTML = "";
    for (const topic of TOPICS) {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "toggle-btn";
      btn.textContent = topic;
      btn.setAttribute("aria-pressed", String(topic === selectedTopic));
      if (topic === selectedTopic) btn.classList.add("toggle-btn-active");
      btn.addEventListener("click", () => {
        if (topic === selectedTopic) return;
        selectedTopic = topic;
        for (const sibling of toggleEl.children) {
          const active = sibling === btn;
          sibling.classList.toggle("toggle-btn-active", active);
          sibling.setAttribute("aria-pressed", String(active));
        }
      });
      toggleEl.appendChild(btn);
    }
  }

  let frameCount = 0;
  function loop() {
    if (stopped) return;
    frameCount++;
    if (frameCount % 60 === 0) prune();
    draw();
    requestAnimationFrame(loop);
  }

  resize();
  buildToggle();
  renderLegend();
  updateNote();
  requestAnimationFrame(loop);

  return {
    addEvent,
    resize,
    setWindowSlots(n) {
      windowSlots = Math.max(1, Math.floor(n));
      updateNote();
    },
    destroy() {
      stopped = true;
      if (ro) ro.disconnect();
      else window.removeEventListener("resize", resize);
      if (mq) {
        if (mq.removeEventListener) mq.removeEventListener("change", onThemeChange);
        else if (mq.removeListener) mq.removeListener(onThemeChange);
      }
    },
  };
}
