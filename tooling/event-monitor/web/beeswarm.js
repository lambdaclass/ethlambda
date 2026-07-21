// beeswarm.js — top panel: rolling per-node beeswarm of arrival offset within
// the slot. See CONTRACT.md §6. Consumes NormalizedEvent objects (§3) for
// topics block/attestation/aggregate; ignores everything else.

const TOPICS = ["block", "attestation", "aggregate"];
const MAX_POINTS_PER_NODE = 2000;

const LANE_HEIGHT = 40;
const TOP_MARGIN = 14;
const BOTTOM_MARGIN = 30;
const LEFT_MARGIN = 92;
const RIGHT_MARGIN = 16;
const JITTER_RANGE = 11; // px, +/- around the lane center
const DOT_RADIUS = 2.6;

// Fade older slots non-linearly: the newest slot is fully opaque and each
// older slot drops geometrically toward a faint floor (front-loaded, so
// recent events pop). opacity = FADE_FLOOR + (1 - FADE_FLOOR) * FADE_DECAY^age,
// e.g. age 0/1/2/3 → ~1.0 / 0.75 / 0.57 / 0.44.
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
    topics: {
      block: get("--topic-block", "#4f8cff"),
      attestation: get("--topic-attestation", "#37b24d"),
      aggregate: get("--topic-aggregate", "#f59f00"),
    },
  };
}

/**
 * @param {{canvas: HTMLCanvasElement, legendEl?: Element, noteEl?: Element, meta: object}} opts
 */
export function createBeeswarm({ canvas, legendEl, noteEl, meta }) {
  const ctx = canvas.getContext("2d");
  const nodeNames = meta.nodes.map((n) => n.name);
  const laneIndex = new Map(nodeNames.map((name, i) => [name, i]));
  const perNode = new Map(nodeNames.map((name) => [name, []]));
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
    const arr = perNode.get(ev.node);
    if (!arr) return; // event from a node not in meta.nodes; ignore defensively
    if (ev.slot > maxSlotSeen) maxSlotSeen = ev.slot;
    const offsetMs = Math.min(Math.max(ev.offset_ms, 0), msPerSlot);
    const seed = `${ev.node}|${ev.topic}|${ev.slot}|${ev.id ?? ""}|${ev.validator_id ?? ""}|${ev.arrival_ms}`;
    arr.push({
      topic: ev.topic,
      offsetMs,
      slot: ev.slot,
      jitter: hashJitter(seed) * JITTER_RANGE,
    });
    // Oldest-first decimation: cap points per node so a flood (e.g.
    // attestations) can't grow memory/render cost unbounded.
    if (arr.length > MAX_POINTS_PER_NODE) {
      arr.splice(0, arr.length - MAX_POINTS_PER_NODE);
    }
  }

  function xForOffset(offsetMs) {
    const plotWidth = cssWidth - LEFT_MARGIN - RIGHT_MARGIN;
    return LEFT_MARGIN + (offsetMs / msPerSlot) * plotWidth;
  }

  function laneY(nodeName) {
    const idx = laneIndex.get(nodeName);
    return TOP_MARGIN + idx * LANE_HEIGHT + LANE_HEIGHT / 2;
  }

  function draw() {
    if (cssWidth === 0) return;
    ctx.save();
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, cssWidth, cssHeight);

    const plotBottom = TOP_MARGIN + LANE_HEIGHT * nodeNames.length;

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
      const x = xForOffset(ms);
      ctx.beginPath();
      ctx.moveTo(x, TOP_MARGIN);
      ctx.lineTo(x, plotBottom);
      ctx.stroke();
      ctx.fillText(`${Math.round(ms)}`, x, plotBottom + 6);
    }
    ctx.textAlign = "left";
    ctx.fillText("ms into slot", LEFT_MARGIN, plotBottom + 18);

    // lane labels
    ctx.textAlign = "right";
    ctx.textBaseline = "middle";
    nodeNames.forEach((name) => {
      ctx.fillStyle = theme.text;
      ctx.fillText(name, LEFT_MARGIN - 10, laneY(name));
    });

    // dots, faded by slot age relative to the rolling window
    nodeNames.forEach((name) => {
      const arr = perNode.get(name);
      const y = laneY(name);
      for (let i = 0; i < arr.length; i++) {
        const pt = arr[i];
        const age = maxSlotSeen - pt.slot;
        if (age >= windowSlots) continue;
        const x = xForOffset(pt.offsetMs);
        ctx.globalAlpha = FADE_FLOOR + (1 - FADE_FLOOR) * Math.pow(FADE_DECAY, age);
        ctx.fillStyle = theme.topics[pt.topic];
        ctx.beginPath();
        ctx.arc(x, y + pt.jitter, DOT_RADIUS, 0, Math.PI * 2);
        ctx.fill();
      }
    });
    ctx.globalAlpha = 1;
    ctx.restore();
  }

  // Periodically drop points that have fully aged out of the window, so the
  // per-node arrays don't hold onto stale data just because they're under
  // the point cap. Each node's array is arrival-ordered, so scanning from
  // the front is a good approximation of oldest-first.
  function prune() {
    for (const arr of perNode.values()) {
      let i = 0;
      while (i < arr.length && maxSlotSeen - arr[i].slot >= windowSlots) i++;
      if (i > 0) arr.splice(0, i);
    }
  }

  function renderLegend() {
    if (!legendEl) return;
    legendEl.innerHTML = "";
    const items = [
      ["block", "Block"],
      ["attestation", "Attestation"],
      ["aggregate", "Aggregate"],
    ];
    for (const [topic, label] of items) {
      const chip = document.createElement("span");
      chip.className = `legend-item legend-${topic}`;
      const swatch = document.createElement("span");
      swatch.className = "legend-swatch";
      chip.appendChild(swatch);
      chip.appendChild(document.createTextNode(label));
      legendEl.appendChild(chip);
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

  function updateNote() {
    if (noteEl) {
      noteEl.textContent = `Showing the last ${windowSlots} slots. Older slots fade out, then drop.`;
    }
  }

  resize();
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
