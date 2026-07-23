// demo.js — self-contained synthetic data generator for the `?demo=1` mode.
// Only ever imported by app.js when that URL param is present (see boot() in
// app.js); never runs otherwise. It fabricates a plausible /api/meta (§4) and
// then drives the exact same "chain"/"status" EventTarget interface that a
// real EventSource would (see CONTRACT.md §4 GET /stream), so app.js and the
// two renderers (beeswarm.js, propagation.js) don't need to know the
// difference.

const DEMO_NODES = ["node-2", "node-3", "node-4", "node-5"];
const MS_PER_SLOT = 4000;
const INTERVALS_PER_SLOT = 5;
const WINDOW_SLOTS = 30;
const VALIDATOR_COUNT = 16;
const SLOW_NODE = "node-5"; // consistently later, so the panels have something to show

export function createDemoMeta() {
  return {
    genesis_time: Math.floor(Date.now() / 1000) - (MS_PER_SLOT / 1000) * 1000,
    ms_per_slot: MS_PER_SLOT,
    intervals_per_slot: INTERVALS_PER_SLOT,
    window_slots: WINDOW_SLOTS,
    topics: ["block", "attestation", "aggregate"],
    nodes: DEMO_NODES.map((name) => ({ name, url: `demo://${name}` })),
  };
}

// Small non-cryptographic hash for fabricating plausible-looking 0x… ids.
function fnv1aHex(str) {
  let h = 2166136261;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return (h >>> 0).toString(16).padStart(8, "0");
}

function fakeRoot(seed) {
  return `0x${fnv1aHex(seed).padEnd(64, "0")}`;
}

/**
 * Returns an object with the same `addEventListener("chain"|"status", cb)`
 * shape as the real `EventSource` from CONTRACT.md §4, but driven by timers
 * instead of a network connection.
 *
 * @param {object} meta as produced by createDemoMeta()
 */
export function createDemoSource(meta) {
  const target = new EventTarget();
  const timers = [];
  let slot = 1000;
  const statusState = new Map(meta.nodes.map((n) => [n.name, "connected"]));

  function emitChain(ev) {
    target.dispatchEvent(new MessageEvent("chain", { data: JSON.stringify(ev) }));
  }
  function emitStatus(st) {
    target.dispatchEvent(new MessageEvent("status", { data: JSON.stringify(st) }));
  }

  // The slow node arrives well after everyone else; the rest jitter a little.
  function nodeDelayMs(name) {
    return name === SLOW_NODE ? 350 + Math.random() * 250 : Math.random() * 60;
  }

  function schedule(fn, delayMs) {
    timers.push(setTimeout(fn, delayMs));
  }

  function runSlot(currentSlot) {
    const blockRoot = fakeRoot(`block:${currentSlot}`);
    const aggId = fakeRoot(`aggregate:${currentSlot}`);

    // blocks: ~0.6s into the slot
    for (const node of meta.nodes) {
      const offset = 600 + nodeDelayMs(node.name);
      schedule(
        () =>
          emitChain({
            node: node.name,
            topic: "block",
            slot: currentSlot,
            arrival_ms: Date.now(),
            offset_ms: Math.round(offset),
            id: blockRoot,
            validator_id: null,
            participants: null,
          }),
        offset
      );
    }

    // attestations: ~1.1s into the slot, one per validator per node
    for (const node of meta.nodes) {
      for (let validatorId = 0; validatorId < VALIDATOR_COUNT; validatorId++) {
        const offset = 1100 + nodeDelayMs(node.name) + Math.random() * 200;
        schedule(
          () =>
            emitChain({
              node: node.name,
              topic: "attestation",
              slot: currentSlot,
              arrival_ms: Date.now(),
              offset_ms: Math.round(offset),
              id: null,
              validator_id: validatorId,
              participants: null,
            }),
          offset
        );
      }
    }

    // aggregate: ~2.2s into the slot
    for (const node of meta.nodes) {
      const offset = 2200 + nodeDelayMs(node.name);
      const participants = Math.max(1, VALIDATOR_COUNT - Math.round(Math.random() * 2));
      schedule(
        () =>
          emitChain({
            node: node.name,
            topic: "aggregate",
            slot: currentSlot,
            arrival_ms: Date.now(),
            offset_ms: Math.round(offset),
            id: aggId,
            validator_id: null,
            participants,
          }),
        offset
      );
    }
  }

  runSlot(slot);
  timers.push(
    setInterval(() => {
      slot += 1;
      runSlot(slot);
    }, meta.ms_per_slot)
  );

  // occasional reconnecting blip on the slow node, plus a periodic rate heartbeat
  timers.push(
    setInterval(() => {
      for (const node of meta.nodes) {
        let state = statusState.get(node.name);
        if (node.name === SLOW_NODE && Math.random() < 0.12) {
          state = state === "connected" ? "reconnecting" : "connected";
          statusState.set(node.name, state);
        }
        emitStatus({
          node: node.name,
          state,
          events_per_sec: state === "down" ? 0 : 4 + Math.random() * 2,
        });
      }
    }, 2000)
  );

  target.close = () => {
    for (const t of timers) {
      clearTimeout(t);
      clearInterval(t);
    }
  };

  return target;
}
