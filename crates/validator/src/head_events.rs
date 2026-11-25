//! The beacon node's `head` events, used only to attest early.
//!
//! The honest-validator guide has an attester vote once it has seen a valid
//! block for its slot *or* once `ATTESTATION_DUE_BPS` of the slot has passed,
//! whichever comes first. The duty loop used to wait for the deadline every
//! slot, so this client's votes always went out after it, a full deadline
//! behind clients that vote on the block. This module is the "has seen the
//! block" half.
//!
//! It is a hint and nothing more. The duty loop still runs on its own clock
//! (see [`crate::slot_clock`]): the event stream is best-effort by contract and
//! may drop events, so the deadline stays the fallback, and a stream that is
//! down, slow or never connects costs the early vote only, never the duty.
//!
//! # Only the first beacon node
//!
//! `attestation_data` is asked of the beacon nodes in order, so the vote is
//! the first healthy node's head. A head event from another node could wake
//! the duty before that node has the block, and the vote would then name the
//! previous head. Listening to the first node alone keeps the wake and the
//! answer on one node; when it is down, the duty falls back to the deadline.

use std::time::Duration;

use ethlambda_types::beacon::primitives::Slot;
use reqwest::Client;
use serde::Deserialize;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// How long establishing the stream's connection may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// How long the stream may stay silent before it is reopened. A node sends a
/// head event every slot it imports a block in, so a minute of silence is a
/// connection that died without closing, or a chain that is not moving, and
/// reopening costs nothing in the second case.
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// The wait before reopening a stream that failed, doubled on every failure
/// in a row up to [`MAX_BACKOFF`].
const INITIAL_BACKOFF: Duration = Duration::from_millis(500);
const MAX_BACKOFF: Duration = Duration::from_secs(12);

/// The highest head slot the beacon node has reported, shared with the duty
/// loop.
#[derive(Debug, Clone)]
pub struct HeadWatch {
    head_slot: watch::Receiver<Slot>,
}

impl HeadWatch {
    /// Subscribes to `base_url`'s `head` events on a task of its own, which
    /// reconnects until `shutdown` is cancelled.
    pub fn spawn(base_url: &str, shutdown: CancellationToken) -> Self {
        let (sender, head_slot) = watch::channel(0);
        let url = format!(
            "{}/eth/v1/events?topics=head",
            base_url.trim_end_matches('/')
        );
        tokio::spawn(async move {
            tokio::select! {
                () = shutdown.cancelled() => {}
                () = follow(url, sender) => {}
            }
        });
        Self { head_slot }
    }

    /// A watch no event ever reaches, so every duty waits for its deadline.
    pub fn never() -> Self {
        let (_sender, head_slot) = watch::channel(0);
        Self { head_slot }
    }

    /// Resolves once the node has reported a head at `slot` or later, which
    /// may already be the case. Never resolves if the stream has stopped for
    /// good, so callers race it against their deadline.
    pub async fn head_at(&self, slot: Slot) {
        let mut head_slot = self.head_slot.clone();
        if head_slot.wait_for(|head| *head >= slot).await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

/// Sleeps for `deadline`, or less if the node reports a head at `slot` first.
/// Returns whether the head cut the wait short.
pub async fn until_deadline_or_head(deadline: Duration, head: &HeadWatch, slot: Slot) -> bool {
    if deadline.is_zero() {
        return false;
    }
    tokio::select! {
        biased;
        () = head.head_at(slot) => true,
        () = tokio::time::sleep(deadline) => false,
    }
}

/// Reads the stream at `url` into `sender`, reopening it whenever it fails or
/// ends. Returns only when every receiver is gone.
async fn follow(url: String, sender: watch::Sender<Slot>) {
    let client = match Client::builder().connect_timeout(CONNECT_TIMEOUT).build() {
        Ok(client) => client,
        Err(err) => {
            warn!(%err, "Cannot build the head event client; attesting at the deadline only");
            return;
        }
    };
    let mut backoff = INITIAL_BACKOFF;
    loop {
        match read_stream(&client, &url, &sender, &mut backoff).await {
            Ok(()) => debug!(%url, "Head event stream ended; reopening"),
            Err(err) => debug!(%url, %err, "Head event stream failed; reopening"),
        }
        if sender.is_closed() {
            return;
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

/// One connection's worth of events. Resets `backoff` once the stream is open.
async fn read_stream(
    client: &Client,
    url: &str,
    sender: &watch::Sender<Slot>,
    backoff: &mut Duration,
) -> Result<(), String> {
    let mut response = client
        .get(url)
        .header(reqwest::header::ACCEPT, "text/event-stream")
        .send()
        .await
        .map_err(|err| err.to_string())?;
    if !response.status().is_success() {
        return Err(format!("status {}", response.status()));
    }
    info!(%url, "Following the beacon node's head events to attest on the block");
    *backoff = INITIAL_BACKOFF;

    let mut parser = EventParser::default();
    loop {
        let chunk = tokio::time::timeout(IDLE_TIMEOUT, response.chunk())
            .await
            .map_err(|_| "idle".to_string())?
            .map_err(|err| err.to_string())?;
        let Some(chunk) = chunk else {
            return Ok(());
        };
        for slot in parser.push(&chunk) {
            sender.send_if_modified(|head| {
                let higher = slot > *head;
                if higher {
                    *head = slot;
                }
                higher
            });
        }
    }
}

/// An incremental `text/event-stream` reader that yields the slot of every
/// `head` event, and skips everything else.
#[derive(Debug, Default)]
struct EventParser {
    pending: Vec<u8>,
}

#[derive(Deserialize)]
struct HeadData {
    #[serde(deserialize_with = "quoted_or_bare")]
    slot: Slot,
}

fn quoted_or_bare<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Slot, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Either {
        Quoted(String),
        Bare(Slot),
    }
    match Either::deserialize(deserializer)? {
        Either::Quoted(text) => text.parse().map_err(serde::de::Error::custom),
        Either::Bare(slot) => Ok(slot),
    }
}

impl EventParser {
    /// Feeds `bytes` in and returns the head slots of the events it completed.
    fn push(&mut self, bytes: &[u8]) -> Vec<Slot> {
        self.pending.extend_from_slice(bytes);
        let mut slots = Vec::new();
        while let Some((end, separator)) = find_event_end(&self.pending) {
            let event: Vec<u8> = self.pending.drain(..end + separator).collect();
            if let Some(slot) = head_slot(&event[..end]) {
                slots.push(slot);
            }
        }
        slots
    }
}

/// Where the first complete event ends and how long its blank-line separator
/// is, for either line ending the format allows.
fn find_event_end(buffer: &[u8]) -> Option<(usize, usize)> {
    let lf = buffer.windows(2).position(|window| window == b"\n\n");
    let crlf = buffer.windows(4).position(|window| window == b"\r\n\r\n");
    match (lf, crlf) {
        (Some(lf), Some(crlf)) if crlf < lf => Some((crlf, 4)),
        (Some(lf), _) => Some((lf, 2)),
        (None, Some(crlf)) => Some((crlf, 4)),
        (None, None) => None,
    }
}

/// The slot of one event, if it is a well-formed `head` event.
fn head_slot(event: &[u8]) -> Option<Slot> {
    let event = std::str::from_utf8(event).ok()?;
    let mut name = None;
    let mut data = String::new();
    for line in event.lines() {
        let line = line.trim_end_matches('\r');
        if let Some(value) = line.strip_prefix("event:") {
            name = Some(value.trim());
        } else if let Some(value) = line.strip_prefix("data:") {
            if !data.is_empty() {
                data.push('\n');
            }
            data.push_str(value.strip_prefix(' ').unwrap_or(value));
        }
    }
    if name != Some("head") {
        return None;
    }
    serde_json::from_str::<HeadData>(&data)
        .ok()
        .map(|head| head.slot)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEAD: &str = "event: head\ndata: {\"slot\":\"10\",\"block\":\"0x00\"}\n\n";

    #[test]
    fn a_head_event_yields_its_slot() {
        let mut parser = EventParser::default();
        assert_eq!(parser.push(HEAD.as_bytes()), vec![10]);
    }

    #[test]
    fn an_event_split_across_chunks_is_read_once_whole() {
        let mut parser = EventParser::default();
        let (first, second) = HEAD.split_at(17);
        assert!(parser.push(first.as_bytes()).is_empty());
        assert_eq!(parser.push(second.as_bytes()), vec![10]);
    }

    #[test]
    fn other_events_comments_and_crlf_are_handled() {
        let mut parser = EventParser::default();
        let stream = ": keep-alive\n\n\
            event: block\ndata: {\"slot\":\"11\"}\n\n\
            event: head\r\ndata: {\"slot\":12}\r\n\r\n";
        assert_eq!(parser.push(stream.as_bytes()), vec![12]);
    }

    #[test]
    fn a_malformed_head_event_is_skipped() {
        let mut parser = EventParser::default();
        let stream = format!("event: head\ndata: {{\"slot\":\"x\"}}\n\n{HEAD}");
        assert_eq!(parser.push(stream.as_bytes()), vec![10]);
    }

    #[tokio::test(start_paused = true)]
    async fn the_deadline_is_the_fallback_without_a_head() {
        let woke_early =
            until_deadline_or_head(Duration::from_secs(3), &HeadWatch::never(), 5).await;
        assert!(!woke_early);
    }

    #[tokio::test(start_paused = true)]
    async fn a_head_at_the_slot_cuts_the_wait_short() {
        let (sender, head_slot) = watch::channel(0);
        let head = HeadWatch { head_slot };
        let waiting = tokio::spawn({
            let head = head.clone();
            async move { until_deadline_or_head(Duration::from_secs(3), &head, 5).await }
        });
        tokio::time::sleep(Duration::from_millis(500)).await;
        sender.send_replace(4);
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(
            !waiting.is_finished(),
            "a head at an earlier slot is not this slot's block"
        );
        sender.send_replace(5);
        assert!(waiting.await.unwrap());
        drop(sender);
    }
}
