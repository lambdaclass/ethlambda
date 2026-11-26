//! The beacon node's event stream, `GET /eth/v1/events`, read as
//! server-sent events.
//!
//! Only the two topics the duty loop acts on are read (see
//! [`crate::head_monitor`]): `head`, and from gloas
//! `execution_payload_available`. Everything else a node might send is
//! skipped.
//!
//! # No new dependency
//!
//! `reqwest`'s `bytes_stream` needs its `stream` feature, which would pull
//! `futures-util` and `tokio-util` into reqwest's own dependency set. The body
//! is read with [`reqwest::Response::chunk`] instead, which every build has,
//! and the frames are parsed here by [`SseParser`]: the format is a few lines
//! of the HTML specification's "Server-sent events" section, and an event this
//! client reads is a few hundred bytes.
//!
//! # A stream is best-effort
//!
//! A node drops events for a subscriber that reads too slowly, restarts, or
//! sits behind a proxy that buffers. Nothing here is relied on for a duty to
//! happen: the slot clock's offsets stay every duty's deadline, and an event
//! can only make a duty earlier (see `crate::slot_clock`).

use std::collections::VecDeque;
use std::time::Duration;

use async_trait::async_trait;
use ethlambda_types::beacon::primitives::{Root, Slot};
use reqwest::{Client, StatusCode};
use serde::Deserialize;
use tracing::warn;

use crate::beacon_node::dto::{parse_root, quoted_u64};
use crate::beacon_node::http::without_credentials;
use crate::error::{BeaconNodeFailure, Error, Result};

/// How long establishing the connection may take: the bound
/// `HttpBeaconNode` puts on its own requests.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// How long the node may take to answer a subscription with its status and
/// headers, once connected: `HttpBeaconNode`'s bound on a whole request. A
/// node streams its events after the headers, so this bounds only the start,
/// and a node that takes the connection and never answers does not hold the
/// reader on it.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(8);

/// How long an open stream may send nothing at all before it is taken for
/// dead and opened again.
///
/// Four times the 15-second keep-alive interval ethlambda's node sends on an
/// idle stream (axum's default), so a live stream there never trips it. Other
/// nodes may send keep-alives less often or not at all, and a stream that is
/// quiet by design (`execution_payload_available` before gloas) then trips it
/// every minute: that reopen is routine, and is logged at debug (see
/// [`is_idle_timeout`]). What it guards against is a connection whose far end
/// is gone without a word, which would otherwise hold a stream open that never
/// delivers again.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// The most one event may take, its `event:` and `data:` lines together,
/// before the stream is dropped as broken.
///
/// An event this client reads is a few hundred bytes. The cap is what stops a
/// node that sends an endless line from growing the buffer without bound.
pub const MAX_FRAME_BYTES: usize = 64 * 1024;

/// How much of a refused subscription's body an error carries.
const ERROR_BODY_LIMIT: usize = 1024;

/// A Beacon API event topic this client reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Topic {
    /// Fork choice picked a new head.
    Head,
    /// Gloas: a block's execution payload, and its blob data, are available.
    ExecutionPayloadAvailable,
}

impl Topic {
    /// The topic's name on the wire, both in the `topics` query and on the
    /// `event:` line.
    pub fn as_str(self) -> &'static str {
        match self {
            Topic::Head => "head",
            Topic::ExecutionPayloadAvailable => "execution_payload_available",
        }
    }
}

/// An event the duty loop acts on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeEvent {
    Head(HeadEvent),
    PayloadAvailable(PayloadAvailableEvent),
}

/// What a `head` event says that this client uses: the head's slot and root,
/// and whether the execution client has validated it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeadEvent {
    pub slot: Slot,
    pub block: Root,
    pub execution_optimistic: bool,
}

/// An `execution_payload_available` event: the payload of the block at
/// `block_root`, in `slot`, and its blob data, are available to the node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadAvailableEvent {
    pub slot: Slot,
    pub block_root: Root,
}

/// `head`'s payload, less the fields this client does not read (the state
/// root, `epoch_transition` and the two dependent roots).
#[derive(Deserialize)]
struct HeadDto {
    #[serde(deserialize_with = "quoted_u64::deserialize")]
    slot: u64,
    block: String,
    /// `Option` and read as `false` when absent, as `head_block_root`'s
    /// answer is: a node that predates the field does not do optimistic sync.
    execution_optimistic: Option<bool>,
}

/// `execution_payload_available`'s payload.
#[derive(Deserialize)]
struct PayloadAvailableDto {
    #[serde(deserialize_with = "quoted_u64::deserialize")]
    slot: u64,
    block_root: String,
}

/// The event `frame` carries, `None` for a topic this client does not read,
/// or an error naming what is wrong with one it does.
pub fn decode(frame: &SseFrame) -> Option<Result<NodeEvent>> {
    let event = if frame.event == Topic::Head.as_str() {
        serde_json::from_str::<HeadDto>(&frame.data)
            .map_err(|err| Error::Decode(format!("head event: {err}")))
            .and_then(|dto| {
                Ok(NodeEvent::Head(HeadEvent {
                    slot: dto.slot,
                    block: parse_root(&dto.block)?,
                    execution_optimistic: dto.execution_optimistic.unwrap_or(false),
                }))
            })
    } else if frame.event == Topic::ExecutionPayloadAvailable.as_str() {
        serde_json::from_str::<PayloadAvailableDto>(&frame.data)
            .map_err(|err| Error::Decode(format!("execution_payload_available event: {err}")))
            .and_then(|dto| {
                Ok(NodeEvent::PayloadAvailable(PayloadAvailableEvent {
                    slot: dto.slot,
                    block_root: parse_root(&dto.block_root)?,
                }))
            })
    } else {
        return None;
    };
    Some(event)
}

/// One server-sent event: its `event:` name and its `data:` lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseFrame {
    /// `message` when the frame named none, as the format specifies.
    pub event: String,
    /// Every `data:` line of the frame, joined with `\n`.
    pub data: String,
}

/// An event, its `event:` and `data:` lines together, ran past
/// [`MAX_FRAME_BYTES`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameTooLong;

/// Server-sent events, parsed from a body that arrives in pieces cut
/// anywhere.
///
/// The HTML specification's "Server-sent events" interpretation, less what
/// this client has no use for (`id:` and `retry:` are read and ignored: a
/// reconnect asks for the stream afresh, on this client's own backoff):
///
/// - A line ends at `\n`, `\r\n` or `\r`, and a `\r\n` split between two
///   pieces is still one line end.
/// - A line starting with `:` is a comment: a keep-alive, or ethlambda's and
///   Lighthouse's `: error - dropped N messages`.
/// - `field: value` sets a field, with one space after the colon dropped if
///   there is one; a line with no colon is a field with an empty value.
/// - `data:` lines accumulate, joined with `\n`; a blank line ends the frame,
///   and a frame with no `data:` line is dropped.
/// - A byte-order mark at the very start of the stream is dropped.
///
/// Bytes are buffered, not text, since a piece can end in the middle of a
/// UTF-8 sequence; each line is decoded once it is whole, and the line-ending
/// bytes cannot occur inside a multi-byte sequence.
#[derive(Debug, Default)]
pub struct SseParser {
    /// The line being read, without its ending.
    line: Vec<u8>,
    /// The frame's `event:` value, empty until one arrives.
    event: String,
    /// The frame's `data:` lines so far, `None` until one arrives.
    data: Option<String>,
    /// The last byte read ended a line with `\r`, so a `\n` that follows
    /// belongs to that ending.
    after_cr: bool,
    /// A line has been read, so a byte-order mark is no longer the stream's
    /// first character.
    started: bool,
}

impl SseParser {
    /// Feed the next piece of the body, and take every frame it completes.
    ///
    /// An error leaves the parser in no state worth continuing from: the
    /// caller drops the stream.
    pub fn push(&mut self, bytes: &[u8]) -> std::result::Result<Vec<SseFrame>, FrameTooLong> {
        let mut frames = Vec::new();
        for &byte in bytes {
            match byte {
                b'\n' if self.after_cr => self.after_cr = false,
                b'\n' | b'\r' => {
                    self.after_cr = byte == b'\r';
                    frames.extend(self.end_line());
                }
                _ => {
                    self.after_cr = false;
                    self.line.push(byte);
                }
            }
            let held =
                self.line.len() + self.event.len() + self.data.as_ref().map_or(0, String::len);
            if held > MAX_FRAME_BYTES {
                return Err(FrameTooLong);
            }
        }
        Ok(frames)
    }

    /// Act on the line just ended, returning the frame it completes, if any.
    fn end_line(&mut self) -> Option<SseFrame> {
        let bytes = std::mem::take(&mut self.line);
        let text = String::from_utf8_lossy(&bytes);
        let mut line: &str = &text;
        if !self.started {
            self.started = true;
            line = line.strip_prefix('\u{feff}').unwrap_or(line);
        }

        if line.is_empty() {
            return self.dispatch();
        }
        if line.starts_with(':') {
            return None;
        }
        let (field, value) = match line.split_once(':') {
            Some((field, value)) => (field, value.strip_prefix(' ').unwrap_or(value)),
            None => (line, ""),
        };
        match field {
            "event" => self.event = value.to_string(),
            "data" => match &mut self.data {
                Some(data) => {
                    data.push('\n');
                    data.push_str(value);
                }
                None => self.data = Some(value.to_string()),
            },
            // `id`, `retry`, and any field the format does not define.
            _ => {}
        }
        None
    }

    /// End the frame being built. Its fields are cleared whether or not it
    /// had any data to dispatch.
    fn dispatch(&mut self) -> Option<SseFrame> {
        let event = std::mem::take(&mut self.event);
        let data = self.data.take()?;
        let event = if event.is_empty() {
            "message".to_string()
        } else {
            event
        };
        Some(SseFrame { event, data })
    }
}

/// Where a beacon node's events come from.
///
/// A trait so the duty loop's triggers can be driven by a scripted mock (see
/// `beacon_node::mock`), as [`crate::beacon_node::BeaconNodeApi`] is.
#[async_trait]
pub trait EventSource: Send + Sync {
    /// Open the node's stream for `topics`.
    ///
    /// An `Err` when the node cannot be reached or refuses the subscription.
    async fn subscribe(&self, topics: &[Topic]) -> Result<Box<dyn EventStream>>;
}

/// One open event stream.
#[async_trait]
pub trait EventStream: Send {
    /// The next event this client reads, `Ok(None)` once the node has closed
    /// the stream, or an `Err` once it broke. Either way the stream is done.
    async fn next_event(&mut self) -> Result<Option<NodeEvent>>;
}

/// An [`EventSource`] reading one beacon node's `GET /eth/v1/events`.
pub struct HttpEventSource {
    /// What requests go to, any `user:password@` included.
    base_url: String,
    /// `base_url` without its credentials: what logs and errors name the node
    /// by, as `HttpBeaconNode` does (see `without_credentials`).
    name: String,
    /// Its own client, not `HttpBeaconNode`'s: that one's total timeout runs
    /// until a body is finished, and a stream's never is. This one bounds the
    /// connection alone, and [`IDLE_TIMEOUT`] the silence on it.
    client: Client,
}

impl HttpEventSource {
    /// A source for the node at `base_url`, a trailing slash stripped as
    /// `HttpBeaconNode::new` strips one.
    pub fn new(base_url: impl Into<String>) -> Result<Self> {
        let base_url = base_url.into().trim_end_matches('/').to_string();
        let name = without_credentials(&base_url);
        let client = Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            .map_err(|err| transport(&name, &err))?;
        Ok(Self {
            base_url,
            name,
            client,
        })
    }

    /// The node's base URL without any credentials it carries, for a log
    /// line or an error.
    pub fn name(&self) -> &str {
        &self.name
    }
}

#[async_trait]
impl EventSource for HttpEventSource {
    async fn subscribe(&self, topics: &[Topic]) -> Result<Box<dyn EventStream>> {
        // The specification's form, one `topics` per topic, rather than the
        // comma-joined list some nodes also accept. The duty loop opens one
        // topic per stream anyway (see `head_monitor`), so the two forms are
        // the same request.
        let query = topics
            .iter()
            .map(|topic| format!("topics={}", topic.as_str()))
            .collect::<Vec<_>>()
            .join("&");
        let url = format!("{}/eth/v1/events?{query}", self.base_url);
        let request = self
            .client
            .get(&url)
            .header(reqwest::header::ACCEPT, "text/event-stream")
            .send();
        let response = tokio::time::timeout(RESPONSE_TIMEOUT, request)
            .await
            .map_err(|_| Error::BeaconNode {
                url: self.name.clone(),
                failure: BeaconNodeFailure::Timeout,
                detail: format!(
                    "the event stream was not answered within {} s",
                    RESPONSE_TIMEOUT.as_secs()
                ),
            })?
            .map_err(|err| transport(&self.name, &err))?;
        let status = response.status();
        if status != StatusCode::OK {
            return Err(Error::BeaconNodeStatus {
                status: status.as_u16(),
                body: body_excerpt(response).await,
            });
        }
        Ok(Box::new(HttpEventStream {
            name: self.name.clone(),
            response,
            parser: SseParser::default(),
            decoded: VecDeque::new(),
        }))
    }
}

/// A stream [`HttpEventSource`] opened.
struct HttpEventStream {
    /// The node's URL without its credentials (see [`HttpEventSource::name`]).
    name: String,
    response: reqwest::Response,
    parser: SseParser,
    /// Events a body piece completed and `next_event` has not handed out.
    decoded: VecDeque<NodeEvent>,
}

#[async_trait]
impl EventStream for HttpEventStream {
    async fn next_event(&mut self) -> Result<Option<NodeEvent>> {
        loop {
            if let Some(event) = self.decoded.pop_front() {
                return Ok(Some(event));
            }
            let chunk = match tokio::time::timeout(IDLE_TIMEOUT, self.response.chunk()).await {
                Err(_) => {
                    return Err(Error::BeaconNode {
                        url: self.name.clone(),
                        failure: BeaconNodeFailure::Timeout,
                        detail: format!(
                            "the event stream sent nothing for {} s",
                            IDLE_TIMEOUT.as_secs()
                        ),
                    });
                }
                Ok(Err(err)) => return Err(transport(&self.name, &err)),
                Ok(Ok(None)) => return Ok(None),
                Ok(Ok(Some(chunk))) => chunk,
            };
            let frames = self.parser.push(&chunk).map_err(|FrameTooLong| {
                Error::Decode(format!(
                    "an event on {}'s stream runs past {MAX_FRAME_BYTES} bytes",
                    self.name
                ))
            })?;
            for frame in frames {
                match decode(&frame) {
                    Some(Ok(event)) => self.decoded.push_back(event),
                    // One bad event is skipped, not the stream: the next
                    // slot's may well be fine, and the duty has its deadline.
                    Some(Err(err)) => warn!(
                        node = %self.name,
                        event = %frame.event,
                        %err,
                        "Skipping a malformed event from the beacon node"
                    ),
                    None => {}
                }
            }
        }
    }
}

/// Whether `err`, from [`EventStream::next_event`], is a stream that went
/// quiet for [`IDLE_TIMEOUT`] rather than one that broke.
///
/// The stream's client has no total timeout, so a timeout on an open stream
/// can only be that one.
pub fn is_idle_timeout(err: &Error) -> bool {
    matches!(
        err,
        Error::BeaconNode {
            failure: BeaconNodeFailure::Timeout,
            ..
        }
    )
}

/// A `reqwest` failure as this crate's beacon-node error. `name` is the
/// node's URL without its credentials ([`HttpEventSource::name`]); reqwest's
/// own text carries none either, since it moves a URL's `user:password@` into
/// the `Authorization` header before sending.
fn transport(name: &str, err: &reqwest::Error) -> Error {
    Error::BeaconNode {
        url: name.to_string(),
        failure: BeaconNodeFailure::classify(err),
        detail: err.to_string(),
    }
}

/// The start of a refused subscription's body, as one line, for the error.
/// Read a piece at a time, only up to [`ERROR_BODY_LIMIT`], and within one
/// [`CONNECT_TIMEOUT`] for the whole read rather than one per piece, so a node
/// answering with an endless or trickled body cannot hold the reconnect on it.
async fn body_excerpt(mut response: reqwest::Response) -> String {
    let mut bytes = Vec::new();
    let read = async {
        while bytes.len() < ERROR_BODY_LIMIT {
            let Ok(Some(chunk)) = response.chunk().await else {
                break;
            };
            bytes.extend_from_slice(&chunk[..chunk.len().min(ERROR_BODY_LIMIT - bytes.len())]);
        }
    };
    // Whatever arrived by then is the excerpt.
    let _ = tokio::time::timeout(CONNECT_TIMEOUT, read).await;
    ethlambda_types::text::one_line(&String::from_utf8_lossy(&bytes), ERROR_BODY_LIMIT)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(event: &str, data: &str) -> SseFrame {
        SseFrame {
            event: event.to_string(),
            data: data.to_string(),
        }
    }

    fn root_hex(byte: u8) -> String {
        format!("0x{}", hex::encode([byte; 32]))
    }

    fn head_json(slot: u64, byte: u8, optimistic: bool) -> String {
        format!(
            r#"{{"slot":"{slot}","block":"{}","state":"{}","epoch_transition":false,"previous_duty_dependent_root":"{}","current_duty_dependent_root":"{}","execution_optimistic":{optimistic}}}"#,
            root_hex(byte),
            root_hex(0xee),
            root_hex(0xdd),
            root_hex(0xcc),
        )
    }

    // The parser.

    #[test]
    fn a_frame_ends_at_a_blank_line() {
        let mut parser = SseParser::default();
        let frames = parser
            .push(b"event: head\ndata: {\"a\":1}\n\n")
            .expect("parses");
        assert_eq!(frames, vec![frame("head", "{\"a\":1}")]);
    }

    #[test]
    fn nothing_is_dispatched_before_the_blank_line() {
        let mut parser = SseParser::default();
        assert!(
            parser
                .push(b"event: head\ndata: x\n")
                .expect("parses")
                .is_empty()
        );
        assert_eq!(
            parser.push(b"\n").expect("parses"),
            vec![frame("head", "x")]
        );
    }

    /// A body cut at every byte gives the same frames as one piece: lines,
    /// fields and the blank line are reassembled whatever the cut.
    #[test]
    fn a_frame_split_at_every_byte_is_the_same_frame() {
        let body = b": keep-alive\n\nevent: head\ndata: first\n\nevent: block\ndata: second\n\n";
        let mut parser = SseParser::default();
        let mut frames = Vec::new();
        for byte in body {
            frames.extend(parser.push(std::slice::from_ref(byte)).expect("parses"));
        }
        assert_eq!(
            frames,
            vec![frame("head", "first"), frame("block", "second")]
        );
    }

    /// `\r\n` and a lone `\r` end lines as `\n` does, and a `\r\n` cut between
    /// two pieces is one line end, not a line end and a blank line.
    #[test]
    fn every_line_ending_is_one_line_end() {
        let mut parser = SseParser::default();
        assert_eq!(
            parser
                .push(b"event: head\r\ndata: a\r\n\r\n")
                .expect("parses"),
            vec![frame("head", "a")]
        );
        assert_eq!(
            parser.push(b"event: head\rdata: b\r\r").expect("parses"),
            vec![frame("head", "b")]
        );
        assert!(parser.push(b"event: head\r").expect("parses").is_empty());
        assert!(parser.push(b"\ndata: c\r").expect("parses").is_empty());
        assert_eq!(
            parser.push(b"\n\r\n").expect("parses"),
            vec![frame("head", "c")]
        );
    }

    #[test]
    fn comments_are_skipped() {
        let mut parser = SseParser::default();
        let frames = parser
            .push(b": error - dropped 3 messages\n\n:\nevent: head\n: in between\ndata: x\n\n")
            .expect("parses");
        assert_eq!(frames, vec![frame("head", "x")]);
    }

    #[test]
    fn data_lines_are_joined_with_newlines() {
        let mut parser = SseParser::default();
        let frames = parser
            .push(b"data: one\ndata:two\ndata\n\n")
            .expect("parses");
        assert_eq!(frames, vec![frame("message", "one\ntwo\n")]);
    }

    /// Only one space after the colon is dropped; the rest is the value.
    #[test]
    fn one_space_after_the_colon_is_dropped() {
        let mut parser = SseParser::default();
        let frames = parser.push(b"event:head\ndata:  x\n\n").expect("parses");
        assert_eq!(frames, vec![frame("head", " x")]);
    }

    /// A frame with no data is dropped, and its `event:` does not leak into
    /// the next one.
    #[test]
    fn a_frame_without_data_is_dropped_and_forgotten() {
        let mut parser = SseParser::default();
        let frames = parser
            .push(b"event: head\nid: 7\nretry: 100\n\ndata: x\n\n")
            .expect("parses");
        assert_eq!(frames, vec![frame("message", "x")]);
    }

    #[test]
    fn a_byte_order_mark_at_the_start_is_dropped() {
        let mut parser = SseParser::default();
        let frames = parser
            .push(b"\xef\xbb\xbfevent: head\ndata: x\n\n")
            .expect("parses");
        assert_eq!(frames, vec![frame("head", "x")]);
    }

    /// A multi-byte character cut between two pieces is decoded whole.
    #[test]
    fn a_character_split_between_pieces_survives() {
        let mut parser = SseParser::default();
        let body = "data: Platåberget\n\n".as_bytes();
        let cut = body
            .iter()
            .position(|&byte| byte >= 0x80)
            .expect("non-ascii")
            + 1;
        assert!(parser.push(&body[..cut]).expect("parses").is_empty());
        assert_eq!(
            parser.push(&body[cut..]).expect("parses"),
            vec![frame("message", "Platåberget")]
        );
    }

    #[test]
    fn an_endless_line_is_refused() {
        let mut parser = SseParser::default();
        let long = vec![b'a'; MAX_FRAME_BYTES + 1];
        assert_eq!(parser.push(&long), Err(FrameTooLong));
    }

    /// Many data lines, each short, are bounded together.
    #[test]
    fn an_endless_frame_is_refused() {
        let mut parser = SseParser::default();
        let line = format!("data: {}\n", "a".repeat(1000));
        let mut result = Ok(Vec::new());
        for _ in 0..(MAX_FRAME_BYTES / 1000 + 2) {
            result = parser.push(line.as_bytes());
            if result.is_err() {
                break;
            }
        }
        assert_eq!(result, Err(FrameTooLong));
    }

    // Decoding.

    #[test]
    fn a_head_event_decodes() {
        let event = decode(&frame("head", &head_json(10, 0xab, false)))
            .expect("a topic this client reads")
            .expect("decodes");
        assert_eq!(
            event,
            NodeEvent::Head(HeadEvent {
                slot: 10,
                block: Root::from([0xab; 32]),
                execution_optimistic: false,
            })
        );
    }

    #[test]
    fn an_optimistic_head_says_so() {
        let event = decode(&frame("head", &head_json(10, 0xab, true)))
            .expect("a topic this client reads")
            .expect("decodes");
        assert!(matches!(
            event,
            NodeEvent::Head(HeadEvent {
                execution_optimistic: true,
                ..
            })
        ));
    }

    /// A node that predates `execution_optimistic` does not sync optimistically.
    #[test]
    fn a_head_without_the_optimistic_flag_is_not_optimistic() {
        let data = format!(r#"{{"slot":"3","block":"{}"}}"#, root_hex(1));
        let event = decode(&frame("head", &data))
            .expect("a topic this client reads")
            .expect("decodes");
        assert!(matches!(
            event,
            NodeEvent::Head(HeadEvent {
                execution_optimistic: false,
                ..
            })
        ));
    }

    #[test]
    fn a_payload_available_event_decodes() {
        let data = format!(r#"{{"slot":"12","block_root":"{}"}}"#, root_hex(7));
        let event = decode(&frame("execution_payload_available", &data))
            .expect("a topic this client reads")
            .expect("decodes");
        assert_eq!(
            event,
            NodeEvent::PayloadAvailable(PayloadAvailableEvent {
                slot: 12,
                block_root: Root::from([7; 32]),
            })
        );
    }

    #[test]
    fn a_topic_this_client_does_not_read_is_skipped() {
        assert!(decode(&frame("block", &head_json(1, 1, false))).is_none());
        assert!(decode(&frame("message", "{}")).is_none());
    }

    /// The Beacon API quotes integers; a bare one, or a short root, is an
    /// error rather than a guess.
    #[test]
    fn a_malformed_event_is_an_error() {
        let bare = format!(r#"{{"slot":10,"block":"{}"}}"#, root_hex(1));
        assert!(matches!(
            decode(&frame("head", &bare)),
            Some(Err(Error::Decode(_)))
        ));
        let short = r#"{"slot":"10","block":"0xabcd"}"#;
        assert!(matches!(
            decode(&frame("head", short)),
            Some(Err(Error::Decode(_)))
        ));
    }

    // Over HTTP.

    /// A node serving `body` on `/eth/v1/events` with `status`, recording
    /// each request's query.
    async fn serve(
        status: u16,
        body: String,
    ) -> (
        HttpEventSource,
        std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    ) {
        use axum::response::IntoResponse as _;

        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded = seen.clone();
        let handler = move |uri: axum::http::Uri| {
            let (recorded, body) = (recorded.clone(), body.clone());
            async move {
                recorded
                    .lock()
                    .expect("lock")
                    .push(uri.query().unwrap_or_default().to_string());
                (
                    axum::http::StatusCode::from_u16(status).expect("a status"),
                    [(axum::http::header::CONTENT_TYPE, "text/event-stream")],
                    body,
                )
                    .into_response()
            }
        };
        let app = axum::Router::new().route("/eth/v1/events", axum::routing::get(handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binds");
        let address = listener.local_addr().expect("address");
        tokio::spawn(async move { axum::serve(listener, app).await });
        let source = HttpEventSource::new(format!("http://{address}/")).expect("builds");
        (source, seen)
    }

    /// The stream is read through to the node closing it: keep-alives and
    /// topics this client does not read are skipped, its own are decoded.
    #[tokio::test]
    async fn a_stream_is_read_until_the_node_closes_it() {
        let body = format!(
            ": keep-alive\n\nevent: block\ndata: {{\"slot\":\"9\"}}\n\nevent: head\ndata: {}\n\n",
            head_json(10, 0xab, false)
        );
        let (source, seen) = serve(200, body).await;

        let mut stream = source.subscribe(&[Topic::Head]).await.expect("opens");
        let event = stream.next_event().await.expect("reads");
        assert_eq!(
            event,
            Some(NodeEvent::Head(HeadEvent {
                slot: 10,
                block: Root::from([0xab; 32]),
                execution_optimistic: false,
            }))
        );
        assert_eq!(stream.next_event().await.expect("reads"), None);
        assert_eq!(*seen.lock().expect("lock"), vec!["topics=head".to_string()]);
    }

    #[tokio::test]
    async fn each_topic_is_its_own_query_parameter() {
        let (source, seen) = serve(200, String::new()).await;
        source
            .subscribe(&[Topic::Head, Topic::ExecutionPayloadAvailable])
            .await
            .expect("opens");
        assert_eq!(
            *seen.lock().expect("lock"),
            vec!["topics=head&topics=execution_payload_available".to_string()]
        );
    }

    /// A refused subscription is an error carrying the node's status, so the
    /// caller backs off and asks again.
    #[tokio::test]
    async fn a_refused_subscription_is_an_error() {
        let refusal = r#"{"code":400,"message":"Invalid topic"}"#.to_string();
        let (source, _) = serve(400, refusal).await;
        let refused = source.subscribe(&[Topic::ExecutionPayloadAvailable]).await;
        match refused {
            Err(Error::BeaconNodeStatus { status, body }) => {
                assert_eq!(status, 400);
                assert!(body.contains("Invalid topic"), "body: {body}");
            }
            Err(other) => panic!("expected the node's status, got {other:?}"),
            Ok(_) => panic!("expected the node's status, got a stream"),
        }
    }

    /// A node URL with credentials names the node without them, in logs and
    /// in errors alike: a connection the node refuses reports the URL, and
    /// that error is logged.
    #[tokio::test]
    async fn credentials_stay_out_of_the_name_and_errors() {
        // Bound and dropped, so nothing listens there and the connect fails.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("binds")
            .local_addr()
            .expect("has an address")
            .port();
        let source =
            HttpEventSource::new(format!("http://user:secret@127.0.0.1:{port}/")).expect("builds");
        assert_eq!(source.name(), format!("http://127.0.0.1:{port}"));

        let Err(err) = source.subscribe(&[Topic::Head]).await else {
            panic!("nothing listens, so the subscription fails");
        };
        let shown = format!("{err} {err:?}");
        assert!(!shown.contains("secret"), "leaked: {shown}");
        assert!(!shown.contains("user:"), "leaked: {shown}");
    }
}
