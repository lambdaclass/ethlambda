//! The [Waggle](https://github.com/libp2p/specs/pull/732) pubsub transport,
//! `/waggle/1.0`.
//!
//! Ported from `dknopik/waggle` at `f437548` (branch `alternate-design`, MIT,
//! Copyright 2026 Sigma Prime Pty Ltd), the revision Lighthouse's
//! `pq-devnet-0-waggle` image runs. `behaviour.rs`, `config.rs`, `handler.rs`,
//! `protocol.rs` and `substream.rs` keep that crate's code and notices; the
//! changes are the module paths, building against this workspace's libp2p
//! fork, and [`codec`] in place of `prost-codec`, which that fork does not
//! publish. `waggle.pb.rs` is the crate's generated code for `waggle.proto`,
//! checked in so the build needs no `protoc`.
//!
//! Waggle carries objects split into pieces. Each topic has its own streams:
//! subscribing opens one stream per connection, on which we write a single
//! `TopicSubscription` and then only read the `ObjectPieces` the peer sends.
//! A peer that subscribes to us opens its own stream, and the application is
//! handed a [`handler::PieceSender`] to write to it. What goes to which peer,
//! and peer scoring, are left to the application: objects, topics and piece
//! metadata are opaque bytes here.

pub mod behaviour;
pub mod codec;
pub mod config;
pub mod handler;
mod protocol;
pub(crate) mod substream;

pub use behaviour::{Behaviour, Event};
pub use config::Config;
pub use handler::{ObjectPieces, PieceSender, TopicEvent};
