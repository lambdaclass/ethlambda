// Ported from dknopik/waggle's tests/swarm.rs at f437548 (MIT, see
// src/waggle/mod.rs), against this crate's port of the transport.
//! End-to-end tests through the public API: real swarms connected over the
//! memory transport, exchanging pieces on the channels handed to the
//! application.

use std::{
    num::NonZeroUsize,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use async_channel::{Receiver, Sender, TrySendError};
use ethlambda_p2p::waggle::{
    behaviour::{Behaviour, Event},
    config::Config,
    handler::{ObjectPieces, PieceSender, TopicEvent},
};
use futures::StreamExt;
use libp2p::{
    Multiaddr, PeerId, Swarm, SwarmBuilder,
    core::{Transport, transport::MemoryTransport, upgrade::Version},
    plaintext,
    swarm::SwarmEvent,
    yamux,
};

const TOPIC: &[u8] = b"topic";
const TIMEOUT: Duration = Duration::from_secs(5);

/// Instructions for a node's swarm task.
enum Command {
    Dial(Multiaddr),
    /// Subscribes to [`TOPIC`], replying with the topic's receiver.
    Subscribe(Sender<Receiver<TopicEvent>>),
    Disconnect(PeerId),
}

/// A swarm subscribed to [`TOPIC`] and listening on a memory address, driven
/// by its own task. The test talks to it through channels.
/// A distinct in-memory address per node: tests in this binary run in
/// parallel, so the counter starts from the process id to keep two test
/// binaries' nodes apart as well.
fn next_memory_port() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    (u64::from(std::process::id()) << 32) + NEXT.fetch_add(1, Ordering::Relaxed) + 1
}

struct Node {
    peer_id: PeerId,
    addr: Multiaddr,
    commands: Sender<Command>,
    events: Receiver<Event>,
    /// The receiver of [`TOPIC`]'s events, until the test unsubscribes.
    topic: Option<Receiver<TopicEvent>>,
}

impl Node {
    fn spawn(config: Config) -> Self {
        let mut swarm: Swarm<Behaviour> = SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_other_transport(|key| {
                MemoryTransport::default()
                    .upgrade(Version::V1)
                    .authenticate(plaintext::Config::new(key))
                    .multiplex(yamux::Config::default())
            })
            .unwrap()
            .with_behaviour(|_| Behaviour::new(config))
            .unwrap()
            .with_swarm_config(|config| {
                config.with_idle_connection_timeout(Duration::from_secs(60))
            })
            .build();
        let peer_id = *swarm.local_peer_id();
        let addr: Multiaddr = format!("/memory/{}", next_memory_port()).parse().unwrap();
        swarm.listen_on(addr.clone()).unwrap();
        let topic = swarm.behaviour_mut().subscribe(TOPIC.to_vec());

        let (commands, command_rx) = async_channel::unbounded();
        let (event_tx, events) = async_channel::unbounded();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    command = command_rx.recv() => match command {
                        Ok(Command::Dial(addr)) => swarm.dial(addr).unwrap(),
                        Ok(Command::Subscribe(reply)) => {
                            let topic = swarm.behaviour_mut().subscribe(TOPIC.to_vec());
                            let _ = reply.try_send(topic.expect("already subscribed"));
                        }
                        Ok(Command::Disconnect(peer_id)) => {
                            let _ = swarm.disconnect_peer_id(peer_id);
                        }
                        Err(_) => return,
                    },
                    event = swarm.select_next_some() => {
                        if let SwarmEvent::Behaviour(event) = event {
                            let _ = event_tx.try_send(event);
                        }
                    }
                }
            }
        });

        Self {
            peer_id,
            addr,
            commands,
            events,
            topic,
        }
    }

    fn command(&self, command: Command) {
        self.commands.try_send(command).unwrap();
    }

    /// Unsubscribes from [`TOPIC`] by dropping its receiver.
    fn unsubscribe(&mut self) {
        self.topic = None;
    }

    /// Subscribes to [`TOPIC`] again.
    async fn subscribe(&mut self) {
        let (reply, topic) = async_channel::bounded(1);
        self.command(Command::Subscribe(reply));
        self.topic = Some(topic.recv().await.expect("node stopped"));
    }

    /// The receiver of [`TOPIC`]'s events.
    fn topic(&self) -> &Receiver<TopicEvent> {
        self.topic.as_ref().expect("not subscribed")
    }

    /// Waits for the next behaviour event.
    async fn next(&self) -> Event {
        tokio::time::timeout(TIMEOUT, self.events.recv())
            .await
            .expect("timed out waiting for an event")
            .expect("node stopped")
    }

    /// Waits for the next event on [`TOPIC`].
    async fn next_topic_event(&self) -> TopicEvent {
        tokio::time::timeout(TIMEOUT, self.topic().recv())
            .await
            .expect("timed out waiting for a topic event")
            .expect("topic receiver closed")
    }

    /// Asserts that no behaviour or topic event arrives for a while.
    async fn no_event(&self) {
        if let Ok(event) =
            tokio::time::timeout(Duration::from_millis(300), self.events.recv()).await
        {
            panic!("unexpected event {event:?}");
        }
        if let Some(Ok(event)) = self.topic.as_ref().map(Receiver::try_recv) {
            panic!("unexpected topic event {event:?}");
        }
    }

    /// Waits for `peer`'s subscription to [`TOPIC`], and returns the sender to
    /// it.
    async fn subscribed(&self, peer: PeerId) -> PieceSender {
        match self.next().await {
            Event::Subscribed {
                peer_id,
                topic_id,
                sender,
                ..
            } => {
                assert_eq!(peer_id, peer);
                assert_eq!(topic_id, TOPIC);
                sender
            }
            event => panic!("unexpected event {event:?}"),
        }
    }

    /// Waits for the end of `peer`'s subscription to [`TOPIC`].
    async fn unsubscribed(&self, peer: PeerId) {
        match self.next().await {
            Event::Unsubscribed {
                peer_id, topic_id, ..
            } => {
                assert_eq!(peer_id, peer);
                assert_eq!(topic_id, TOPIC);
            }
            event => panic!("unexpected event {event:?}"),
        }
    }

    /// Waits for our subscription stream to `peer` to open.
    async fn opened(&self, peer: PeerId) {
        match self.next_topic_event().await {
            TopicEvent::Opened { peer_id, .. } => assert_eq!(peer_id, peer),
            event => panic!("unexpected topic event {event:?}"),
        }
    }

    /// Waits for the next pieces from `peer`.
    async fn recv(&self, peer: PeerId) -> ObjectPieces {
        match self.next_topic_event().await {
            TopicEvent::Pieces {
                peer_id, pieces, ..
            } => {
                assert_eq!(peer_id, peer);
                pieces
            }
            event => panic!("unexpected topic event {event:?}"),
        }
    }

    /// Waits for our subscription stream to `peer` to close.
    async fn closed(&self, peer: PeerId) {
        match self.next_topic_event().await {
            TopicEvent::Closed { peer_id, .. } => assert_eq!(peer_id, peer),
            event => panic!("unexpected topic event {event:?}"),
        }
    }
}

/// Connects `a` to `b` and returns each side's sender to the other, once
/// both subscription streams are open.
async fn connect(a: &Node, b: &Node) -> (PieceSender, PieceSender) {
    a.command(Command::Dial(b.addr.clone()));
    let a_b = a.subscribed(b.peer_id).await;
    let b_a = b.subscribed(a.peer_id).await;
    a.opened(b.peer_id).await;
    b.opened(a.peer_id).await;
    (a_b, b_a)
}

fn pieces(i: u8) -> ObjectPieces {
    ObjectPieces {
        object_id: vec![i].into(),
        metadata: Some(vec![i, i].into()),
        pieces: Some(vec![i; 3].into()),
    }
}

/// Pieces with a 32 KiB payload, so a few of them fill the transport's
/// buffers.
fn large_pieces(i: u32) -> ObjectPieces {
    ObjectPieces {
        object_id: i.to_be_bytes().to_vec().into(),
        metadata: None,
        pieces: Some(vec![0; 32 * 1024].into()),
    }
}

#[tokio::test]
async fn pieces_flow_both_ways() {
    let a = Node::spawn(Config::default());
    let b = Node::spawn(Config::default());
    let (a_b, b_a) = connect(&a, &b).await;

    a_b.try_send(pieces(1)).unwrap();
    assert_eq!(b.recv(a.peer_id).await, pieces(1));
    b_a.try_send(pieces(2)).unwrap();
    assert_eq!(a.recv(b.peer_id).await, pieces(2));

    a.no_event().await;
    b.no_event().await;
}

#[tokio::test]
async fn pieces_from_all_peers_share_the_receiver() {
    let a = Node::spawn(Config::default());
    let b = Node::spawn(Config::default());
    let c = Node::spawn(Config::default());
    let (_a_b, b_a) = connect(&a, &b).await;
    let (_a_c, c_a) = connect(&a, &c).await;

    b_a.try_send(pieces(1)).unwrap();
    assert_eq!(a.recv(b.peer_id).await, pieces(1));
    c_a.try_send(pieces(2)).unwrap();
    assert_eq!(a.recv(c.peer_id).await, pieces(2));
}

#[tokio::test]
async fn full_receive_queue_pauses_reading() {
    let a = Node::spawn(Config::default().set_max_send_queue_limit(NonZeroUsize::new(10).unwrap()));
    let b = Node::spawn(Config::default().set_max_receive_queue_len(NonZeroUsize::new(2).unwrap()));
    let (a_b, _b_a) = connect(&a, &b).await;

    // B stops reading once its receive queue is full. The transport's
    // buffers fill next, then A's send queue, which stays full instead of
    // draining. A queue full for a short while only means A sent faster than
    // its writer drains.
    let mut sent = 0;
    let mut full_polls = 0;
    tokio::time::timeout(TIMEOUT, async {
        while full_polls < 30 {
            match a_b.try_send(large_pieces(sent)) {
                Ok(()) => {
                    sent += 1;
                    full_polls = 0;
                    tokio::task::yield_now().await;
                }
                Err(TrySendError::Full(_)) => {
                    full_polls += 1;
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(TrySendError::Closed(_)) => panic!("subscription closed"),
            }
        }
    })
    .await
    .expect("send queue did not stay full");
    assert!(b.topic().is_full());

    // Draining the queue resumes reading, without losing pieces.
    for i in 0..sent {
        assert_eq!(b.recv(a.peer_id).await, large_pieces(i));
    }
}

#[tokio::test]
async fn send_queue_limit() {
    let a = Node::spawn(Config::default().set_max_send_queue_limit(NonZeroUsize::new(3).unwrap()));
    let b = Node::spawn(Config::default());
    let (a_b, _b_a) = connect(&a, &b).await;

    // Nothing runs between these sends on the current-thread runtime.
    for i in 0..3 {
        a_b.try_send(pieces(i)).unwrap();
    }
    assert!(matches!(
        a_b.try_send(pieces(3)),
        Err(TrySendError::Full(_))
    ));
    for i in 0..3 {
        assert_eq!(b.recv(a.peer_id).await, pieces(i));
    }

    // The writer made room as it drained the queue.
    a_b.try_send(pieces(4)).unwrap();
    assert_eq!(b.recv(a.peer_id).await, pieces(4));
}

#[tokio::test]
async fn dropping_receiver_unsubscribes() {
    let a = Node::spawn(Config::default());
    let mut b = Node::spawn(Config::default());
    let (a_b, b_a) = connect(&a, &b).await;

    b.unsubscribe();
    a.unsubscribed(b.peer_id).await;
    assert!(matches!(
        a_b.try_send(pieces(0)),
        Err(TrySendError::Closed(_))
    ));

    // A's subscription to B is untouched.
    b_a.try_send(pieces(1)).unwrap();
    assert_eq!(a.recv(b.peer_id).await, pieces(1));
}

#[tokio::test]
async fn subscribing_again_after_dropping_receiver() {
    let a = Node::spawn(Config::default());
    let mut b = Node::spawn(Config::default());
    let (_a_b, _b_a) = connect(&a, &b).await;

    b.unsubscribe();
    a.unsubscribed(b.peer_id).await;

    // The subscription opens again on the existing connection.
    b.subscribe().await;
    let a_b = a.subscribed(b.peer_id).await;
    b.opened(a.peer_id).await;
    a_b.try_send(pieces(0)).unwrap();
    assert_eq!(b.recv(a.peer_id).await, pieces(0));
}

#[tokio::test]
async fn dropping_sender_ends_subscription() {
    let a = Node::spawn(Config::default());
    let b = Node::spawn(Config::default().set_max_receive_queue_len(NonZeroUsize::new(1).unwrap()));
    let (a_b, _b_a) = connect(&a, &b).await;

    // The piece fills B's receive queue, so the end of the stream waits for
    // room behind it.
    a_b.try_send(pieces(0)).unwrap();
    drop(a_b);
    a.unsubscribed(b.peer_id).await;
    assert_eq!(b.recv(a.peer_id).await, pieces(0));
    b.closed(a.peer_id).await;
}

#[tokio::test]
async fn connection_close_ends_everything() {
    let a = Node::spawn(Config::default());
    let b = Node::spawn(Config::default());
    let (a_b, b_a) = connect(&a, &b).await;

    a.command(Command::Disconnect(b.peer_id));
    a.unsubscribed(b.peer_id).await;
    b.unsubscribed(a.peer_id).await;
    a.closed(b.peer_id).await;
    b.closed(a.peer_id).await;
    a.no_event().await;
    b.no_event().await;

    assert!(matches!(
        a_b.try_send(pieces(0)),
        Err(TrySendError::Closed(_))
    ));
    assert!(matches!(
        b_a.try_send(pieces(0)),
        Err(TrySendError::Closed(_))
    ));
}

#[tokio::test]
async fn connection_close_delivers_waiting_pieces() {
    let a = Node::spawn(Config::default());
    let b = Node::spawn(Config::default().set_max_receive_queue_len(NonZeroUsize::new(1).unwrap()));
    let (a_b, _b_a) = connect(&a, &b).await;

    // The first piece fills B's receive queue, the second waits for room.
    a_b.try_send(pieces(0)).unwrap();
    a_b.try_send(pieces(1)).unwrap();
    tokio::time::timeout(TIMEOUT, async {
        while !b.topic().is_full() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("receive queue did not fill");
    tokio::time::sleep(Duration::from_millis(100)).await;

    // The full receive queue does not hold up closing the connection: A sees
    // it close before B drains the queue.
    b.command(Command::Disconnect(a.peer_id));
    b.unsubscribed(a.peer_id).await;
    a.unsubscribed(b.peer_id).await;
    a.closed(b.peer_id).await;

    assert_eq!(b.recv(a.peer_id).await, pieces(0));
    assert_eq!(b.recv(a.peer_id).await, pieces(1));
    b.closed(a.peer_id).await;
}
