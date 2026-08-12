# Architecture

The current ethlambda architecture consists of two genservers: one that manages the libp2p swarm (`P2PServer`), which runs in its own thread; and another that manages consensus events (`BlockChainServer`). Both genservers message each other, sending blocks for processing or publishing new blocks, for example. Independent of this, genservers have a reference to the underlying storage engine (the `Store`). Another process, the axum web server, is responsible for exposing data extracted from the running node to the outside world.

> Note: for what a genserver is, read [this blogpost on the `spawned` crate](https://blog.lambdaclass.com/introducing-spawned-erlang-style-actors-for-rust/).

## The `BlockChainServer`

This genserver is responsible for serializing consensus updates and processing consensus events. It uses self-messages on a timer to drive the slot clock, and it receives messages from the `P2PServer` when new blocks or attestations are received.

When each slot interval is reached, the `BlockChainServer` performs any validator duties due in that interval. For example, during the vote propagation interval, it gossips its votes to the network; during the vote aggregation interval, if an aggregator, it aggregates votes received from the network; and so on.

This genserver has an aggregation worker, that concurrently performs vote aggregation. Once enough signatures are received in the vote propagation interval, the aggregation worker is started with a snapshot of the votes received so far. The snapshot includes votes for the current slot and also previous aggregated payloads and signatures for further aggregation. These are selected according to perceived usefulness. Once the aggregation worker finishes, it sends the aggregated payload back to the `BlockChainServer`, which gossips it to the network.

## The `P2PServer`

This genserver is responsible for managing the libp2p swarm, receiving events from it, and sending messages to it. It receives messages from the `BlockChainServer` to gossip new blocks or attestations, forwarding those to the swarm. When new blocks or attestations are received from the network, it sends them to the `BlockChainServer`. The initial bootstrapping of the swarm is done by connecting to a set of bootstrap nodes given by the user.

Block requests sent by the `BlockChainServer` are handled by `P2PServer` too, which forwards them to the swarm. Any failed requests are retried a number of times before giving up.

## `Store`

The `Store` follows a similar approach as ethrex's. It is a safe and easy to use interface, that uses a pluggable key-value store (`StorageBackend`) as the underlying storage. The `Store` is used by the whole node to access heavy data, with the `BlockChainServer` being the only writer of consensus state.

## HTTP API

We use `axum` as our API router. API requests are served in tokio tasks. We use the same router to serve metrics, but these can be configured to be served in different ports.
