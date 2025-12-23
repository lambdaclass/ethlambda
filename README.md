# ethlambda

Minimalist, fast and modular implementation of the Lean Ethereum client written in Rust.

## Getting started

We use `cargo` as our build system. To build and run the client, simply run:

```sh
cargo run
```

Run `make help` or take a look at our [`Makefile`](./Makefile) for other useful commands.

## Running in a devnet

To quickly spin up a devnet, see [lean-quickstart](https://github.com/blockblaz/lean-quickstart).

## Philosophy

Many long-established clients accumulate bloat over time. This often occurs due to the need to support legacy features for existing users or through attempts to implement overly ambitious software. The result is often complex, difficult-to-maintain, and error-prone systems.

In contrast, our philosophy is rooted in simplicity. We strive to write minimal code, prioritize clarity, and embrace simplicity in design. We believe this approach is the best way to build a client that is both fast and resilient. By adhering to these principles, we will be able to iterate fast and explore next-generation features early.

Read more about our engineering philosophy [in this post of our blog](https://blog.lambdaclass.com/lambdas-engineering-philosophy/).

## Design Principles

- Ensure effortless setup and execution across all target environments.
- Be vertically integrated. Have the minimal amount of dependencies.
- Be structured in a way that makes it easy to build on top of it.
- Have a simple type system. Avoid having generics leaking all over the codebase.
- Have few abstractions. Do not generalize until you absolutely need it. Repeating code two or three times can be fine.
- Prioritize code readability and maintainability over premature optimizations.
- Avoid concurrency split all over the codebase. Concurrency adds complexity. Only use where strictly necessary.

## Roadmap

0. Initial project setup and integration with [lean-quickstart](https://github.com/blockblaz/lean-quickstart)
1. Load network configuration and genesis block
2. Connect to P2P layer and listen for new blocks
3. Compute next chain state from received blocks
4. Receive attestations from peers and apply fork-choice rule
5. Produce and broadcast attestations for the head of the chain
6. Build new blocks and broadcast them to peers
