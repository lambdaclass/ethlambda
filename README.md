# ethlambda

Minimalist, fast and modular implementation of the Lean Ethereum client written in Rust.

## Getting started

We use `cargo` as our build system. To build and run the client, simply run:

```sh
cargo run
```

Run `make help` or take a look at our [`Makefile`](./Makefile) for other useful commands.

## Running in a devnet

To run a local devnet with multiple clients using [lean-quickstart](https://github.com/blockblaz/lean-quickstart):

```sh
# Clone lean-quickstart (if not already present)
git clone https://github.com/blockblaz/lean-quickstart.git

# Build the ethlambda Docker image
make docker-build

# Run a 3-client devnet (zeam, ream, ethlambda)
cd lean-quickstart
NETWORK_DIR=local-devnet ./spin-node.sh --node zeam_0,ream_0,ethlambda_0 --generateGenesis --metrics
```

This generates fresh genesis files and starts all three clients with metrics enabled.
Press `Ctrl+C` to stop all nodes.

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

## 📚 References and acknowledgements

The following links, repos, companies and projects have been important in the development of this repo, we have learned a lot from them and want to thank and acknowledge them.

- [Ethereum](https://ethereum.org/en/)
- [LeanEthereum](https://github.com/leanEthereum)
- [Zeam](https://github.com/blockblaz/zeam)

If we forgot to include anyone, please file an issue so we can add you. We always strive to reference the inspirations and code we use, but as an organization with multiple people, mistakes can happen, and someone might forget to include a reference.

## Roadmap

The initial project setup and integration with [lean-quickstart](https://github.com/blockblaz/lean-quickstart) are complete.

### Listen for new blocks

This milestone focuses on connecting to other clients and listening for new blocks through gossipsub.

- Connect to other peers via libp2p ✅
- Respond to STATUS messages from other peers ✅
- Listen for new blocks in gossipsub ✅

### Compute current chain state

This milestone focuses on computing the chain state from the gossiped by peers received.

- Generate initial state from genesis configuration ✅
- Implement state transition function ✅
- Transition state on each new block ✅

### Apply fork-choice rule

This milestone focuses on choosing the head of the chain based on gossiped attestations.

- Listen for attestations in gossipsub ✅
- Implement fork-choice rule ✅
- Apply fork-choice rule based on received attestations ✅

### Produce blocks and attestations

This milestone focuses on performing the duties of a validator.

- Produce and broadcast attestations on each slot ✅
- Compute current proposer for each slot ✅
- Build and broadcast new blocks when proposing ✅
