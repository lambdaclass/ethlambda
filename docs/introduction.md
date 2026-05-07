# Introduction

**ethlambda** is a minimalist, fast and modular implementation of the Lean Ethereum
consensus client, written in Rust.

This book collects the design notes and operator-facing references for ethlambda.
It is split into two parts:

- **Consensus** explains the algorithms ethlambda implements: the
  [3SF-mini](./3sf_mini.md) justification and finalization rules, and the
  [LMD-GHOST](./lmd_ghost.md) fork choice algorithm. Both documents are
  implementation-agnostic; ethlambda-specific behaviour is called out in
  blockquotes.
- **Operations** documents observable surfaces of a running node:
  [Prometheus metrics](./metrics.md), [checkpoint sync](./checkpoint_sync.md),
  and the [fork choice visualization](./fork_choice_visualization.md) served
  by the API.

For build and contribution instructions, see the
[`README`](https://github.com/lambdaclass/ethlambda/blob/main/README.md) and
[`CONTRIBUTING.md`](https://github.com/lambdaclass/ethlambda/blob/main/CONTRIBUTING.md)
in the repository.

## Visual references

Two standalone HTML infographics ship alongside this book and are copied verbatim
into the rendered output:

- [3SF-mini infographic](./infographics/3sf-mini-infographic.html)
- [ethlambda architecture infographic](./infographics/ethlambda_architecture.html)

## Related projects

ethlambda is one of several Lean Ethereum consensus clients under active development.
For comparison and cross-client testing:

- [zeam](https://github.com/blockblaz/zeam) (Zig)
- [ream](https://github.com/ReamLabs/ream) (Rust)
- [qlean](https://github.com/qdrvm/qlean-mini) (C++)
- [grandine](https://github.com/grandinetech/lean/tree/main/lean_client) (Rust)
- [gean](https://github.com/devlongs/gean) (Go)
- [Lantern](https://github.com/Pier-Two/lantern) (C)
