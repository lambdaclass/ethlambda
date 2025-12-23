# ethlambda

Minimalist, fast and modular implementation of the Lean Ethereum client written in Rust.

## Roadmap

0. Initial project setup and integration with [lean-quickstart](https://github.com/blockblaz/lean-quickstart)
1. Load initial state from network configuration file
2. Connect to P2P layer and listen for new blocks from peers
3. Compute next state based on received blocks
4. Receive attestations from peers and apply fork-choice rule to actively determine the head of the chain
