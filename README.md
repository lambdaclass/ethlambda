# ethlambda

Minimalist, fast and modular implementation of the Lean Ethereum client written in Rust.

## Roadmap

0. Initial project setup and integration with [lean-quickstart](https://github.com/blockblaz/lean-quickstart)
1. Load network configuration and genesis block
2. Connect to P2P layer and listen for new blocks
3. Compute next chain state from received blocks
4. Receive attestations from peers and apply fork-choice rule
5. Produce and broadcast attestations for the head of the chain
6. Build new blocks and broadcast them to peers
