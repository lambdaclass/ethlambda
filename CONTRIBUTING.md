# Contributing to ethlambda

Thanks for your interest in contributing to ethlambda — a minimalist Lean Consensus client for Ethereum, written in Rust.

Before diving in, we recommend reading [our introductory blog post](https://blog.lambdaclass.com/introducing-ethlambda-a-lean-consensus-client-for-ethereums-next-era/) to understand the project's goals and philosophy.

## Philosophy

ethlambda follows the [LambdaClass work ethos](https://blog.lambdaclass.com/): simplicity is not the opposite of capability, but its foundation. Every contribution should uphold this.

- **Lines of code matter.** We track LoC. ethlambda targets staying under a strict limit. If you can remove lines without losing clarity, do it.
- **Vertical integration.** Flat structure, self-explanatory crates. If you can't explain a module in one sentence, it's doing too much.
- **Traits are a last resort.** Reach for concrete types first. Only introduce a trait when you have a proven need for polymorphism.
- **Macros are frowned upon.** They save lines at the cost of debuggability. Avoid them unless there's a very strong justification.
- **Concurrency is contained.** We use the [spawned](https://github.com/lambdaclass/spawned) actor model. Don't spread concurrency throughout the codebase — keep it at the boundaries.
- **No historical baggage.** Lean Consensus is a clean slate. Don't add backward compatibility for deprecated features.

## Project Structure

```
bin/ethlambda/                  # Entry point, CLI, orchestration
crates/
  blockchain/                   # Fork processing actor
  ├─ fork_choice/               # LMD GHOST implementation
  └─ state_transition/          # Process slots, blocks, attestations
  common/
  ├─ types/                     # Core types
  ├─ crypto/                    # XMSS aggregation (leansig wrapper)
  └─ metrics/                   # Prometheus metrics
  net/
  ├─ p2p/                       # libp2p: gossipsub + req-resp
  └─ rpc/                       # HTTP REST API
  storage/                      # Storage API (RocksDB and InMemory backends)
```

## Getting Started

### Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) (stable toolchain)
- [Docker](https://docs.docker.com/get-docker/) (for local devnets)
- [Git](https://git-scm.com/)

### Setup

```bash
git clone https://github.com/lambdaclass/ethlambda.git
cd ethlambda
make lint
make test
```

## How to Submit a Pull Request

1. **Fork** the repository and create your branch from `main`.
2. Make your changes, following the code style and philosophy guidelines.
3. **Run tests locally** to ensure nothing is broken: `make test`
4. **Open a pull request** with a title following the naming rules below, and link related issues.
5. Keep PRs small and focused — one logical change per PR.

### Pull Request Naming Rules

All PR titles must follow the enforced semantic format:

```
<type>: <subject>
```

- **Allowed types:** `feat`, `fix`, `perf`, `refactor`, `revert`, `deps`, `build`, `ci`, `test`, `style`, `chore`, `docs`
- **Subject** must not start with an uppercase character.
- An exclamation mark may be added before the colon to indicate **breaking changes**, e.g. `perf!: change db schema`

**Examples:**

```
fix: handle edge case in signature aggregation
feat: add req-resp protocol for state sync
docs: update leanMetrics coverage notes
```

PRs not following this convention will fail automated checks.

### Commit Signature Verification

All commits must have a verified signature.

- Sign your commits using **GPG or SSH** so that GitHub marks them as "Verified".
- Unsigned or unverified commits may be rejected during review.
- For instructions, see [GitHub: Signing commits](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits).

### Code Style

- **Formatting:** `make fmt` — no exceptions.
- **Linting:** `make lint` must pass with no warnings.
- **Naming:** Descriptive, concise. Follow Rust API guidelines.
- **Comments:** Explain *why*, not *what*. Code should be self-explanatory.
- **Error handling:** Use `Result` and `thiserror`. Avoid `.unwrap()` outside tests.
- **Dependencies:** Adding a new crate requires justification in the PR description.

### Review Process

- All PRs require review and approval by at least one maintainer.
- You may be asked to make changes before merging.
- Automated checks (fmt, lint, tests, PR title) must pass before merge.


## Getting Started: Good First Issues

If you're new to ethlambda, the best way to get involved is by tackling a "good first issue":

👉 [Good First Issues on GitHub](https://github.com/lambdaclass/ethlambda/issues?q=state%3Aopen+label%3A%22good+first+issue%22)

If there are no open good first issues, browse other issues or ask in the Telegram group for guidance.

### Contributions Related to Spelling and Grammar

We do not accept PRs from first-time contributors that only address spelling or grammatical errors. For your initial contribution, please focus on meaningful improvements, bug fixes, or new features.

### Areas Where Help Is Welcome

- **Testing:** Edge cases in state transitions, fork choice scenarios.
- **Metrics:** Expanding Prometheus metrics coverage per leanMetrics spec.
- **Documentation:** Architecture docs, inline documentation, examples.
- **Performance:** Profiling and optimizing for 4-second slot times.
- **Networking:** libp2p gossipsub tuning, req-resp improvements.

## Issue Reporting

Use GitHub Issues to report bugs or request features. Please include:

- Steps to reproduce (minimal sequence to trigger the issue).
- Expected behavior.
- Actual behavior.
- Environment: OS, Rust version, ethlambda commit/branch.
- Relevant logs, Prometheus metrics, or stack traces.

## Running a Local Devnet

ethlambda supports spinning up a local multi-client devnet via [lean-quickstart](https://github.com/pq-ethereum/lean-quickstart). This is the fastest way to test your changes in a realistic environment.

## Security

If you discover a security vulnerability, **do not open a public issue**. Instead, email [security@lambdaclass.com](mailto:security@lambdaclass.com). For more details, refer to our [Security Policy](.github/SECURITY.md).

## Communication

- **Telegram**: [ethlambda group](https://t.me/ethlambda_client) — questions, discussion, coordination
- **X (Twitter)**: Follow [@ethlambda_lean](https://twitter.com/ethlambda_lean) for updates
- **GitHub Issues**: Bugs, feature requests, and technical discussion

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).

---

We appreciate your help in making ethlambda better!
