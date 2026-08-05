.PHONY: help fmt lint docker-build shadow-build shadow-docker-build run-devnet test test-beacon consensus-spec-tests docs docs-deps docs-serve

help: ## 📚 Show help for each of the Makefile recipes
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

fmt: ## 🎨 Format all code using rustfmt
	cargo fmt --all

lint: ## 🔍 Run clippy on all workspace crates
	cargo clippy --workspace --all-targets -- -D warnings

test: leanSpec/fixtures ## 🧪 Run all tests
	# release-fast: release-grade opt-level to avoid stack overflows during
	# signature verification/aggregation, without paying for LTO on every rebuild
	#
	# ethlambda-beacon is excluded and has its own target: its fixtures are a
	# separate multi-gigabyte download, and it has to be built once per preset.
	cargo test --workspace --exclude ethlambda-beacon --profile release-fast

test-beacon: consensus-spec-tests ## 🧪 Run the Beacon Chain spec tests, both presets
	# The preset fixes SSZ container bounds at compile time, so each preset needs
	# its own build of the crate. Each run walks only its own fixture tree.
	cargo test -p ethlambda-beacon --profile release-fast
	cargo test -p ethlambda-beacon --profile release-fast --features preset-minimal

GIT_COMMIT=$(shell git rev-parse HEAD)
GIT_BRANCH=$(shell git rev-parse --abbrev-ref HEAD)
DOCKER_TAG?=local

docker-build: ## 🐳 Build the Docker image
	docker build \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		--build-arg GIT_BRANCH=$(GIT_BRANCH) \
		-t ghcr.io/lambdaclass/ethlambda:$(DOCKER_TAG) .
	@echo

shadow-build: ## 👻 Build a Shadow-simulator-compatible binary (single-threaded, no jemalloc)
	./shadow/build.sh cargo build --release --no-default-features --features shadow-integration --bin ethlambda

shadow-docker-build: ## 👻🐳 Build a Shadow-compatible Docker image
	docker build \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		--build-arg GIT_BRANCH=$(GIT_BRANCH) \
		--build-arg SHADOW=1 \
		--build-arg FEATURES=shadow-integration \
		--build-arg NO_DEFAULT_FEATURES=--no-default-features \
		--build-arg LOCKED= \
		-t ghcr.io/lambdaclass/ethlambda:$(DOCKER_TAG)-shadow .
	@echo

LEAN_SPEC_FIXTURES_URL ?= https://github.com/leanEthereum/leanSpec/releases/latest/download/fixtures-prod-scheme.tar.gz
LEAN_SPEC_FIXTURES_SHA_URL ?= $(LEAN_SPEC_FIXTURES_URL).sha256

leanSpec/fixtures:
	tmpdir=$$(mktemp -d); \
	trap 'rm -rf "$$tmpdir"' EXIT; \
	curl -L -f -o "$$tmpdir/fixtures-prod-scheme.tar.gz" "$(LEAN_SPEC_FIXTURES_URL)"; \
	curl -L -f -o "$$tmpdir/fixtures-prod-scheme.tar.gz.sha256" "$(LEAN_SPEC_FIXTURES_SHA_URL)"; \
	expected=$$(cut -d' ' -f1 "$$tmpdir/fixtures-prod-scheme.tar.gz.sha256"); \
	actual=$$(sha256sum "$$tmpdir/fixtures-prod-scheme.tar.gz" | awk '{print $$1}'); \
	if [ "$$expected" != "$$actual" ]; then \
		echo "SHA256 mismatch: expected $$expected, got $$actual" >&2; \
		exit 1; \
	fi; \
	rm -rf leanSpec/fixtures; \
	mkdir -p leanSpec/fixtures; \
	tar -xzf "$$tmpdir/fixtures-prod-scheme.tar.gz" -C leanSpec/fixtures --strip-components=1

# Beacon Chain spec test fixtures, for crates/beacon.
#
# Pinned rather than tracking the latest release: this fixture tree *is* the
# definition of correctness for that crate, so it should move only when we choose
# to move it. The release publishes no checksums for these assets, so unlike the
# leanSpec bundle below there is nothing to verify against.
CONSENSUS_SPEC_TESTS_VERSION ?= v1.6.1
CONSENSUS_SPEC_TESTS_BASE_URL ?= https://github.com/ethereum/consensus-specs/releases/download/$(CONSENSUS_SPEC_TESTS_VERSION)

consensus-spec-tests: consensus-spec-tests/tests/general consensus-spec-tests/tests/minimal consensus-spec-tests/tests/mainnet ## ⬇️ Download the Beacon Chain spec test fixtures

# Every tarball unpacks to `tests/<name>/...`, so all three extract into the same
# directory and land side by side.
consensus-spec-tests/tests/%:
	@mkdir -p consensus-spec-tests
	@echo "Downloading $* spec test fixtures ($(CONSENSUS_SPEC_TESTS_VERSION))"
	@tmpdir=$$(mktemp -d); \
	trap 'rm -rf "$$tmpdir"' EXIT; \
	curl -L -f -o "$$tmpdir/$*.tar.gz" "$(CONSENSUS_SPEC_TESTS_BASE_URL)/$*.tar.gz"; \
	tar -xzf "$$tmpdir/$*.tar.gz" -C consensus-spec-tests

lean-quickstart:
	git clone https://github.com/blockblaz/lean-quickstart.git --depth 1 --single-branch

run-devnet: docker-build lean-quickstart ## 🚀 Run a local devnet using lean-quickstart
	@# Remove local devnet data folder to avoid stale data
	@# NOTE: --cleanData flag in spin-node.sh doesn't work
	@rm -rf lean-quickstart/local-devnet/data/
	@echo "Starting local devnet with ethlambda client (\"$(DOCKER_TAG)\" tag). Logs will be dumped in devnet.log, and metrics served in http://localhost:3000"
	@echo
	@echo "Devnet will be using the current configuration. For custom configurations, modify lean-quickstart/local-devnet/genesis/validator-config.yaml and restart the devnet."
	@echo
	@# Use temp file instead of sed -i for macOS/GNU portability
	@sed 's|ghcr.io/lambdaclass/ethlambda:[^ ]*|ghcr.io/lambdaclass/ethlambda:$(DOCKER_TAG)|' lean-quickstart/client-cmds/ethlambda-cmd.sh > lean-quickstart/client-cmds/ethlambda-cmd.sh.tmp \
		&& mv lean-quickstart/client-cmds/ethlambda-cmd.sh.tmp lean-quickstart/client-cmds/ethlambda-cmd.sh
	@echo "Starting local devnet. Press Ctrl+C to stop all nodes."
	@cd lean-quickstart \
		&& NETWORK_DIR=local-devnet ./spin-node.sh --node all --generateGenesis --metrics > ../devnet.log 2>&1

docs-deps: ## 📦 Install dependencies for generating the documentation
	cargo install --version 0.5.2 --locked mdbook
	cargo install --version 0.12.0 --locked mdbook-linkcheck2

docs: ## 📚 Generate the documentation site under ./book
	mdbook build

docs-serve: ## 📖 Serve the documentation locally with live reload
	mdbook serve --open
