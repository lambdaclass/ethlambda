.PHONY: help fmt lint docker-build run-devnet test docs docs-deps docs-serve

help: ## 📚 Show help for each of the Makefile recipes
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

fmt: ## 🎨 Format all code using rustfmt
	cargo fmt --all

lint: ## 🔍 Run clippy on all workspace crates
	cargo clippy --workspace --all-targets -- -D warnings

test: leanSpec/fixtures ## 🧪 Run all tests
	# Tests need to be run on release to avoid stack overflows during signature verification/aggregation
	cargo test --workspace --release

GIT_COMMIT=$(shell git rev-parse HEAD)
GIT_BRANCH=$(shell git rev-parse --abbrev-ref HEAD)
DOCKER_TAG?=local

docker-build: ## 🐳 Build the Docker image
	docker build \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		--build-arg GIT_BRANCH=$(GIT_BRANCH) \
		-t ghcr.io/lambdaclass/ethlambda:$(DOCKER_TAG) .
	@echo

LEAN_SPEC_FIXTURES_URL ?= https://github.com/leanEthereum/leanSpec/releases/latest/download/fixtures-prod-scheme.tar.gz
LEAN_SPEC_FIXTURES_SHA_URL ?= $(LEAN_SPEC_FIXTURES_URL).sha256
# 2026-05-17
LEAN_SPEC_COMMIT_HASH:=f12000bd68a9640cffdfbd9a07503c9112d32bee

leanSpec:
	git clone https://github.com/leanEthereum/leanSpec.git --single-branch

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
# Pre-download the prod keys ourselves before `fill`. The pinned leanSpec
# commit predates leanSpec PR #745, whose `download_keys` reads the still-open
# (unflushed) download tempfile, intermittently truncating the gzip tail and
# aborting with EOFError. A plain curl+tar fully writes the archive before
# reading it, sidestepping the bug. `fill` then sees the keys already present
# and skips its own download. Remove once the pin moves past PR #745.
leanSpec/fixtures: leanSpec
	cd leanSpec && \
		KEYS_URL=$$(uv run python -c "from consensus_testing.keys import KEY_DOWNLOAD_URLS; print(KEY_DOWNLOAD_URLS['prod'])") && \
		KEYS_DIR=packages/testing/src/consensus_testing/test_keys && \
		mkdir -p $$KEYS_DIR && \
		curl -sSL "$$KEYS_URL" -o /tmp/prod_scheme.tar.gz && \
		tar -xzf /tmp/prod_scheme.tar.gz -C $$KEYS_DIR && \
		uv run fill --fork Lstar -n auto --scheme prod -o fixtures

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
