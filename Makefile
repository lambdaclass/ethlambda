.PHONY: help fmt lint docker-build run-devnet test

help: ## 📚 Show help for each of the Makefile recipes
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

fmt: ## 🎨 Format all code using rustfmt
	cargo fmt --all

lint: ## 🔍 Run clippy on all workspace crates
	cargo clippy --workspace --all-targets -- -D warnings

test: leanSpec/fixtures ## 🧪 Run all tests, then forkchoice tests with skip-signature-verification
	# Tests need to be run on release to avoid stack overflows during signature verification/aggregation
	cargo test --workspace --release
	cargo test -p ethlambda-blockchain --features skip-signature-verification --test forkchoice_spectests

GIT_COMMIT=$(shell git rev-parse HEAD)
GIT_BRANCH=$(shell git rev-parse --abbrev-ref HEAD)
DOCKER_TAG?=local

docker-build: ## 🐳 Build the Docker image
	docker build \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		--build-arg GIT_BRANCH=$(GIT_BRANCH) \
		-t ghcr.io/lambdaclass/ethlambda:$(DOCKER_TAG) .
	@echo

LEAN_SPEC_COMMIT_HASH:=4edcf7bc9271e6a70ded8aff17710d68beac4266

leanSpec:
	git clone https://github.com/leanEthereum/leanSpec.git --single-branch
	cd leanSpec && git checkout $(LEAN_SPEC_COMMIT_HASH)

leanSpec/fixtures: leanSpec
	cd leanSpec && uv run fill --fork devnet --scheme=prod -o fixtures

lean-quickstart:
	git clone https://github.com/blockblaz/lean-quickstart.git --depth 1 --single-branch

run-devnet: docker-build lean-quickstart ## 🚀 Run a local devnet using lean-quickstart
	@echo "Starting local devnet with ethlambda client. Logs will be dumped in devnet.log"
	@echo
	@echo "Devnet will be using the current configuration. For custom configurations, modify lean-quickstart/local-devnet/genesis/validator-config.yaml and restart the devnet."
	@echo
	@# Use temp file instead of sed -i for macOS/GNU portability
	@sed 's|ghcr.io/lambdaclass/ethlambda:[^ ]*|ghcr.io/lambdaclass/ethlambda:local|' lean-quickstart/client-cmds/ethlambda-cmd.sh > lean-quickstart/client-cmds/ethlambda-cmd.sh.tmp \
		&& mv lean-quickstart/client-cmds/ethlambda-cmd.sh.tmp lean-quickstart/client-cmds/ethlambda-cmd.sh
	@echo "Starting local devnet. Press Ctrl+C to stop all nodes."
	@cd lean-quickstart \
		&& NETWORK_DIR=local-devnet ./spin-node.sh --node all --generateGenesis --metrics > devnet.log 2>&1
