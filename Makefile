.PHONY: help lint docker-build run-devnet test

help: ## 📚 Show help for each of the Makefile recipes
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

lint: ## 🔍 Run clippy on all workspace crates
	cargo clippy --workspace --all-targets -- -D warnings

test: ## 🧪 Run all tests, then forkchoice tests with skip-signature-verification
	cargo test --workspace
	cargo test -p ethlambda-blockchain --features skip-signature-verification --test forkchoice_spectests

docker-build: ## 🐳 Build the Docker image
	docker build -t ethlambda:latest .

LEAN_SPEC_COMMIT_HASH:=bf0f606a75095cf1853529bc770516b1464d9716

leanSpec:
	git clone https://github.com/leanEthereum/leanSpec.git --single-branch
	cd leanSpec && git checkout $(LEAN_SPEC_COMMIT_HASH)

leanSpec/fixtures: leanSpec
	cd leanSpec && uv run fill --fork devnet --scheme=prod -o fixtures

# lean-quickstart:
# 	git clone https://github.com/blockblaz/lean-quickstart.git --depth 1 --single-branch

run-devnet: docker-build lean-quickstart ## 🚀 Run a local devnet using lean-quickstart
	cargo build \
	&& cd lean-quickstart \
	&& NETWORK_DIR=local-devnet ./spin-node.sh --node zeam_0,ethlambda_0 --generateGenesis --metrics
