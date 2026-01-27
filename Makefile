.PHONY: help lint docker-build run-devnet test

help: ## 📚 Show help for each of the Makefile recipes
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

lint: ## 🔍 Run clippy on all workspace crates
	cargo clippy --workspace --all-targets -- -D warnings

test: ## 🧪 Run all tests, then forkchoice tests with skip-signature-verification
	# Tests need to be run on release to avoid stack overflows during signature verification/aggregation
	cargo test --workspace --release
	cargo test -p ethlambda-blockchain --features skip-signature-verification --test forkchoice_spectests

GIT_COMMIT=$(shell git rev-parse HEAD)
GIT_BRANCH=$(shell git rev-parse --abbrev-ref HEAD)

docker-build: ## 🐳 Build the Docker image
	docker build \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		--build-arg GIT_BRANCH=$(GIT_BRANCH) \
		-t ghcr.io/lambdaclass/ethlambda:local .

LEAN_SPEC_COMMIT_HASH:=4edcf7bc9271e6a70ded8aff17710d68beac4266

leanSpec:
	git clone https://github.com/leanEthereum/leanSpec.git --single-branch
	cd leanSpec && git checkout $(LEAN_SPEC_COMMIT_HASH)

leanSpec/fixtures: leanSpec
	cd leanSpec && uv run fill --fork devnet --scheme=prod -o fixtures

lean-quickstart:
	git clone https://github.com/blockblaz/lean-quickstart.git --depth 1 --single-branch


# TODO: start metrics too
run-devnet: docker-build lean-quickstart ## 🚀 Run a local devnet using lean-quickstart
	# Go to lean-quickstart/local-devnet/genesis/validator-config.yaml to modify
	# the validator configuration for the local devnet.
	# NOTE: to run the local image of ethlambda, make sure to set the image tag
	# in lean-quickstart/client-cmds/ethlambda-cmd.sh to "ghcr.io/lambdaclass/ethlambda:local"
	cd lean-quickstart \
	&& NETWORK_DIR=local-devnet ./spin-node.sh --node all --generateGenesis --metrics
