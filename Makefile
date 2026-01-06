.PHONY: help lint run-devnet

help: ## 📚 Show help for each of the Makefile recipes
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

lint: ## 🔍 Run clippy on all workspace crates
	cargo clippy --workspace --all-targets -- -D warnings

# lean-quickstart:
# 	git clone https://github.com/blockblaz/lean-quickstart.git --depth 1 --single-branch

run-devnet: lean-quickstart ## 🚀 Run a local devnet using lean-quickstart
	cargo build \
	&& cd lean-quickstart \
	&& NETWORK_DIR=local-devnet ./spin-node.sh --node ream_0,ethlambda_0 --generateGenesis
