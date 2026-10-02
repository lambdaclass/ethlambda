.PHONY: help fmt lint bench update cooldown-check docker-build shadow-build shadow-docker-build run-devnet test test-consensus test-node test-beacon test-beacon-mainnet test-beacon-minimal consensus-spec-tests cryptography-specs docs docs-deps docs-serve

help: ## 📚 Show help for each of the Makefile recipes
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

fmt: ## 🎨 Format all code using rustfmt
	cargo fmt --all

lint: ## 🔍 Run clippy on all workspace crates
	cargo clippy --locked --workspace --all-targets -- -D warnings
	# The spectests are `test = false` (stale leanSpec fixtures), which
	# `--all-targets` skips: lint them by name so they keep compiling
	cargo clippy --locked --workspace --test forkchoice_spectests --test signature_spectests --test stf_spectests --test ssz_spectests -- -D warnings

# release-fast: release-grade opt-level to avoid stack overflows during
# signature verification/aggregation, without paying for LTO on every rebuild
#
# The Beacon Chain spec tests have their own target and are not run here: their
# fixtures are a separate multi-gigabyte download, and the suite has to be built
# once per preset. The `--exclude` flags below only divide the halves: the
# beacon target requires the `beacon-spec-tests` feature, so these commands skip
# it without excluding anything.
TEST=cargo test --locked --profile release-fast

# Two halves, one CI job each: undivided, a release-grade build of every test
# target measured 14 GiB against the 13-14 GiB a stock runner has free. Both
# halves build the shared dependency graph, so what the split halves is the
# linked test binaries.
#
# Named once, and `test-node` is the workspace minus this list, so the two are
# exhaustive by construction and a crate added later cannot silently go
# untested. Keep them roughly even by build weight; the boundary means nothing
# else.
CONSENSUS_CRATES=ethlambda-types ethlambda-fork-choice ethlambda-state-transition ethlambda-blockchain ethlambda-crypto ethlambda-ssz-tree

test: test-consensus test-node ## 🧪 Run all tests

test-consensus: leanSpec/fixtures ## 🧪 Run the consensus half of the workspace suite
	$(TEST) $(addprefix -p ,$(CONSENSUS_CRATES))

test-node: leanSpec/fixtures ## 🧪 Run the node half of the workspace suite
	$(TEST) --workspace $(addprefix --exclude ,$(CONSENSUS_CRATES))

# --lib as well as the spec target: the BLS and KZG modules keep their fixture
# vectors as unit tests, which are `ignore`d unless this feature is on.
BEACON_TEST=cargo test -p ethlambda-state-transition --lib --test beacon_spec_tests --profile release-fast

# The preset fixes SSZ container bounds at compile time, so each preset needs its
# own build, and a run walks its own preset's fixture tree and nothing else; the
# BLS and KZG vectors are a separate, preset-independent download
# (`cryptography-specs`). Hence a target per preset rather than one recipe
# running both: CI gives each its own job, so the two build and run
# concurrently and each downloads only the trees its preset reads.
test-beacon: test-beacon-mainnet test-beacon-minimal ## 🧪 Run the Beacon Chain spec tests, both presets

test-beacon-mainnet: consensus-spec-tests cryptography-specs ## 🧪 Run the Beacon Chain spec tests, mainnet preset
	$(BEACON_TEST) --features beacon-spec-tests

test-beacon-minimal: consensus-spec-tests cryptography-specs ## 🧪 Run the Beacon Chain spec tests, minimal preset
	$(BEACON_TEST) --features beacon-spec-tests,preset-minimal

# Used ONLY to resolve dependency updates: min-publish-age (.cargo/config.toml)
# is nightly-only, everything else runs on the stable toolchain pinned in
# rust-toolchain.toml.
RESOLVER_TOOLCHAIN := nightly-2026-06-21

# Versions published less than 14 days ago are excluded from resolution.
# Resolution done on stable (`cargo add`, plain `cargo update`) is NOT covered;
# this target is the intended path for routine updates. Git dependencies have
# no publish age and are refreshed WITHOUT any cooldown: review their lockfile
# rev changes manually.
update: ## 📦 Update dependencies under the publish-age cooldown (UPDATE_ARGS="-p foo")
	rustup toolchain install $(RESOLVER_TOOLCHAIN) --profile minimal > /dev/null && \
	cargo +$(RESOLVER_TOOLCHAIN) update -Z min-publish-age $(UPDATE_ARGS)

# Stable cargo ignores the cooldown, so a lockfile can pin too-young crates;
# same check as the CI `cooldown` job, without touching the files. A cooldown
# downgrade is annotated with the too-young version's publish date; downgrades
# for other reasons carry no such note and are not flagged.
cooldown-check: ## 🔎 Fail if a lockfile pins crates younger than the publish-age cooldown
	@rustup toolchain install $(RESOLVER_TOOLCHAIN) --profile minimal > /dev/null && \
	status=0; \
	for manifest in Cargo.toml tooling/event-monitor/Cargo.toml; do \
		if ! out=$$(cargo +$(RESOLVER_TOOLCHAIN) update --dry-run -Z min-publish-age --manifest-path $$manifest 2>&1); then \
			echo "WARNING: publish-age cooldown probe failed for $$manifest:"; echo "$$out" | grep -v "^ *Updating " | head -20; continue; \
		fi; \
		hits=$$(echo "$$out" | grep -E "^ *Downgrading .*published" || true); \
		if [ -n "$$hits" ]; then echo "ERROR: $$manifest pins crates younger than the publish-age cooldown:"; echo "$$hits"; status=1; fi; \
	done; \
	exit $$status

BENCH_ARGS ?= synthetic --mock-crypto

bench: ## 🏁 Benchmark block building offline (override BENCH_ARGS to customize)
	cargo run --release --bin ethlambda -- benchmark $(BENCH_ARGS)

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

# Beacon Chain spec test fixtures, for the `beacon` module of
# crates/blockchain/state_transition.
#
# Pinned rather than tracking the latest release: this fixture tree *is* the
# definition of correctness for that module, so it should move only when we choose
# to move it. The release publishes no checksums for these assets, so unlike the
# leanSpec bundle below there is nothing to verify against.
CONSENSUS_SPEC_TESTS_VERSION ?= v1.7.0-beta.2
CONSENSUS_SPEC_TESTS_BASE_URL ?= https://github.com/ethereum/consensus-specs/releases/download/$(CONSENSUS_SPEC_TESTS_VERSION)

# Which fixture trees to fetch. A run reads its own preset's tree and nothing
# else, so a CI job pinned to one preset narrows this and skips the other
# preset's tree. `general` is gone from the list: since v1.7.0-alpha.13
# (consensus-specs #5398) its KZG vectors live only in
# ethereum/cryptography-specs, and what is left of it (the BLS suites) ships
# there too (see `cryptography-specs` below).
CONSENSUS_SPEC_TESTS_CONFIGS ?= minimal mainnet

# The stamp is named after the version AND the configs, so changing either names
# a file that does not exist and forces a fresh download. Depending on the
# extracted directories instead would make a bump a silent no-op: they already
# exist, make would consider them up to date, and the suite would go green
# against the old tree while the docs claimed the new version. Nothing in the
# fixtures themselves records which release they came from, so the stamp is the
# only thing that can carry it.
#
# The configs belong in the name for the same reason: the recipe wipes the tree
# before extracting, so a narrowed run leaves the other preset's tree gone, and a
# stamp naming only the version would then mark a partial tree as complete.
# `sort` normalises order and duplicates, so the same set always names one stamp.
empty:=
space:=$(empty) $(empty)
CONSENSUS_SPEC_TESTS_STAMP=consensus-spec-tests/.version-$(CONSENSUS_SPEC_TESTS_VERSION)-$(subst $(space),-,$(sort $(CONSENSUS_SPEC_TESTS_CONFIGS)))

consensus-spec-tests: $(CONSENSUS_SPEC_TESTS_STAMP) ## ⬇️ Download the Beacon Chain spec test fixtures

# The old tree goes first, rather than being extracted over: every tarball
# unpacks to `tests/<name>/...`, so all three land side by side in one directory,
# and unpacking a new version on top of an old one would merge the two, leaving
# cases a release deleted still present and still passing.
$(CONSENSUS_SPEC_TESTS_STAMP):
	@rm -rf consensus-spec-tests
	@mkdir -p consensus-spec-tests
	@for config in $(CONSENSUS_SPEC_TESTS_CONFIGS); do \
		echo "Downloading $$config spec test fixtures ($(CONSENSUS_SPEC_TESTS_VERSION))"; \
		tmpdir=$$(mktemp -d); \
		trap 'rm -rf "$$tmpdir"' EXIT; \
		curl -L -f -o "$$tmpdir/$$config.tar.gz" "$(CONSENSUS_SPEC_TESTS_BASE_URL)/$$config.tar.gz" || exit 1; \
		tar -xzf "$$tmpdir/$$config.tar.gz" -C consensus-spec-tests || exit 1; \
		rm -rf "$$tmpdir"; \
	done
	@touch $@

# BLS and KZG test vectors, split out of consensus-spec-tests' `general` config
# since v1.7.0-alpha.13 (consensus-specs #5398). Preset-independent, so both
# beacon test targets share this one download. Flat layout, one zip:
# `tests/{bls,kzg}/<handler>/<case>/`.
CRYPTOGRAPHY_SPECS_VERSION ?= v0.1.0
CRYPTOGRAPHY_SPECS_URL ?= https://github.com/ethereum/cryptography-specs/releases/download/$(CRYPTOGRAPHY_SPECS_VERSION)/tests.zip
CRYPTOGRAPHY_SPECS_STAMP=cryptography-specs/.version-$(CRYPTOGRAPHY_SPECS_VERSION)

cryptography-specs: $(CRYPTOGRAPHY_SPECS_STAMP) ## ⬇️ Download the BLS and KZG test vectors

$(CRYPTOGRAPHY_SPECS_STAMP):
	@command -v unzip >/dev/null || { echo "unzip is required to extract the BLS/KZG vectors"; exit 1; }
	@rm -rf cryptography-specs
	@mkdir -p cryptography-specs
	@tmpdir=$$(mktemp -d); trap 'rm -rf "$$tmpdir"' EXIT; \
	echo "Downloading BLS/KZG test vectors ($(CRYPTOGRAPHY_SPECS_VERSION))"; \
	curl -L -f -o "$$tmpdir/tests.zip" "$(CRYPTOGRAPHY_SPECS_URL)" || exit 1; \
	unzip -q "$$tmpdir/tests.zip" -d cryptography-specs || exit 1
	@touch $@

# lambdaclass fork of lean-quickstart: genesis keys come from `ethlambda keygen`, and the
# partner clients run their devnet-5 images. An existing lean-quickstart/ is never
# re-cloned, so delete it to pick up a new pin.
LEAN_QUICKSTART_REPO ?= https://github.com/lambdaclass/lean-quickstart.git
LEAN_QUICKSTART_BRANCH ?= devnet5-ethlambda-keygen

lean-quickstart:
	git clone $(LEAN_QUICKSTART_REPO) --branch $(LEAN_QUICKSTART_BRANCH) --depth 1 --single-branch

run-devnet: docker-build lean-quickstart ## 🚀 Run a local devnet using lean-quickstart
	@# The branch name check works offline. On the right branch, also compare against the
	@# remote tip, so a clone left behind by a moved pin is caught too. ls-remote reads the
	@# ref without touching the clone
	@if [ "$$(git -C lean-quickstart rev-parse --abbrev-ref HEAD)" != "$(LEAN_QUICKSTART_BRANCH)" ]; then \
		echo "⚠️  lean-quickstart/ is not on the pinned $(LEAN_QUICKSTART_BRANCH) branch; delete it to re-clone"; \
	else \
		have=$$(git -C lean-quickstart rev-parse HEAD); \
		want=$$(git ls-remote $(LEAN_QUICKSTART_REPO) refs/heads/$(LEAN_QUICKSTART_BRANCH) 2>/dev/null | cut -f1); \
		if [ -z "$$want" ]; then \
			echo "⚠️  could not resolve $(LEAN_QUICKSTART_BRANCH) at $(LEAN_QUICKSTART_REPO); skipping the lean-quickstart/ freshness check"; \
		elif [ "$$have" != "$$want" ]; then \
			echo "⚠️  lean-quickstart/ is at $$(printf '%.8s' "$$have"), but $(LEAN_QUICKSTART_BRANCH) is at $$(printf '%.8s' "$$want"); delete it to re-clone"; \
		fi; \
	fi
	@# Remove local devnet data folder to avoid stale data
	@# NOTE: --cleanData flag in spin-node.sh doesn't work
	@rm -rf lean-quickstart/local-devnet/data/
	@echo "Starting local devnet with ethlambda client (\"$(DOCKER_TAG)\" tag). Logs will be dumped in devnet.log, and metrics served in http://localhost:3000"
	@echo
	@echo "Devnet will be using the current configuration. For custom configurations, modify lean-quickstart/local-devnet/genesis/validator-config.yaml and restart the devnet."
	@echo
	@# Use temp file instead of sed -i for macOS/GNU portability. The tag stops at a `}` so an
	@# image written as a shell parameter default keeps its closing brace
	@sed 's|ghcr.io/lambdaclass/ethlambda:[^ }]*|ghcr.io/lambdaclass/ethlambda:$(DOCKER_TAG)|' lean-quickstart/client-cmds/ethlambda-cmd.sh > lean-quickstart/client-cmds/ethlambda-cmd.sh.tmp \
		&& mv lean-quickstart/client-cmds/ethlambda-cmd.sh.tmp lean-quickstart/client-cmds/ethlambda-cmd.sh
	@echo "Starting local devnet. Press Ctrl+C to stop all nodes."
	@# Generate the genesis keys with the image under test, so they match its leanVM revision
	@cd lean-quickstart \
		&& NETWORK_DIR=local-devnet KEYGEN_IMAGE=ghcr.io/lambdaclass/ethlambda:$(DOCKER_TAG) \
			./spin-node.sh --node all --generateGenesis --metrics > ../devnet.log 2>&1

docs-deps: ## 📦 Install dependencies for generating the documentation
	cargo install --version 0.5.2 --locked mdbook
	cargo install --version 0.12.0 --locked mdbook-linkcheck2

docs: ## 📚 Generate the documentation site under ./book
	mdbook build

docs-serve: ## 📖 Serve the documentation locally with live reload
	mdbook serve --open
