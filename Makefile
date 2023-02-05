SANITIZER ?= NONE
UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Darwin)
FUZZERS := libfuzzer afl
else
FUZZERS := libfuzzer honggfuzz afl
endif

test: unit-tests test_fuzzers examples-tests

examples-tests: test_basic_example test_workspace_example

test_basic_example:
	@$(MAKE) test_example \
		MANIFEST_PATH=examples/basic/Cargo.toml \
		TEST_THREADS=""
	@$(MAKE) test_example \
		MANIFEST_PATH=examples/basic/Cargo.toml \
		TEST_THREADS="--test-threads=1"

test_workspace_example:
	@$(MAKE) test_example \
		MANIFEST_PATH=examples/workspace/Cargo.toml \
		TEST_THREADS=""
	@$(MAKE) test_example \
		MANIFEST_PATH=examples/workspace/Cargo.toml \
		TEST_THREADS="--test-threads=1"

test_example:
	@RUST_BACKTRACE=1 cargo test \
	    --manifest-path $(MANIFEST_PATH) \
	    -- \
	    --nocapture $(TEST_THREADS)
	@RUST_BACKTRACE=1 cargo test \
	    --release \
	    --manifest-path $(MANIFEST_PATH) \
	    -- \
	    --nocapture $(TEST_THREADS)

unit-tests:
	cargo test

unit-tests-no-1.57:
	cargo test --features arbitrary

test_fuzzers: $(FUZZERS)

libfuzzer honggfuzz:
	@cargo run \
	    --features $@ \
	    test \
	    fuzz_bytes \
	    --manifest-path examples/basic/Cargo.toml \
	    --runs 100000 \
	    --engine $@ \
	    --release \
	    --sanitizer $(SANITIZER)
	@cargo run \
	    --features $@ \
	    reduce \
	    fuzz_bytes \
	    --manifest-path examples/basic/Cargo.toml \
	    --engine $@ \
	    --release \
	    --sanitizer $(SANITIZER)
	@cargo run \
	    --features $@ \
	    test \
	    fuzz_generator \
	    --manifest-path examples/basic/Cargo.toml \
	    --runs 100000 \
	    --engine $@ \
	    --release true \
	    --sanitizer $(SANITIZER)
	@cargo run \
	    --features $@ \
	    reduce \
	    fuzz_generator \
	    --manifest-path examples/basic/Cargo.toml \
	    --engine $@ \
	    --release \
	    --sanitizer $(SANITIZER)
	@cargo run \
	    --features $@ \
	    test \
	    fuzz_operations \
	    --manifest-path examples/basic/Cargo.toml \
	    --runs 1000 \
	    --engine $@ \
	    --release \
	    --sanitizer $(SANITIZER)
	@cargo run \
	    --features $@ \
	    reduce \
	    fuzz_operations \
	    --manifest-path examples/basic/Cargo.toml \
	    --engine $@ \
	    --release \
	    --sanitizer $(SANITIZER)
	@SHOULD_PANIC=1 cargo run \
	    --features $@ \
	    test \
	    tests::add_test \
	    --manifest-path examples/basic/Cargo.toml \
	    --runs 100000 \
	    --engine $@ \
	    --release \
	    --sanitizer $(SANITIZER) \
	    || true # TODO make this consistent
	@SHOULD_PANIC=1 cargo run \
	    --features $@ \
	    reduce \
	    tests::add_test \
	    --manifest-path examples/basic/Cargo.toml \
	    --engine $@ \
	    --release \
	    --sanitizer $(SANITIZER) \
	    || true # TODO make this consistent
	@SHOULD_PANIC=1 cargo run \
	    --features $@ \
	    test \
	    tests::other_test \
	    --manifest-path examples/basic/Cargo.toml \
	    --runs 100000 \
	    --engine $@ \
	    --release \
	    --sanitizer $(SANITIZER) \
	    || true # TODO make this consistent
	@SHOULD_PANIC=1 cargo run \
	    --features $@ \
	    reduce \
	    tests::other_test \
	    --manifest-path examples/basic/Cargo.toml \
	    --engine $@ \
	    --release \
	    --sanitizer $(SANITIZER) \
	    || true # TODO make this consistent
	@SHOULD_PANIC=1 cargo run \
	    --features $@ \
	    test \
	    tests::panicking_generator_test \
	    --manifest-path examples/basic/Cargo.toml \
	    --runs 1000 \
	    --engine $@ \
	    --release \
	    --sanitizer $(SANITIZER) \
	    || true # TODO make this consistent

afl:
	@cargo run \
	    --features $@ \
	    test \
	    fuzz_bytes \
	    --manifest-path examples/basic/Cargo.toml \
	    --runs 100000 \
	    --engine $@ \
	    --release \
	    --sanitizer $(SANITIZER)
	@cargo run \
	    --features $@ \
	    test \
	    fuzz_generator \
	    --manifest-path examples/basic/Cargo.toml \
	    --runs 100000 \
	    --engine $@ \
	    --release \
	    --sanitizer $(SANITIZER)
	@rm -rf examples/basic/src/__fuzz__
	@SHOULD_PANIC=1 cargo run \
	    --features $@ \
	    test \
	    tests::add_test \
	    --manifest-path examples/basic/Cargo.toml \
	    --runs 100000 \
	    --engine $@ \
	    --release \
	    --sanitizer $(SANITIZER) \
	    && exit 1 || true
	@rm -rf examples/basic/src/__fuzz__
	@SHOULD_PANIC=1 cargo run \
	    --features $@ \
	    test \
	    tests::other_test \
	    --manifest-path examples/basic/Cargo.toml \
	    --runs 100000 \
	    --engine $@ \
	    --release \
	    --sanitizer $(SANITIZER) \
	    && exit 1 || true

book:
	@mdbook build book

publish: book
	@cd bolero-generator-derive && cargo publish
	@sleep 30
	@cd bolero-generator && cargo publish
	@sleep 30
	@cd bolero-engine && cargo publish
	@sleep 30
	@cd bolero-afl && cargo publish
	@sleep 30
	@cd bolero-honggfuzz && cargo publish
	@sleep 30
	@cd bolero-libfuzzer && cargo publish
	@sleep 30
	@cd bolero-kani && cargo publish
	@sleep 30
	@cd bolero && cargo publish
	@sleep 30
	@cd cargo-bolero && cargo publish

dry-run:
	@cd bolero-generator-derive && cargo publish --dry-run --allow-dirty
	@cd bolero-generator && cargo publish --dry-run --allow-dirty
	@cd bolero-engine && cargo publish --dry-run --allow-dirty
	@cd bolero-afl && cargo publish --dry-run --allow-dirty
	@cd bolero-honggfuzz && cargo publish --dry-run --allow-dirty
	@cd bolero-libfuzzer && cargo publish --dry-run --allow-dirty
	@cd bolero-kani && cargo publish --dry-run --allow-dirty
	@cd bolero && cargo publish --dry-run --allow-dirty
	@cd cargo-bolero && cargo publish --dry-run --allow-dirty

.PHONY: book
