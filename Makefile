SANITIZER ?= NONE

test: test_bolero test_fuzzers test_examples

test_examples: test_basic_example test_workspace_example

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

test_bolero:
	@cargo test

test_fuzzers: libfuzzer honggfuzz afl

libfuzzer honggfuzz:
	@cargo run \
	    test \
	    fuzz_bytes \
	    --manifest-path examples/basic/Cargo.toml \
	    --runs 100000 \
	    --engine $@ \
	    --release \
	    --sanitizer $(SANITIZER)
	@cargo run \
	    reduce \
	    fuzz_bytes \
	    --manifest-path examples/basic/Cargo.toml \
	    --engine $@ \
	    --release \
	    --sanitizer $(SANITIZER)
	@cargo run \
	    test \
	    fuzz_generator \
	    --manifest-path examples/basic/Cargo.toml \
	    --runs 100000 \
	    --engine $@ \
	    --release true \
	    --sanitizer $(SANITIZER)
	@cargo run \
	    reduce \
	    fuzz_generator \
	    --manifest-path examples/basic/Cargo.toml \
	    --engine $@ \
	    --release \
	    --sanitizer $(SANITIZER)
	@cargo run \
	    test \
	    fuzz_operations \
	    --manifest-path examples/basic/Cargo.toml \
	    --runs 1000 \
	    --engine $@ \
	    --release \
	    --sanitizer $(SANITIZER)
	@cargo run \
	    reduce \
	    fuzz_operations \
	    --manifest-path examples/basic/Cargo.toml \
	    --engine $@ \
	    --release \
	    --sanitizer $(SANITIZER)
	@SHOULD_PANIC=1 cargo run \
	    test \
	    tests::add_test \
	    --manifest-path examples/basic/Cargo.toml \
	    --runs 100000 \
	    --engine $@ \
	    --release \
	    --sanitizer $(SANITIZER) \
	    && exit 1 || true
	@SHOULD_PANIC=1 cargo run \
	    reduce \
	    tests::add_test \
	    --manifest-path examples/basic/Cargo.toml \
	    --engine $@ \
	    --release \
	    --sanitizer $(SANITIZER) \
	    || true # TODO make this consistent
	@SHOULD_PANIC=1 cargo run \
	    test \
	    tests::other_test \
	    --manifest-path examples/basic/Cargo.toml \
	    --runs 100000 \
	    --engine $@ \
	    --release \
	    --sanitizer $(SANITIZER) \
	    && exit 1 || true
	@SHOULD_PANIC=1 cargo run \
	    reduce \
	    tests::other_test \
	    --manifest-path examples/basic/Cargo.toml \
	    --engine $@ \
	    --release \
	    --sanitizer $(SANITIZER) \
	    || true # TODO make this consistent
	@SHOULD_PANIC=1 cargo run \
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
	    test \
	    fuzz_bytes \
	    --manifest-path examples/basic/Cargo.toml \
	    --runs 100000 \
	    --engine $@ \
	    --release \
	    --sanitizer $(SANITIZER)
	@cargo run \
	    test \
	    fuzz_generator \
	    --manifest-path examples/basic/Cargo.toml \
	    --runs 100000 \
	    --engine $@ \
	    --release \
	    --sanitizer $(SANITIZER)
	@SHOULD_PANIC=1 cargo run \
	    test \
	    tests::add_test \
	    --manifest-path examples/basic/Cargo.toml \
	    --runs 100000 \
	    --engine $@ \
	    --release \
	    --sanitizer $(SANITIZER) \
	    && exit 1 || true
	@SHOULD_PANIC=1 cargo run \
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
	@cd bolero && cargo publish
	@sleep 30
	@cd cargo-bolero && cargo publish

.PHONY: book
