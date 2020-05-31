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
	    fuzz \
	    fuzz_bytes \
	    --manifest-path examples/basic/Cargo.toml \
	    --runs 100000 \
	    --fuzzer $@ \
	    --release \
	    --sanitizer $(SANITIZER)
	@cargo run \
	    reduce \
	    fuzz_bytes \
	    --manifest-path examples/basic/Cargo.toml \
	    --fuzzer $@ \
	    --release \
	    --sanitizer $(SANITIZER)
	@cargo run \
	    fuzz \
	    fuzz_generator \
	    --manifest-path examples/basic/Cargo.toml \
	    --runs 100000 \
	    --fuzzer $@ \
	    --release \
	    --sanitizer $(SANITIZER)
	@cargo run \
	    reduce \
	    fuzz_generator \
	    --manifest-path examples/basic/Cargo.toml \
	    --fuzzer $@ \
	    --release \
	    --sanitizer $(SANITIZER)
	@cargo run \
	    fuzz \
	    fuzz_operations \
	    --manifest-path examples/basic/Cargo.toml \
	    --runs 100000 \
	    --fuzzer $@ \
	    --release \
	    --sanitizer $(SANITIZER)
	@cargo run \
	    reduce \
	    fuzz_operations \
	    --manifest-path examples/basic/Cargo.toml \
	    --fuzzer $@ \
	    --release \
	    --sanitizer $(SANITIZER)
	@OTHER_SHOULD_PANIC=1 cargo run \
	    fuzz \
	    tests::add_test \
	    --manifest-path examples/basic/Cargo.toml \
	    --runs 100000 \
	    --fuzzer $@ \
	    --release \
	    --sanitizer $(SANITIZER)
	@OTHER_SHOULD_PANIC=1 cargo run \
	    reduce \
	    tests::add_test \
	    --manifest-path examples/basic/Cargo.toml \
	    --fuzzer $@ \
	    --release \
	    --sanitizer $(SANITIZER)
	@ADD_SHOULD_PANIC=1 cargo run \
	    fuzz \
	    tests::other_test \
	    --manifest-path examples/basic/Cargo.toml \
	    --runs 100000 \
	    --fuzzer $@ \
	    --release \
	    --sanitizer $(SANITIZER)
	@ADD_SHOULD_PANIC=1 cargo run \
	    reduce \
	    tests::other_test \
	    --manifest-path examples/basic/Cargo.toml \
	    --fuzzer $@ \
	    --release \
	    --sanitizer $(SANITIZER)

afl:
	@cargo run \
	    fuzz \
	    fuzz_bytes \
	    --manifest-path examples/basic/Cargo.toml \
	    --runs 100000 \
	    --fuzzer $@ \
	    --release \
	    --sanitizer $(SANITIZER)
	@cargo run \
	    fuzz \
	    fuzz_generator \
	    --manifest-path examples/basic/Cargo.toml \
	    --runs 100000 \
	    --fuzzer $@ \
	    --release \
	    --sanitizer $(SANITIZER)
	@OTHER_SHOULD_PANIC=1 cargo run \
	    fuzz \
	    tests::add_test \
	    --manifest-path examples/basic/Cargo.toml \
	    --runs 100000 \
	    --fuzzer $@ \
	    --release \
	    --sanitizer $(SANITIZER)
	@ADD_SHOULD_PANIC=1 cargo run \
	    fuzz \
	    tests::other_test \
	    --manifest-path examples/basic/Cargo.toml \
	    --runs 100000 \
	    --fuzzer $@ \
	    --release \
	    --sanitizer $(SANITIZER)

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
