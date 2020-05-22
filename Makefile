SANITIZER ?= NONE

test: test_bolero test_fuzzers test_harness

test_harness:
	@cargo test \
	    --manifest-path examples/basic/Cargo.toml
	@cargo test \
	    --manifest-path examples/workspace/Cargo.toml

test_bolero:
	@cargo test

test_fuzzers: libfuzzer honggfuzz afl

honggfuzz:
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

afl libfuzzer:
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
	@cargo run \
	    fuzz \
	    fuzz_operations \
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

	@SHOULD_PANIC=1 cargo run \
	    fuzz \
	    fuzz_bytes \
	    --manifest-path examples/basic/Cargo.toml \
	    --runs 100000 \
	    --fuzzer $@ \
	    --release \
	    --sanitizer $(SANITIZER) \
	    && exit 1 \
	    || exit 0
	@SHOULD_PANIC=1 cargo run \
	    fuzz \
	    fuzz_generator \
	    --manifest-path examples/basic/Cargo.toml \
	    --runs 100000 \
	    --fuzzer $@ \
	    --release \
	    --sanitizer $(SANITIZER) \
	    && exit 1 \
	    || exit 0
	@SHOULD_PANIC=1 cargo run \
	    fuzz \
	    fuzz_operations \
	    --manifest-path examples/basic/Cargo.toml \
	    --runs 100000 \
	    --fuzzer $@ \
	    --release \
	    --sanitizer $(SANITIZER) \
	    && exit 1 \
	    || exit 0
	@ADD_SHOULD_PANIC=1 cargo run \
	    fuzz \
	    tests::add_test \
	    --manifest-path examples/basic/Cargo.toml \
	    --runs 100000 \
	    --fuzzer $@ \
	    --release \
	    --sanitizer $(SANITIZER) \
	    && exit 1 \
	    || exit 0
	@OTHER_SHOULD_PANIC=1 cargo run \
	    fuzz \
	    tests::other_test \
	    --manifest-path examples/basic/Cargo.toml \
	    --runs 100000 \
	    --fuzzer $@ \
	    --release \
	    --sanitizer $(SANITIZER) \
	    && exit 1 \
	    || exit 0

book:
	@mdbook build book

publish: book
	@cd bolero-generator-derive && cargo publish
	@sleep 10
	@cd bolero-generator && cargo publish
	@sleep 10
	@cd bolero-engine && cargo publish
	@sleep 10
	@cd bolero-afl && cargo publish
	@sleep 10
	@cd bolero-honggfuzz && cargo publish
	@sleep 10
	@cd bolero-libfuzzer && cargo publish
	@sleep 10
	@cd cargo-bolero && cargo publish
	@sleep 10
	@cd bolero && cargo publish

.PHONY: book
