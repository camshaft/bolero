test: test_bolero test_fuzzers test_harness

test_harness:
	@cargo test \
	    --manifest-path examples/basic/Cargo.toml
	@cargo test \
	    --manifest-path examples/workspace/Cargo.toml

test_bolero:
	@cargo test

test_fuzzers: test_libfuzzer test_afl test_honggfuzz

test_afl:
	@cargo run \
	    fuzz \
	    fuzz_bytes \
	    --manifest-path examples/basic/Cargo.toml \
	    --runs 100000 \
	    --fuzzer afl \
	    --release

test_libfuzzer:
	@cargo run \
	    fuzz \
	    fuzz_bytes \
	    --manifest-path examples/basic/Cargo.toml \
	    --runs 100000 \
	    --fuzzer libfuzzer \
	    --release
	@cargo run \
	    reduce \
	    fuzz_bytes \
	    --manifest-path examples/basic/Cargo.toml \
	    --fuzzer libfuzzer \
	    --release
	@cargo run \
	    fuzz \
	    fuzz_generator \
	    --manifest-path examples/basic/Cargo.toml \
	    --runs 100000 \
	    --fuzzer libfuzzer \
	    --release
	@cargo run \
	    reduce \
	    fuzz_generator \
	    --manifest-path examples/basic/Cargo.toml \
	    --fuzzer libfuzzer \
	    --release

test_honggfuzz:
	@cargo run \
	    fuzz \
	    fuzz_bytes \
	    --manifest-path examples/basic/Cargo.toml \
	    --runs 100000 \
	    --fuzzer honggfuzz \
	    --release

publish:
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
