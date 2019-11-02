test: test_bolero test_harness test_fuzzers

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
	    --fuzzer afl

test_libfuzzer:
	@cargo run \
	    fuzz \
	    fuzz_bytes \
	    --manifest-path examples/basic/Cargo.toml \
	    --runs 100000 \
	    --fuzzer libfuzzer
	@cargo run \
	    fuzz \
	    fuzz_bytes \
	    --manifest-path examples/basic/Cargo.toml \
	    --runs 100000 \
	    --fuzzer libfuzzer \
	    --sanitizer address
	@cargo run \
	    shrink \
	    fuzz_bytes \
	    --manifest-path examples/basic/Cargo.toml \
	    --fuzzer libfuzzer
	@cargo run \
	    fuzz \
	    fuzz_generator \
	    --manifest-path examples/basic/Cargo.toml \
	    --runs 100000 \
	    --fuzzer libfuzzer
	@cargo run \
	    shrink \
	    fuzz_generator \
	    --manifest-path examples/basic/Cargo.toml \
	    --fuzzer libfuzzer

test_honggfuzz:
	@cargo run \
	    fuzz \
	    fuzz_bytes \
	    --manifest-path examples/basic/Cargo.toml \
	    --runs 100000 \
	    --fuzzer honggfuzz

publish:
	@cd bolero-afl && cargo publish
	@cd bolero-generator && cargo publish
	@cd bolero-honggfuzz && cargo publish
	@cd bolero-libfuzzer && cargo publish
	@cd cargo-bolero && cargo publish
	@cd bolero && cargo publish
