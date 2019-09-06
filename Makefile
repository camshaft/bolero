test_all:
	@cargo build
	@cargo test
	@cd examples/basic \
	  && ../../target/debug/cargo-bolero \
	    fuzz \
	    fuzz_bytes \
	    --manifest-path Cargo.toml \
	    --runs 100000 \
	    --jobs 2 \
	  && ../../target/debug/cargo-bolero \
	    shrink \
	    fuzz_bytes \
	    --manifest-path Cargo.toml \
	  && ../../target/debug/cargo-bolero \
	    fuzz \
	    fuzz_generator \
	    --manifest-path Cargo.toml \
	    --runs 100000 \
	    --jobs 2 \
	  && ../../target/debug/cargo-bolero \
	    shrink \
	    fuzz_generator \
	    --manifest-path Cargo.toml \
	  && cargo test
