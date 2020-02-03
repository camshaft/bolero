# Unified Fuzzing Interface

`bolero` unifies the implementation to a single interface that supports `libfuzzer`, `afl`, and `honggfuzz`:

```rust
use bolero::fuzz;

fn main() {
    fuzz!().for_each(|input| {
        // code to fuzz goes here
    });
}
```

Fuzzers can be easily swapped out with the `fuzzer` flag passed to `cargo-bolero`:

```bash
$ cargo bolero fuzz --fuzzer {libfuzzer,afl,honggfuzz} my_fuzz_target
```
