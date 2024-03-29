# Unified Interface

Using the interface provided by `bolero`, a single test target can execute under several different engines.

## LibFuzzer

* [LibFuzzer documentation](https://llvm.org/docs/LibFuzzer.html)

LibFuzzer is an in-process, coverage-guided, evolutionary fuzzing engine.

LibFuzzer is linked with the library under test, and feeds fuzzed inputs to the library via a specific fuzzing entrypoint (aka “target function”); the fuzzer then tracks which areas of the code are reached, and generates mutations on the corpus of input data in order to maximize the code coverage.

The `libfuzzer` engine can be selected like so:

```bash
$ cargo bolero test --engine libfuzzer my_test_target
```

Currently, it is also the default engine:

```bash
# will use --engine libfuzzer
$ cargo bolero test my_test_target
```

## AFL

* [AFL documentation](http://lcamtuf.coredump.cx/afl/)

American fuzzy lop is a security-oriented fuzzer that employs a novel type of compile-time instrumentation and genetic algorithms to automatically discover clean, interesting test cases that trigger new internal states in the targeted binary. This substantially improves the functional coverage for the fuzzed code. The compact synthesized corpora produced by the tool are also useful for seeding other, more labor- or resource-intensive testing regimes down the road.

The `afl` engine can be selected like so:

```bash
$ cargo bolero test --engine afl my_test_target
```

## Honggfuzz

* [Honggfuzz documentation](https://google.github.io/honggfuzz/)

Honggfuzz is a security oriented fuzzer with powerful analysis options. Supports evolutionary, feedback-driven fuzzing based on code coverage (software- and hardware-based)

The `honggfuzz` engine can be selected like so:

```bash
$ cargo bolero test --engine honggfuzz my_test_target
```

## Kani

* [Kani documentation](https://model-checking.github.io/kani/)

Kani is an open-source verification tool that uses automated reasoning to analyze Rust programs. Kani is particularly useful for verifying unsafe code in Rust, where many of the Rust’s usual guarantees are no longer checked by the compiler. Some example properties you can prove with Kani include memory safety properties (e.g., null pointer dereferences, use-after-free, etc.), the absence of certain runtime errors (i.e., index out of bounds, panics), and the absence of some types of unexpected behavior (e.g., arithmetic overflows). Kani can also prove custom properties provided in the form of user-specified assertions.

Kani uses proof harnesses to analyze programs. Proof harnesses are similar to test harnesses, especially property-based test harnesses.

The `kani` engine can be selected like so:

```bash
$ cargo bolero test --engine kani my_test_target
```

Note that each target needs to include a `#[kani::proof]` attribute:

```rust
#[test]
#[cfg_attr(kani, kani::proof)]
fn my_test_target() {
    bolero::check!().with_type().for_each(|v: &u8| {
        assert_ne!(*v, 123);
    });
}
```
