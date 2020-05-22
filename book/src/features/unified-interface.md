# Unified Interface

Using the interface provided by `bolero`, a single test target can execute under several different engines.

## LibFuzzer

* [LibFuzzer documentation](https://llvm.org/docs/LibFuzzer.html)

LibFuzzer is an in-process, coverage-guided, evolutionary fuzzing engine.

LibFuzzer is linked with the library under test, and feeds fuzzed inputs to the library via a specific fuzzing entrypoint (aka “target function”); the fuzzer then tracks which areas of the code are reached, and generates mutations on the corpus of input data in order to maximize the code coverage.

The `libfuzzer` engine can be selected like so:

```bash
$ cargo bolero fuzz --fuzzer libfuzzer my_fuzz_target
```

Currently, it is also the default engine when fuzzing:

```bash
# will use --fuzzer libfuzzer
$ cargo bolero fuzz my_fuzz_target
```

## AFL

* [AFL documentation](http://lcamtuf.coredump.cx/afl/)

American fuzzy lop is a security-oriented fuzzer that employs a novel type of compile-time instrumentation and genetic algorithms to automatically discover clean, interesting test cases that trigger new internal states in the targeted binary. This substantially improves the functional coverage for the fuzzed code. The compact synthesized corpora produced by the tool are also useful for seeding other, more labor- or resource-intensive testing regimes down the road.

The `afl` engine can be selected like so:

```bash
$ cargo bolero fuzz --fuzzer afl my_fuzz_target
```

## Honggfuzz

* [Honggfuzz documentation](https://google.github.io/honggfuzz/)

Honggfuzz is a security oriented fuzzer with powerful analysis options. Supports evolutionary, feedback-driven fuzzing based on code coverage (software- and hardware-based)

The `honggfuzz` engine can be selected like so:

```bash
$ cargo bolero fuzz --fuzzer honggfuzz my_fuzz_target
```

