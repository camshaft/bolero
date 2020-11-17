# Works on Rust Stable

`bolero` does not require nightly to execute test targets:

```bash
# does not require nightly
$ cargo bolero test my_test_target --sanitizer NONE
```

## Sanitizer support

Using a sanitizer will improve the number of edge cases caught by the test. As such, the preference should be towards using them. Unfortunately, sanitizers require Rust nightly to compile.

`cargo-bolero` will use `cargo +nightly` instead to execute the test target:

```bash
# uses nightly, even if we're using stable by default
$ cargo bolero test --sanitizer address my_test_target
```

If a specific version of nightly is required, the `--toolchain` argument can be used:

```bash
$ cargo bolero test --sanitizer address --toolchain nightly-2020-01-01 my_test_target
```
