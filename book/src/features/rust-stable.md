# Works on Rust Stable

`bolero` does not require nightly to execute test targets:

```bash
# does not require nightly
$ cargo bolero fuzz my_fuzz_target
```

## Sanitizer support

Using a sanitizer will improve the number of edge cases caught by the test. As such, the preference should be towards using them. Unfortunately, sanitizers require Rust nightly to compile.

`cargo-bolero` will use `rustup run nightly cargo` instead to execute the test target:

```bash
# uses rustup to execute, even if we're using stable by default
$ cargo bolero fuzz --sanitizer address my_fuzz_target
```

If a specific version of nightly is required, the `--toolchain` argument can be used:

```bash
$ cargo bolero fuzz --sanitizer address --toolchain nightly-2020-01-01 my_fuzz_target
```
