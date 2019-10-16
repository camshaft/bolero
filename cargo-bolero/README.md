# cargo-bolero

## fuzz

```bash
USAGE:
    cargo-bolero fuzz [FLAGS] [OPTIONS] <test>

FLAGS:
        --all-features           Activate all available features
    -h, --help                   Prints help information
        --no-default-features    Do not activate the `default` feature
    -V, --version                Prints version information

OPTIONS:
        --features <features>                    Space-separated list of features to activate
    -f, --fuzzer <fuzzer>                        Run the test with a specific fuzzer [default: libfuzzer]
    -j, --jobs <jobs>                            Number of parallel jobs
        --manifest-path <manifest-path>          Path to Cargo.toml
    -l, --max-input-length <max-input-length>    Limit the size of inputs to a specific length
    -p, --package <package>                      Package to run tests for
    -r, --runs <runs>                            Run the fuzzer for a specified number of runs
    -s, --sanitizer <sanitizer>...               Build with the sanitizer enabled
    -S, --seed <seed>                            Run the fuzzer with an initial seed
        --target <target>                        Build for the target triple [default: x86_64-apple-darwin]
    -T, --time <time>                            Run the fuzzer for a specified number of seconds
        --toolchain <toolchain>                  Use a rustup toolchain to execute cargo build

ARGS:
    <test>    Name of the test target
```

## shrink

```bash
USAGE:
    cargo-bolero shrink [FLAGS] [OPTIONS] <test>

FLAGS:
        --all-features           Activate all available features
    -h, --help                   Prints help information
        --no-default-features    Do not activate the `default` feature
    -V, --version                Prints version information

OPTIONS:
        --features <features>              Space-separated list of features to activate
    -f, --fuzzer <fuzzer>                  Run the test with a specific fuzzer [default: libfuzzer]
        --manifest-path <manifest-path>    Path to Cargo.toml
    -p, --package <package>                Package to run tests for
    -s, --sanitizer <sanitizer>...         Build with the sanitizer enabled
        --target <target>                  Build for the target triple [default: x86_64-apple-darwin]
        --toolchain <toolchain>            Use a rustup toolchain to execute cargo build

ARGS:
    <test>    Name of the test target
```
