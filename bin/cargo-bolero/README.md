# cargo-bolero

[`cargo-bolero`](https://crates.io/crates/cargo-bolero) can be installed globally with cargo:

```bash
$ cargo install -f cargo-bolero
```

## Linux Installation

`cargo-bolero` needs a couple of libraries installed to compile. If these libraries aren't
available the requirement can be relaxed by executing `cargo install cargo-bolero --no-default-features -f`

### Debian/Ubuntu

```bash
$ sudo apt install binutils-dev libunwind-dev
```

## fuzz

```bash
Run an engine for a target

USAGE:
    cargo bolero test [FLAGS] [OPTIONS] <test>

FLAGS:
        --all-features           Activate all available features
    -h, --help                   Prints help information
        --no-default-features    Do not activate the `default` feature
        --release                Build artifacts in release mode, with optimizations
    -V, --version                Prints version information

OPTIONS:
        --features <features>                    Space-separated list of features to activate
    -e, --engine <engine>                        Run the test with a specific engine [default: libfuzzer]
    -j, --jobs <jobs>                            Number of parallel jobs
        --manifest-path <manifest-path>          Path to Cargo.toml
    -l, --max-input-length <max-input-length>    Limit the size of inputs to a specific length
    -p, --package <package>                      Package to run tests for
    -r, --runs <runs>                            Run the engine for a specified number of runs
    -s, --sanitizer <sanitizer>...               Build with the sanitizer enabled
    -S, --seed <seed>                            Run the engine with an initial seed
        --target <target>                        Build for the target triple
        --target_dir <target-dir>                Directory for all generated artifacts
    -T, --time <time>                            Run the engine for a specified number of seconds
        --toolchain <toolchain>                  Use a rustup toolchain to execute cargo build

ARGS:
    <test>    Name of the test target
```

## reduce

```bash
Reduce the corpus of a test target with an engine

USAGE:
    cargo bolero reduce [FLAGS] [OPTIONS] <test>

FLAGS:
        --all-features           Activate all available features
    -h, --help                   Prints help information
        --no-default-features    Do not activate the `default` feature
        --release                Build artifacts in release mode, with optimizations
    -V, --version                Prints version information

OPTIONS:
        --features <features>              Space-separated list of features to activate
    -e, --engine <engine>                  Run the test with a specific engine [default: libfuzzer]
        --manifest-path <manifest-path>    Path to Cargo.toml
    -p, --package <package>                Package to run tests for
    -s, --sanitizer <sanitizer>...         Build with the sanitizer enabled
        --target <target>                  Build for the target triple
        --target_dir <target-dir>          Directory for all generated artifacts
        --toolchain <toolchain>            Use a rustup toolchain to execute cargo build

ARGS:
    <test>    Name of the test target
```
