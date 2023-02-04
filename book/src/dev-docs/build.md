# Build from source

In general, the following dependencies are required to build `bolero` from source.

## Dependencies

 * The Rust toolchain (`cargo`, `rustfmt`, etc.) installed via [rustup](https://rustup.rs/)
 * `make`

`bolero` has been tested in [`Ubuntu 22.04`](#ubuntu-2204) and [`macOS 12`](#macos-12) platforms.

### Ubuntu 22.04

```bash
sudo apt update
sudo apt install binutils-dev libunwind-dev
```

`make` comes pre-installed on Ubuntu, but if for some reason it isn't,
it can be installed using the command:

```bash
sudo apt install make
```

### macOS 12

`make` can be installed using the command:

```bash
xcode-select --install
```

No other dependencies are required.

## Build and test

The [`Makefile`](https://github.com/camshaft/bolero/blob/master/Makefile) located in the
root directory can be used to build `bolero` and run it on several test suites. To execute
it, just run:

```bash
make
```

This should compile `bolero` and run multiple tests. In the process, it's
possible that you are shown the following message:

```
[-] Hmm, your system is configured to send core dump notifications to an
    external utility. This will cause issues: there will be an extended delay
    between stumbling upon a crash and having this information relayed to the
    fuzzer via the standard waitpid() API.

    To avoid having crashes misinterpreted as timeouts, please log in as root
    and temporarily modify /proc/sys/kernel/core_pattern, like so:

    echo core >/proc/sys/kernel/core_pattern
```

This message comes from AFL. You can either modify the file as indicated or
re-run the `make` command as follows:

```bash
AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 make
```

However, this doesn't guarantee that the AFL tests will pass. In that case, the
best option is to temporarily modify the `/proc/sys/kernel/core_pattern` file.
