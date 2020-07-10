This is related to issue #18, but I don't know if it shows the whole cause of
it. If you read the code, you'll notice that there is an `assert!()` statement
within the `TypeGenerator` implementation for `Dummy`.  The problem is that its
output is never printed, even when you request 'nocapture' at the command line.
As a result, you don't know why a test failed, only that it did.

For simply types, this isn't an issue, but for complex types that rely on
external code that can panic, this becomes a big problem.

```bash
cfkaran2@Hammer:~/Desktop/reduced_bolero_test$ cargo clean && cargo test -- --nocapture
   Compiling libc v0.2.72
   Compiling proc-macro2 v1.0.18
   Compiling unicode-xid v0.2.1
   Compiling syn v1.0.33
   Compiling version_check v0.9.2
   Compiling getrandom v0.1.14
   Compiling cfg-if v0.1.10
   Compiling bitflags v1.2.1
   Compiling unicode-segmentation v1.6.0
   Compiling unicode-width v0.1.8
   Compiling byteorder v1.3.4
   Compiling strsim v0.8.0
   Compiling vec_map v0.8.2
   Compiling ppv-lite86 v0.2.8
   Compiling gimli v0.22.0
   Compiling anyhow v1.0.31
   Compiling ansi_term v0.11.0
   Compiling lazy_static v1.4.0
   Compiling adler v0.2.2
   Compiling either v1.5.3
   Compiling object v0.20.0
   Compiling rustc-demangle v0.1.16
   Compiling termcolor v1.1.0
   Compiling pretty-hex v0.1.1
   Compiling textwrap v0.11.0
   Compiling heck v0.3.1
   Compiling proc-macro-error-attr v1.0.3
   Compiling proc-macro-error v1.0.3
   Compiling miniz_oxide v0.4.0
   Compiling quote v1.0.7
   Compiling atty v0.2.14
   Compiling clap v2.33.1
   Compiling rand_core v0.5.1
   Compiling rand_chacha v0.2.2
   Compiling rand v0.7.3
   Compiling addr2line v0.13.0
   Compiling backtrace v0.3.50
   Compiling syn-mid v0.5.0
   Compiling bolero-generator-derive v0.5.2
   Compiling bolero-generator v0.5.2
   Compiling structopt-derive v0.4.8
   Compiling structopt v0.3.15
   Compiling libtest-mimic v0.2.0
   Compiling bolero-engine v0.5.2
   Compiling bolero v0.5.2
   Compiling reduced_bolero_test v0.1.0 (/home/cfkaran2/Desktop/reduced_bolero_test)
    Finished test [unoptimized + debuginfo] target(s) in 28.61s
     Running target/debug/deps/reduced_bolero_test-529df0ed3283e341

running 1 test
test tests::serialize ... FAILED

failures:

failures:
    tests::serialize

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out

error: test failed, to rerun pass '--lib'
```

## Meta information

```bash
cfkaran2@Hammer:~/Desktop/reduced_bolero_test$ rustc -Vv && echo && cargo -Vv && echo && uname -a && echo && lsb_release -a && echo && cargo bolero --version
rustc 1.44.1 (c7087fe00 2020-06-17)
binary: rustc
commit-hash: c7087fe00d2ba919df1d813c040a5d47e43b0fe7
commit-date: 2020-06-17
host: x86_64-unknown-linux-gnu
release: 1.44.1
LLVM version: 9.0

cargo 1.44.1 (88ba85757 2020-06-11)
release: 1.44.1
commit-hash: 88ba8575724c08a50eb265a05f3ff6d0883de1ee
commit-date: 2020-06-11

Linux Hammer 5.3.0-61-generic #55~18.04.1-Ubuntu SMP Mon Jun 22 16:40:20 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux

No LSB modules are available.
Distributor ID:   Ubuntu
Description:   Ubuntu 18.04.4 LTS
Release: 18.04
Codename:   bionic

cargo-bolero 0.5.2
```