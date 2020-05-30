This is a really weird one that seems to affect about half of my unit tests.
In debug mode, everything runs fine.  However, in release mode, it errors out.
Here is the complete output of what I'm seeing:

```bash
cfkaran2@Hammer:~/Desktop/reduced_bolero_test$ cargo clean ; cargo test
   Compiling libc v0.2.71
   Compiling proc-macro2 v1.0.17
   Compiling unicode-xid v0.2.0
   Compiling syn v1.0.29
   Compiling cfg-if v0.1.10
   Compiling getrandom v0.1.14
   Compiling version_check v0.9.2
   Compiling byteorder v1.3.4
   Compiling anyhow v1.0.31
   Compiling cc v1.0.54
   Compiling ppv-lite86 v0.2.8
   Compiling lazy_static v1.4.0
   Compiling gimli v0.21.0
   Compiling bitflags v1.2.1
   Compiling rustc-demangle v0.1.16
   Compiling either v1.5.3
   Compiling object v0.19.0
   Compiling unicode-segmentation v1.6.0
   Compiling pretty-hex v0.1.1
   Compiling unicode-width v0.1.7
   Compiling ansi_term v0.11.0
   Compiling vec_map v0.8.2
   Compiling strsim v0.8.0
   Compiling bolero-honggfuzz v0.5.0
   Compiling termcolor v1.1.0
   Compiling proc-macro-error-attr v1.0.2
   Compiling proc-macro-error v1.0.2
   Compiling textwrap v0.11.0
   Compiling heck v0.3.1
   Compiling bolero-libfuzzer v0.5.0
   Compiling bolero-afl v0.5.0
   Compiling quote v1.0.6
   Compiling atty v0.2.14
   Compiling clap v2.33.1
   Compiling rand_core v0.5.1
   Compiling rand_chacha v0.2.2
   Compiling rand v0.7.3
   Compiling addr2line v0.12.1
   Compiling backtrace v0.3.48
   Compiling syn-mid v0.5.0
   Compiling bolero-generator-derive v0.5.0
   Compiling bolero-generator v0.5.1
   Compiling structopt-derive v0.4.7
   Compiling structopt v0.3.14
   Compiling libtest-mimic v0.2.0
   Compiling bolero-engine v0.5.1
   Compiling bolero v0.5.1
   Compiling reduced_bolero_test v0.1.0 (/home/cfkaran2/Desktop/reduced_bolero_test)
    Finished test [unoptimized + debuginfo] target(s) in 17.94s
     Running target/debug/deps/reduced_bolero_test-026cecbded21ab56

running 1 test
test tests::new ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

   Doc-tests reduced_bolero_test

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

cfkaran2@Hammer:~/Desktop/reduced_bolero_test$ cargo clean ; cargo test --release
   Compiling libc v0.2.71
   Compiling proc-macro2 v1.0.17
   Compiling unicode-xid v0.2.0
   Compiling syn v1.0.29
   Compiling getrandom v0.1.14
   Compiling cfg-if v0.1.10
   Compiling version_check v0.9.2
   Compiling byteorder v1.3.4
   Compiling cc v1.0.54
   Compiling gimli v0.21.0
   Compiling ppv-lite86 v0.2.8
   Compiling anyhow v1.0.31
   Compiling lazy_static v1.4.0
   Compiling rustc-demangle v0.1.16
   Compiling either v1.5.3
   Compiling object v0.19.0
   Compiling bitflags v1.2.1
   Compiling unicode-width v0.1.7
   Compiling pretty-hex v0.1.1
   Compiling unicode-segmentation v1.6.0
   Compiling ansi_term v0.11.0
   Compiling strsim v0.8.0
   Compiling vec_map v0.8.2
   Compiling bolero-honggfuzz v0.5.0
   Compiling termcolor v1.1.0
   Compiling textwrap v0.11.0
   Compiling heck v0.3.1
   Compiling proc-macro-error-attr v1.0.2
   Compiling proc-macro-error v1.0.2
   Compiling addr2line v0.12.1
   Compiling quote v1.0.6
   Compiling atty v0.2.14
   Compiling rand_core v0.5.1
   Compiling clap v2.33.1
   Compiling rand_chacha v0.2.2
   Compiling rand v0.7.3
   Compiling backtrace v0.3.48
   Compiling bolero-afl v0.5.0
   Compiling bolero-libfuzzer v0.5.0
   Compiling syn-mid v0.5.0
   Compiling bolero-generator-derive v0.5.0
   Compiling bolero-generator v0.5.1
   Compiling structopt-derive v0.4.7
   Compiling structopt v0.3.14
   Compiling libtest-mimic v0.2.0
   Compiling bolero-engine v0.5.1
   Compiling bolero v0.5.1
   Compiling reduced_bolero_test v0.1.0 (/home/cfkaran2/Desktop/reduced_bolero_test)
    Finished release [optimized] target(s) in 37.10s
     Running target/release/deps/reduced_bolero_test-1370df26033debf2

running 1 test
test tests::new ... FAILED

failures:

---- tests::new stdout ----
thread 'tests::new' panicked at 'test name not found', /home/cfkaran2/.cargo/registry/src/github.com-1ecc6299db9ec823/bolero-engine-0.5.1/src/target_location.rs:92:5
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace


failures:
    tests::new

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out

error: test failed, to rerun pass '--lib'
cfkaran2@Hammer:~/Desktop/reduced_bolero_test$ 
```

## Meta information

```bash
cfkaran2@Hammer:~/Desktop/reduced_bolero_test$ rustc -Vv && cargo -Vv && uname -a && lsb_release -a && cargo bolero --version
rustc 1.43.1 (8d69840ab 2020-05-04)
binary: rustc
commit-hash: 8d69840ab92ea7f4d323420088dd8c9775f180cd
commit-date: 2020-05-04
host: x86_64-unknown-linux-gnu
release: 1.43.1
LLVM version: 9.0

cargo 1.43.0 (2cbe9048e 2020-05-03)
release: 1.43.0
commit-hash: 2cbe9048efc5c904b33191d799f97dc4698debaa
commit-date: 2020-05-03

Linux Hammer 5.3.0-53-generic #47~18.04.1-Ubuntu SMP Thu May 7 13:10:50 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux

No LSB modules are available.
Distributor ID: Ubuntu
Description:    Ubuntu 18.04.4 LTS
Release:    18.04
Codename:   bionic

cargo-bolero 0.5.1
```