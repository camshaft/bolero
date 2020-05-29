This is a reduced test of bolero.  It exists to show a deadlock issue that I've
run into.  You can get the same results as I've been getting by doing the
following the notes in the `Instructions` section.

Note that the test seems to be non-deterministic; if I run the test immediately
after rebooting my machine then it may complete.  That said, if I rerun the test
immediately, it always deadlocks.  You may need to experiment a bit to get a
consistent failure mode.

## Instructions

- First, execute the following, in order:
  - cargo clean
  - cargo update
  - cargo test --no-run
- At this point you will have an executable in your target directory.  Change
  directories into 'target/debug' and search for the executable.  It will have a
  name similar to 'reduced_bolero_test-0be8c02cbd6dc271'.
- Run lldb on it:
  - 'lldb reduced_bolero_test-0be8c02cbd6dc271'
  - This will result in output similar to the following:
    ```bash
    (lldb) target create "reduced_bolero_test-0be8c02cbd6dc271"
    Current executable set to 'reduced_bolero_test-0be8c02cbd6dc271' (x86_64).
    (lldb) run
    Process 424 launched: '/home/cfkaran2/Desktop/reduced_bolero_test/target/debug/reduced_bolero_test-0be8c02cbd6dc271' (x86_64)

    running 1 test
    ```
  - When the line `test tests::bolero_test ... test tests::bolero_test has been running for over 60 seconds`
    break the running process with `^C` (ctrl-C).  This should leave you at the
    `(lldb)` prompt, with output like the following:
    ```bash
    Process 424 stopped
    * thread #1, name = 'reduced_bolero_', stop reason = signal SIGSTOP
        frame #0: 0x00007ffff74349f3 libpthread.so.0`__pthread_cond_wait + 579
    libpthread.so.0`__pthread_cond_wait:
    ->  0x7ffff74349f3 <+579>: cmpq   $-0x1000, %rax            ; imm = 0xF000
        0x7ffff74349f9 <+585>: movq   0x30(%rsp), %r8
        0x7ffff74349fe <+590>: ja     0x7ffff7434b30            ; <+896>
        0x7ffff7434a04 <+596>: movl   %r9d, %edi
    (lldb)
    ```
  - To get a backtrace, enter the `bt` command:
  ```bash
  (lldb) bt
    * thread #1, name = 'reduced_bolero_', stop reason = signal SIGSTOP
      * frame #0: 0x00007ffff74349f3 libpthread.so.0`__pthread_cond_wait + 579
        frame #1: 0x0000555555893ca3 reduced_bolero_test-0be8c02cbd6dc271`std::thread::park::h296acd55d5276ee3 [inlined] std::sys::unix::condvar::Condvar::wait::h1cca46687e79e674 at condvar.rs:73
        frame #2: 0x0000555555893ca1 reduced_bolero_test-0be8c02cbd6dc271`std::thread::park::h296acd55d5276ee3 [inlined] std::sys_common::condvar::Condvar::wait::ha779a4eda9e4f92e at condvar.rs:50
        frame #3: 0x0000555555893ca1 reduced_bolero_test-0be8c02cbd6dc271`std::thread::park::h296acd55d5276ee3 [inlined] std::sync::condvar::Condvar::wait::hb93c1601d9e8bfa5 at condvar.rs:200
        frame #4: 0x0000555555893c87 reduced_bolero_test-0be8c02cbd6dc271`std::thread::park::h296acd55d5276ee3 at mod.rs:919
        frame #5: 0x000055555589cd22 reduced_bolero_test-0be8c02cbd6dc271`std::sync::mpsc::blocking::WaitToken::wait::hfa37a42a6608c105 at blocking.rs:64
        frame #6: 0x00005555555b8632 reduced_bolero_test-0be8c02cbd6dc271`std::sync::mpsc::shared::Packet$LT$T$GT$::recv::h031a3f9382fc7f86 at shared.rs:235
        frame #7: 0x00005555555b7776 reduced_bolero_test-0be8c02cbd6dc271`std::sync::mpsc::Receiver$LT$T$GT$::recv::hf7bff188b3bd801c at mod.rs:1179
        frame #8: 0x00005555555caa9e reduced_bolero_test-0be8c02cbd6dc271`test::console::run_tests_console::h1310f799a6a11e7c [inlined] test::run_tests::hee095da8f7fe5691 at lib.rs:323
        frame #9: 0x00005555555c8c22 reduced_bolero_test-0be8c02cbd6dc271`test::console::run_tests_console::h1310f799a6a11e7c at console.rs:280
        frame #10: 0x00005555555d7167 reduced_bolero_test-0be8c02cbd6dc271`test::test_main::ha4f31af3b7432712 at lib.rs:121
        frame #11: 0x00005555555d870c reduced_bolero_test-0be8c02cbd6dc271`test::test_main_static::h3c6293225879b233 at lib.rs:140
        frame #12: 0x00005555555acb56 reduced_bolero_test-0be8c02cbd6dc271`reduced_bolero_test::main::h14143e9e2de1e795 + 22
        frame #13: 0x00005555555afe4b reduced_bolero_test-0be8c02cbd6dc271`std::rt::lang_start::_$u7b$$u7b$closure$u7d$$u7d$::hd2674889fd6dbd4a at rt.rs:67
        frame #14: 0x00005555558a0933 reduced_bolero_test-0be8c02cbd6dc271`std::panicking::try::do_call::h0b6fc9f6090c1e2b [inlined] std::rt::lang_start_internal::_$u7b$$u7b$closure$u7d$$u7d$::h9a4aa16acf1cdc99 at rt.rs:52
        frame #15: 0x00005555558a0927 reduced_bolero_test-0be8c02cbd6dc271`std::panicking::try::do_call::h0b6fc9f6090c1e2b at panicking.rs:303
        frame #16: 0x00005555558a8ab7 reduced_bolero_test-0be8c02cbd6dc271`__rust_maybe_catch_panic at lib.rs:86
        frame #17: 0x00005555558a138c reduced_bolero_test-0be8c02cbd6dc271`std::rt::lang_start_internal::hcea4e704875ab132 [inlined] std::panicking::try::h9eaeeaa81242ec77 at panicking.rs:281
        frame #18: 0x00005555558a134e reduced_bolero_test-0be8c02cbd6dc271`std::rt::lang_start_internal::hcea4e704875ab132 [inlined] std::panic::catch_unwind::h07d504c1b691e8fb at panic.rs:394
        frame #19: 0x00005555558a134e reduced_bolero_test-0be8c02cbd6dc271`std::rt::lang_start_internal::hcea4e704875ab132 at rt.rs:51
        frame #20: 0x00005555555afe27 reduced_bolero_test-0be8c02cbd6dc271`std::rt::lang_start::h1bc98385dd7fba9f(main=(reduced_bolero_test-0be8c02cbd6dc271`reduced_bolero_test::main::h14143e9e2de1e795), argc=1, argv=0x00007fffffffdd98) at rt.rs:67
        frame #21: 0x00005555555acb8a reduced_bolero_test-0be8c02cbd6dc271`main + 42
        frame #22: 0x00007ffff7a05b97 libc.so.6`__libc_start_main(main=(reduced_bolero_test-0be8c02cbd6dc271`main), argc=1, argv=0x00007fffffffdd98, init=<unavailable>, fini=<unavailable>, rtld_fini=<unavailable>, stack_end=0x00007fffffffdd88) at libc-start.c:310
        frame #23: 0x00005555555a13ba reduced_bolero_test-0be8c02cbd6dc271`_start + 42
  ```

Once you've hit this point, there really isn't much more you can do.  You can
resume running with `c`, but when you break again with `^C`, you'll find that
you're at the exact same point as above.  Good luck figuring out what's going
on!

## Meta information

OS, kernel, rust, and cargo info

```bash
cfkaran2@Hammer:~/Desktop/bolero$ uname -a
Linux Hammer 5.3.0-53-generic #47~18.04.1-Ubuntu SMP Thu May 7 13:10:50 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
cfkaran2@Hammer:~/Desktop/bolero$ lsb_release -a
No LSB modules are available.
Distributor ID: Ubuntu
Description:  Ubuntu 18.04.4 LTS
Release:  18.04
Codename: bionic
cfkaran2@Hammer:~/Desktop/bolero$ rustc -Vv
rustc 1.43.1 (8d69840ab 2020-05-04)
binary: rustc
commit-hash: 8d69840ab92ea7f4d323420088dd8c9775f180cd
commit-date: 2020-05-04
host: x86_64-unknown-linux-gnu
release: 1.43.1
LLVM version: 9.0
cfkaran2@Hammer:~/Desktop/bolero$ cargo -Vv
cargo 1.43.0 (2cbe9048e 2020-05-03)
release: 1.43.0
commit-hash: 2cbe9048efc5c904b33191d799f97dc4698debaa
commit-date: 2020-05-03
```