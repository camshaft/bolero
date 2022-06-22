# Fibonacci

In this tutorial, we want to arrive at a bug-free fibonacci implementation. Let's start with a basic setup:

```bash
$ cargo new --lib my_fibonacci
```

```rust
// src/lib.rs

pub fn fibonacci(number: u64) -> u64 {
    let mut a = 0;
    let mut b = 1;

    for _ in 0..number {
        b += core::mem::replace(&mut a, b);
    }

    b
}
```

Now we define a test:

```bash
$ cargo bolero new fibonacci_test --generator
```

```rust
// tests/fibonacci_test/main.rs
use bolero::check;
use my_fibonacci::fibonacci;

fn main() {
    check!()
        .with_type()
        .cloned()
        .for_each(|number: u64| {
            fibonacci(number);
        })
}
```

Now let's fuzz our `fibonacci` function:

```bash
$ cargo bolero test fibonacci_test
    Finished test [unoptimized + debuginfo] target(s) in 0.10s
     Running target/fuzz/build_62a8ab526939db81/x86_64-apple-darwin/debug/deps/fibonacci_test-f9f8f1dcc806b6b6
...
thread 'main' panicked at 'attempt to add with overflow', my_fibonacci/tests/fibonacci_test/main.rs:8:9
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace

======================== Test Failure ========================

Input:
93

Error:
panicked at 'attempt to add with overflow', my_fibonacci/tests/fibonacci_test/fuzz_target.rs:8:9

==============================================================
```

Uh oh... It looks like we've got a bug! `bolero` was able to find that calling our function with `93` results in an integer overflow. It's try fixing that by adding overflow checks with [`u64::checked_add`](https://doc.rust-lang.org/std/primitive.u64.html#method.checked_add):

```rust
// src/lib.rs

pub fn fibonacci(number: u64) -> Option<u64> {
    let mut a = 0u64;
    let mut b = 1u64;

    for _ in 0..number {
        b = b.checked_add(core::mem::replace(&mut a, b))?;
    }

    Some(b)
}
```

After running the `test` command for a few minutes things are looking better:

```bash
$ cargo bolero test fibonacci_test
    Finished test [unoptimized + debuginfo] target(s) in 0.10s
     Running target/fuzz/build_62a8ab526939db81/x86_64-apple-darwin/debug/deps/fibonacci_test-f9f8f1dcc806b6b6
...
#272    INITED cov: 469 ft: 872 corp: 17/106b lim: 4 exec/s: 0 rss: 27Mb
    NEW_FUNC[1/1]: 0x102ef95f1
#277    NEW    cov: 476 ft: 880 corp: 18/112b lim: 6 exec/s: 0 rss: 27Mb L: 6/13 MS: 5 ChangeByte-ChangeBit-CopyPart-CopyPart-CrossOver-
#293    REDUCE cov: 476 ft: 880 corp: 18/109b lim: 6 exec/s: 0 rss: 27Mb L: 3/13 MS: 1 EraseBytes-
#341    NEW    cov: 476 ft: 928 corp: 19/119b lim: 6 exec/s: 0 rss: 27Mb L: 10/13 MS: 3 CMP-CopyPart-ChangeBinInt- DE: " \x00\x00\x00\x00\x00\x00\x00"-
#369    REDUCE cov: 476 ft: 928 corp: 19/118b lim: 6 exec/s: 0 rss: 27Mb L: 2/13 MS: 3 ShuffleBytes-ShuffleBytes-EraseBytes-
#397    REDUCE cov: 476 ft: 928 corp: 19/117b lim: 6 exec/s: 0 rss: 27Mb L: 1/13 MS: 3 ShuffleBytes-ChangeByte-EraseBytes-
#409    NEW    cov: 476 ft: 984 corp: 20/130b lim: 6 exec/s: 0 rss: 27Mb L: 13/13 MS: 2 ChangeByte-ChangeBinInt-
#501    NEW    cov: 476 ft: 1033 corp: 21/143b lim: 6 exec/s: 0 rss: 27Mb L: 13/13 MS: 2 ChangeBit-ChangeBinInt-
#977    REDUCE cov: 476 ft: 1033 corp: 21/139b lim: 8 exec/s: 0 rss: 27Mb L: 9/13 MS: 1 EraseBytes-
#1289   REDUCE cov: 476 ft: 1033 corp: 21/136b lim: 11 exec/s: 0 rss: 27Mb L: 10/13 MS: 2 ChangeASCIIInt-EraseBytes-
#1670   REDUCE cov: 476 ft: 1033 corp: 21/132b lim: 14 exec/s: 0 rss: 27Mb L: 9/10 MS: 1 EraseBytes-
#1741   REDUCE cov: 476 ft: 1033 corp: 21/131b lim: 14 exec/s: 0 rss: 27Mb L: 9/10 MS: 1 EraseBytes-
#10199  REDUCE cov: 476 ft: 1033 corp: 21/127b lim: 92 exec/s: 5099 rss: 27Mb L: 5/10 MS: 2 ChangeByte-EraseBytes-
#10455  REDUCE cov: 476 ft: 1033 corp: 21/125b lim: 92 exec/s: 5227 rss: 27Mb L: 3/10 MS: 1 EraseBytes-
#11753  REDUCE cov: 476 ft: 1033 corp: 21/121b lim: 104 exec/s: 5876 rss: 27Mb L: 5/10 MS: 3 ChangeBinInt-InsertByte-EraseBytes-
```

Are we done? Not quite... This is a good time to point out that basic fuzz testing can only get you so far. If we look on [Wikipedia](https://en.wikipedia.org/wiki/Fibonacci_number#Sequence_properties) we find the following table:

| F0 | F1 | F2 | F3 | F4 | F5 | F6 | F7 | F8 | F9 | F10|
|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| 0  |  1 |  1 |  2 |  3 |  5 |  8 | 13 | 21 | 34 | 55 |

Do we actually know if the return value is correct? All we've really made sure of is that the implementation doesn't panic. It could be returning `42` for every answer and our fuzz tests wouldn't have caught it. How do we fix this?

## Test Oracle

Using [test oracles](https://en.wikipedia.org/wiki/Test_oracle) in conjection with our test can be an effective way to assert our implementation is correct. What is a test oracle? From [Write Fuzzable Code](https://blog.regehr.org/archives/1687):

> A test oracle decides whether a test case triggered a bug or not. By default, the only oracle available to a fuzzer like afl is provided by the OS’s page protection mechanism. In other words, it detects only crashes. We can do much better than this.
>
> Assertions and their compiler-inserted friends — sanitizer checks — are another excellent kind of oracle. You should fuzz using as many of these checks as possible. Beyond these easy oracles, many more possibilities exist, such as:
>
> * function-inverse pairs: does a parse-print loop, compress-decompress loop, encrypt-decrypt loop, or similar, work as expected?
> * differential: do two different implementations, or modes of the same implementation, show the same behavior?
> * metamorphic: does the system show the same behavior when a test case is modified in a semantics-preserving way, such as adding a layer of parentheses to an expression?
> * resource: does the system consume a reasonable amount of time, memory, etc. when processing an input?
> * domain specific: for example, is a lossily-compressed image sufficiently visually similar to its uncompressed version?

We've already seen a good example of a test oracle in action. Rust includes debug assertions for unchecked integer overflows. We were able to use these assertions in finding the limits of our implementation.

Unit tests could also be considered as test oracles and can be effective at asserting expected behavior of well known inputs and outputs.

### Unit tests

The easiest solution is to copy the table values from wikipedia and test our function with a unit test:

```rust
// src/lib.rs

#[test]
fn fibonacci_test() {
    assert_eq!(fibonacci(0), Some(0));
    assert_eq!(fibonacci(1), Some(1));
    assert_eq!(fibonacci(2), Some(1));
    assert_eq!(fibonacci(3), Some(2));
    assert_eq!(fibonacci(4), Some(3));
    assert_eq!(fibonacci(5), Some(5));
    assert_eq!(fibonacci(6), Some(8));
    assert_eq!(fibonacci(7), Some(13));
    assert_eq!(fibonacci(8), Some(21));
    assert_eq!(fibonacci(9), Some(34));
    assert_eq!(fibonacci(10), Some(55));
}
```

Let's try running our unit test:

```bash
$ cargo test
    Finished test [unoptimized + debuginfo] target(s) in 52.06s
     Running target/debug/deps/my_fibonacci-e9bfbebb80b3a5bf

running 1 test
test fibonacci_test ... FAILED

failures:

---- fibonacci_test stdout ----
thread 'fibonacci_test' panicked at 'assertion failed: `(left == right)`
  left: `Some(1)`,
 right: `Some(0)`', my_fibonacci/src/lib.rs:29:5
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace


failures:
    fibonacci_test

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out

error: test failed, to rerun pass '--lib'
```

We haven't handled our zero case! Let's fix that:

```rust
// src/lib.rs

pub fn fibonacci(number: u64) -> Option<u64> {
    if number == 0 {
        return Some(0);
    }

    let mut a = 0u64;
    let mut b = 1u64;

    for _ in 0..number {
        b = b.checked_add(core::mem::replace(&mut a, b))?;
    }

    Some(b)
}
```

Let's run the test again:

```bash
$ cargo test
    Finished test [unoptimized + debuginfo] target(s) in 52.06s
     Running target/debug/deps/my_fibonacci-e9bfbebb80b3a5bf

running 1 test
test fibonacci_test ... FAILED

failures:

---- fibonacci_test stdout ----
thread 'fibonacci_test' panicked at 'assertion failed: `(left == right)`
  left: `Some(2)`,
 right: `Some(1)`', my_fibonacci/src/lib.rs:35:5
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace


failures:
    fibonacci_test

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out

error: test failed, to rerun pass '--lib'
```

Another bug!? In this case we're actually looping 1 too many times. Here's the fix:

```rust
// src/lib.rs

pub fn fibonacci(number: u64) -> Option<u64> {
    if number == 0 {
        return Some(0);
    }

    let mut a = 0u64;
    let mut b = 1u64;

    for _ in 1..number {
        b = b.checked_add(core::mem::replace(&mut a, b))?;
    }

    Some(b)
}
```

After that final fix all of our tests pass:

```bash
$ cargo test
    Finished test [unoptimized + debuginfo] target(s) in 52.06s
     Running target/debug/deps/my_fibonacci-e9bfbebb80b3a5bf

running 1 test
test fibonacci_test ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

     Running target/debug/deps/fibonacci_test-e98d85aab754d963

running 1022 tests
...............................................................................
...............................................................................
...............................................................................
...............................................................................
...............................................................................
...............................................................................
...............................................................................
...............................................................................
...............................................................................
...............................................................................
...............................................................................
...............................................................................
..........................................................................
test result: ok. 1022 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

### Differential Oracle

We could also try to use the less-efficient, recursive method to check our implementation. It's easy to understand and implement:

```rust
fn fibonacci_reccursive(n: u64) -> Option<u64> {
    match n {
        0 => Some(0),
        1 => Some(1),
        _ => fibonacci_reccursive(n - 1)?.checked_add(fibonacci_reccursive(n - 2)?),
    }
}
```

The problem with that approach is it ends up being _way_ too slow for larger numbers, even in `--release` mode.

Another option is to use a 3rd party implementation. Doing a quick search on [crates.io](https://crates.io/) results in a [crate that implements the fibonacci sequence](https://crates.io/crates/fibonacci). There's also a problem with that: the crate actually has the same bug as our implementation. It skips the first two values in the sequence `0` and `1`.

### Conclusion

The takeaway is some thought needs to go into how to test your implementation effectively. Often times, combining multiple approaches will provide the best result.
