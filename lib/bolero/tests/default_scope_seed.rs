//! The default scope of `any` reads its seed from `BOLERO_RANDOM_SEED`, and prints the seed
//! when a test that drew from it panics outside a harness.
//!
//! Each test below runs one of the `*_child` tests of this binary in a child process, with the
//! environment its case needs, and reads what the child printed.

use bolero::{any, check};
use bolero_generator::{any::scope, driver};
use rand::{rngs::StdRng, SeedableRng};
use std::process::{Command, Output};

/// Set in the environment of a child process, where a `*_child` test runs
const CHILD: &str = "BOLERO_DEFAULT_SCOPE_CHILD";

/// The variable that seeds the default scope, which starts each line that prints a seed
const SEED: &str = "BOLERO_RANDOM_SEED";

/// The exit code of a test binary whose test failed
const FAILED: i32 = 101;

fn is_child() -> bool {
    std::env::var_os(CHILD).is_some()
}

/// Runs the test `name` of this binary in a child process, with `BOLERO_RANDOM_SEED` set to
/// `seed`, or unset where `seed` is `None`
fn run_child(name: &str, seed: Option<&str>) -> Output {
    let exe = std::env::current_exe().unwrap();
    let mut command = Command::new(exe);
    command.args([name, "--exact", "--nocapture"]);
    command.env(CHILD, "1");
    if let Some(seed) = seed {
        command.env(SEED, seed);
    } else {
        command.env_remove(SEED);
    }
    command.output().unwrap()
}

/// What the child printed on stderr
fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// The line that holds the values the child drew, which it printed on stdout
fn values(output: &Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut lines = stdout.lines();
    let line = lines.find(|line| line.starts_with("values="));
    line.expect("the child prints its values").to_string()
}

/// Each seed the child printed on stderr, in a line `BOLERO_RANDOM_SEED=<seed>`
fn seeds(output: &Output) -> Vec<String> {
    let prefix = format!("{SEED}=");
    let text = stderr(output);
    let mut seeds = vec![];
    for line in text.lines() {
        if let Some(seed) = line.strip_prefix(prefix.as_str()) {
            seeds.push(seed.to_string());
        }
    }
    seeds
}

/// The number of the first line of `text` that holds `needle`
fn line_of(text: &str, needle: &str) -> usize {
    let mut lines = text.lines();
    let number = lines.position(|line| line.contains(needle));
    assert!(number.is_some(), "no line holds {needle}:\n{text}");
    number.unwrap()
}

/// Draws the values a child prints, from the scope that `any` reads
fn draw() -> Vec<u64> {
    (0..4).map(|_| any()).collect()
}

/// Fails the test it is called from, with a call whose type is `()`
fn fail(why: &str) {
    panic!("{why}");
}

/// Draws from the default scope as it drops
struct DrawOnDrop;

impl Drop for DrawOnDrop {
    fn drop(&mut self) {
        println!("values={:?}", draw());
    }
}

#[test]
fn draw_child() {
    if !is_child() {
        return;
    }

    println!("values={:?}", draw());
}

#[test]
fn panic_child() {
    if !is_child() {
        return;
    }

    // a harness that ends before the draws leaves the seed's report on
    check!().with_iterations(1).run(|| {});

    println!("values={:?}", draw());
    panic!("the test fails after it draws from the default scope");
}

#[test]
fn drop_draw_child() {
    if !is_child() {
        return;
    }

    // the first draw from the default scope comes while the test panics
    let _draw = DrawOnDrop;
    panic!("the test fails before it draws from the default scope");
}

#[test]
fn other_scope_child() {
    if !is_child() {
        return;
    }

    // another thread draws from its default scope, which installs the panic hook
    std::thread::spawn(draw).join().unwrap();

    let rng = StdRng::seed_from_u64(1);
    let rng = driver::Rng::new(rng, &driver::Options::default());
    let rng = Box::new(driver::object::Object(rng));
    let (_rng, values) = scope::with(rng, draw);
    println!("values={values:?}");
    panic!("the test fails after it draws from a scope that `with` set");
}

#[test]
fn check_child() {
    if !is_child() {
        return;
    }

    check!().with_type::<u64>().for_each(|_: &u64| {
        // the harness doesn't set a scope here, so this draws from the default scope
        let _: u64 = any();
        fail("the input fails after it draws from the default scope");
    });
}

#[test]
fn check_after_draw_child() {
    if !is_child() {
        return;
    }

    let _: u64 = any();
    check!().with_type::<u64>().for_each(|_: &u64| {
        let _: u64 = any();
        fail("the input fails after it draws from the default scope");
    });
}

#[test]
fn a_seed_draws_the_same_values_on_each_run() {
    let first = run_child("draw_child", Some("1234"));
    let second = run_child("draw_child", Some("1234"));
    let other = run_child("draw_child", Some("5678"));

    assert!(first.status.success(), "{}", stderr(&first));
    assert_eq!(values(&first), values(&second));
    assert_ne!(values(&first), values(&other));
    // a test that doesn't panic doesn't print a seed
    assert!(seeds(&first).is_empty(), "{}", stderr(&first));
}

#[test]
fn a_panic_prints_the_seed_that_replays_the_draws() {
    let first = run_child("panic_child", None);
    let text = stderr(&first);
    assert_eq!(first.status.code(), Some(FAILED), "{text}");
    // the panic hook that the report replaced still prints the panic
    assert!(text.contains("the test fails after it draws"), "{text}");

    let printed = seeds(&first);
    assert_eq!(printed.len(), 1, "{text}");
    // the seed is in the decimal form that `BOLERO_RANDOM_SEED` reads
    let seed: u128 = printed[0].parse().unwrap();
    let seed = seed.to_string();

    let replay = run_child("panic_child", Some(seed.as_str()));
    assert_eq!(replay.status.code(), Some(FAILED), "{}", stderr(&replay));
    assert_eq!(values(&replay), values(&first));
    assert_eq!(seeds(&replay), printed);
}

#[test]
fn a_first_draw_while_the_test_panics_doesnt_abort() {
    let output = run_child("drop_draw_child", None);
    let text = stderr(&output);
    // a test binary that aborts doesn't exit with the code of a failed test
    assert_eq!(output.status.code(), Some(FAILED), "{text}");
    // the drop drew its values as the test panicked
    values(&output);
}

#[test]
fn a_panic_after_draws_from_another_scope_doesnt_print_a_seed() {
    let output = run_child("other_scope_child", None);
    let text = stderr(&output);
    assert_eq!(output.status.code(), Some(FAILED), "{text}");
    assert!(text.contains("from a scope that `with` set"), "{text}");
    assert!(seeds(&output).is_empty(), "{text}");
}

#[test]
fn a_failing_check_prints_the_harness_seed_alone() {
    for name in ["check_child", "check_after_draw_child"] {
        let output = run_child(name, None);
        let text = stderr(&output);
        assert_eq!(output.status.code(), Some(FAILED), "{text}");

        // the first seed line is the one in the harness's failure report
        let report = line_of(&text, "Test Failure");
        let first_seed = line_of(&text, SEED);
        assert!(report < first_seed, "{text}");

        // and no other line prints a different seed
        let printed = seeds(&output);
        assert!(printed.iter().all(|seed| seed == &printed[0]), "{text}");
    }
}
