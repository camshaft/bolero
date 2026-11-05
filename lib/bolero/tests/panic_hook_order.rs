//! The test engine's panic hook and the default scope's panic hook are both installed, in
//! either order of first use, and the engine's hook wraps the default scope's.
//!
//! Each test below runs one of the `*_child` tests of this binary in a child process, so that
//! each case starts without either hook, and reads what the child printed.

use bolero::any;
use bolero_engine::panic as engine;
use std::process::{Command, Output};

/// Set in the environment of a child process, where a `*_child` test runs
const CHILD: &str = "BOLERO_PANIC_HOOK_CHILD";

/// The variable that seeds the default scope, which starts each line that prints a seed
const SEED: &str = "BOLERO_RANDOM_SEED";

fn is_child() -> bool {
    std::env::var_os(CHILD).is_some()
}

/// Runs the test `name` of this binary in a child process, with `BOLERO_RANDOM_SEED` unset
fn run_child(name: &str) -> Output {
    let exe = std::env::current_exe().unwrap();
    let mut command = Command::new(exe);
    command.args([name, "--exact", "--nocapture"]);
    command.env(CHILD, "1");
    command.env_remove(SEED);
    command.output().unwrap()
}

/// What the child printed on stderr
fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// The number of the first line of `text` that holds `needle`
fn line_of(text: &str, needle: &str) -> usize {
    let mut lines = text.lines();
    let number = lines.position(|line| line.contains(needle));
    assert!(number.is_some(), "no line holds {needle}:\n{text}");
    number.unwrap()
}

/// Panics after a draw from the default scope, with the engine's hook set to forward the panic
/// to the hook it replaced or not, and prints whether the engine's hook recorded the panic
fn panic_after_draw(forward: bool) {
    let prev = engine::forward_panic(forward);
    let result = std::panic::catch_unwind(|| {
        let _: u64 = any();
        panic!("the test fails after it draws from the default scope");
    });
    engine::forward_panic(prev);
    assert!(result.is_err());

    // the engine's hook records each panic it sees, whether it forwards it or not
    let recorded = engine::take_panic().is_some();
    eprintln!("forward={forward} recorded={recorded}");
}

#[test]
fn engine_hook_first_child() {
    if !is_child() {
        return;
    }

    // the engine installs its hook before this thread draws from the default scope
    engine::set_hook();
    panic_after_draw(false);
    panic_after_draw(true);
}

#[test]
fn scope_hook_first_child() {
    if !is_child() {
        return;
    }

    // the first draw from the default scope installs its hook before the engine installs its own
    let _: u64 = any();
    engine::set_hook();
    panic_after_draw(false);
    panic_after_draw(true);
}

#[test]
fn both_hooks_run_in_either_order_of_install() {
    for name in ["engine_hook_first_child", "scope_hook_first_child"] {
        let output = run_child(name);
        let text = stderr(&output);
        assert!(output.status.success(), "{text}");

        // the engine's hook recorded both panics, so the default scope's install didn't drop it
        let unforwarded = line_of(&text, "forward=false recorded=true");
        let forwarded = line_of(&text, "forward=true recorded=true");

        // the default scope's hook printed one seed line, so the engine's install didn't drop it,
        // and it printed the line for the forwarded panic alone, so the engine's hook wraps it
        let prefix = format!("{SEED}=");
        let is_seed = |line: &&str| line.starts_with(prefix.as_str());
        let seeds = text.lines().filter(is_seed).count();
        assert_eq!(seeds, 1, "{text}");
        let seed = line_of(&text, prefix.as_str());
        assert!(unforwarded < seed && seed < forwarded, "{text}");
    }
}
