use crate::{reduce, test, Selection};
use anyhow::Result;
use std::fs;

const FLAGS: &[&str] = &[
    "--cfg fuzzing_honggfuzz",
    "-Clink-args=-lhfuzz",
    "-Cllvm-args=-sanitizer-coverage-level=4",
    "-Cllvm-args=-sanitizer-coverage-prune-blocks=0",
    #[cfg(not(target_os = "macos"))]
    "-Cllvm-args=-sanitizer-coverage-trace-compares",
    "-Cllvm-args=-sanitizer-coverage-trace-divs",
    "-Cllvm-args=-sanitizer-coverage-trace-pc",
    "-Cllvm-args=-sanitizer-coverage-trace-pc-guard",
];

fn bin() -> String {
    std::env::current_exe()
        .expect("valid current_exe")
        .display()
        .to_string()
}

macro_rules! optional_arg {
    ($cmd:ident, $harg:expr, $arg:expr) => {
        if let Some(value) = $arg {
            $cmd.push($harg.to_string());
            $cmd.push(format!("{value}"));
        }
    };
}

pub(crate) fn test(selection: &Selection, test_args: &test::Args) -> Result<()> {
    let test_target = selection.test_target(FLAGS, "honggfuzz")?;
    let corpus_dir = test_args
        .corpus_dir
        .clone()
        .unwrap_or_else(|| test_target.default_corpus_dir());
    let crashes_dir = test_args
        .crashes_dir
        .clone()
        .unwrap_or_else(|| test_target.default_crashes_dir());

    fs::create_dir_all(&corpus_dir)?;
    fs::create_dir_all(&crashes_dir)?;

    let mut args = vec![
        bin(),
        "--persistent".to_string(),
        "-i".to_string(),
        corpus_dir.to_str().unwrap().to_string(),
        "--workspace".to_string(),
        crashes_dir.to_str().unwrap().to_string(),
        "--timeout".to_string(),
        format!("{}", test_args.timeout_as_secs()),
        // make it consistent with libfuzzer
        "--exit_upon_crash".to_string(),
    ];

    optional_arg!(args, "--run_timeout", test_args.time_as_secs());
    optional_arg!(args, "--iterations", test_args.runs);
    optional_arg!(args, "--threads", test_args.jobs);
    optional_arg!(args, "--max_file_size", test_args.max_input_length);

    args.extend(test_args.engine_args.iter().cloned());

    args.push("--".to_string());

    for (k, v) in test_target.command_env() {
        std::env::set_var(k, v);
    }
    args.push(test_target.exe.to_string());
    args.extend(test_target.command_args().map(String::from));

    unsafe { bolero_honggfuzz::exec(args.into_iter()) };

    Ok(())
}

pub(crate) fn reduce(selection: &Selection, reduce: &reduce::Args) -> Result<()> {
    let test_target = selection.test_target(FLAGS, "honggfuzz")?;
    let corpus_dir = test_target.default_corpus_dir();
    let crashes_dir = test_target.default_crashes_dir();

    fs::create_dir_all(&corpus_dir)?;
    fs::create_dir_all(&crashes_dir)?;

    let mut args = vec![
        bin(),
        "--persistent".to_string(),
        "-i".to_string(),
        corpus_dir.to_str().unwrap().to_string(),
        "--workspace".to_string(),
        crashes_dir.to_str().unwrap().to_string(),
        "-M".to_string(),
    ];

    args.extend(reduce.engine_args.iter().cloned());

    args.push("--".to_string());
    for (k, v) in test_target.command_env() {
        std::env::set_var(k, v);
    }
    args.push(test_target.exe.to_string());
    args.extend(test_target.command_args().map(String::from));

    unsafe { bolero_honggfuzz::exec(args.into_iter()) };

    Ok(())
}
