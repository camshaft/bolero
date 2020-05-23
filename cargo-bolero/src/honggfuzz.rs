use crate::{FuzzArgs, ReduceArgs, Selection};
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

pub(crate) fn fuzz(selection: &Selection, fuzz: &FuzzArgs) -> Result<()> {
    let test_target = selection.test_target(FLAGS, "honggfuzz")?;
    let corpus_dir = test_target.corpus_dir();
    let crashes_dir = test_target.crashes_dir();

    fs::create_dir_all(&corpus_dir)?;
    fs::create_dir_all(&crashes_dir)?;

    let mut args = vec![
        bin(),
        "--persistent".to_string(),
        "-i".to_string(),
        corpus_dir.to_str().unwrap().to_string(),
        "--workspace".to_string(),
        crashes_dir.to_str().unwrap().to_string(),
    ];

    if let Some(runs) = fuzz.runs {
        args.push("--iterations".to_string());
        args.push(format!("{}", runs));
    }

    args.push("--".to_string());
    args.push(test_target.exe.to_string());
    args.extend(test_target.command_args().map(String::from));

    unsafe { bolero_honggfuzz::exec(args.into_iter()) };

    Ok(())
}

pub(crate) fn reduce(selection: &Selection, _reduce: &ReduceArgs) -> Result<()> {
    let test_target = selection.test_target(FLAGS, "honggfuzz")?;
    let corpus_dir = test_target.corpus_dir();
    let crashes_dir = test_target.crashes_dir();

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
        "--".to_string(),
        test_target.exe.to_string(),
    ];

    args.extend(test_target.command_args().map(String::from));

    unsafe { bolero_honggfuzz::exec(args.into_iter()) };

    Ok(())
}
