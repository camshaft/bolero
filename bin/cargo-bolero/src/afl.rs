use crate::{reduce, test, Selection};
use anyhow::Result;
use std::fs;

const FLAGS: &[&str] = &[
    "--cfg fuzzing_afl",
    "-Cllvm-args=-sanitizer-coverage-level=3",
    "-Cllvm-args=-sanitizer-coverage-trace-pc-guard",
    "-Cllvm-args=-sanitizer-coverage-prune-blocks=0",
];

fn bin() -> String {
    std::env::current_exe()
        .expect("valid current_exe")
        .display()
        .to_string()
}

pub(crate) fn test(selection: &Selection, test_args: &test::Args) -> Result<()> {
    let test_target = selection.test_target(FLAGS, "afl")?;
    let corpus_dir = test_args
        .corpus_dir
        .clone()
        .unwrap_or_else(|| test_target.default_corpus_dir());
    let afl_state = test_target.workdir().join("afl_state");

    fs::create_dir_all(&afl_state)?;
    fs::create_dir_all(&corpus_dir)?;

    // if the corpus dir is empty create an initial file to make AFL happy
    if corpus_dir.read_dir()?.next().is_none() {
        fs::write(corpus_dir.join("initial"), "file to make AFL happy")?;
    }

    if let Some(runs) = test_args.runs {
        std::env::set_var("AFL_EXIT_WHEN_DONE", "1");
        let cycles = runs / 100_000; // a cycle is about 100,000 runs
        std::env::set_var("BOLERO_AFL_MAX_CYCLES", format!("{}", cycles));
    }

    let mut args = vec![
        bin(),
        "-i".to_string(),
        corpus_dir.to_str().unwrap().to_string(),
        "-o".to_string(),
        afl_state.to_str().unwrap().to_string(),
    ];

    args.extend(test_args.engine_args.iter().cloned());

    args.push("--".to_string());

    for (k, v) in test_target.command_env() {
        std::env::set_var(k, v);
    }
    args.push(test_target.exe.to_string());
    args.extend(test_target.command_args().map(String::from));

    unsafe { bolero_afl::exec(args.into_iter()) };

    Ok(())
}

pub(crate) fn reduce(_selection: &Selection, _reduce_args: &reduce::Args) -> Result<()> {
    todo!()
}
