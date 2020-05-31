use crate::{FuzzArgs, ReduceArgs, Selection};
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

pub(crate) fn fuzz(selection: &Selection, fuzz: &FuzzArgs) -> Result<()> {
    let test_target = selection.test_target(FLAGS, "afl")?;
    let corpus_dir = test_target.corpus_dir();
    let afl_state = test_target.workdir().join("afl_state");

    fs::create_dir_all(&afl_state)?;
    fs::create_dir_all(&corpus_dir)?;

    if let Some(runs) = fuzz.runs {
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

    args.extend(fuzz.fuzzer_args.iter().cloned());

    args.push("--".to_string());

    for (k, v) in test_target.command_env() {
        std::env::set_var(k, v);
    }
    args.push(test_target.exe.to_string());
    args.extend(test_target.command_args().map(String::from));

    unsafe { bolero_afl::exec(args.into_iter()) };

    Ok(())
}

pub(crate) fn reduce(_selection: &Selection, _shrink: &ReduceArgs) -> Result<()> {
    todo!()
}
