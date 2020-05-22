use crate::{exec, Config, FuzzArgs, ReduceArgs};
use anyhow::Result;
use std::fs;

macro_rules! optional_arg {
    ($cmd:ident, $arg:expr, $fmt:expr) => {
        if let Some(value) = $arg {
            $cmd.push(format!($fmt, value));
        }
    };
}

const FLAGS: &[&str] = &[
    "--cfg fuzzing_libfuzzer",
    "-Cllvm-args=-sanitizer-coverage-inline-8bit-counters",
    "-Cllvm-args=-sanitizer-coverage-level=4",
    "-Cllvm-args=-sanitizer-coverage-pc-table",
    "-Cllvm-args=-sanitizer-coverage-prune-blocks=0",
    "-Cllvm-args=-sanitizer-coverage-trace-compares",
    "-Cllvm-args=-sanitizer-coverage-trace-divs",
    "-Cllvm-args=-sanitizer-coverage-trace-geps",
    "-Cllvm-args=-sanitizer-coverage-trace-pc",
    "-Cllvm-args=-sanitizer-coverage-trace-pc-guard",
    #[cfg(target_os = "linux")]
    "-Cllvm-args=-sanitizer-coverage-stack-depth",
];

pub(crate) fn fuzz(config: &Config, fuzz: &FuzzArgs) -> Result<()> {
    let test_target = config.test_target(FLAGS, "libfuzzer")?;
    let corpus_dir = test_target.corpus_dir();
    let crashes_dir = test_target.crashes_dir();

    fs::create_dir_all(&corpus_dir)?;
    fs::create_dir_all(&crashes_dir)?;

    let mut cmd = test_target.command();

    let mut args = vec![
        format!("{}", corpus_dir.display()),
        format!("-artifact_prefix={}/", crashes_dir.display()),
    ];

    optional_arg!(args, fuzz.seed, "-seed={}");
    optional_arg!(args, fuzz.runs, "-runs={}");
    optional_arg!(args, fuzz.time, "-max_total_time={}");
    optional_arg!(args, fuzz.max_input_length, "-max_len={}");

    // TODO figure out log file location
    optional_arg!(args, fuzz.jobs, "-jobs={}");

    cmd.env("BOLERO_LIBFUZZER_ARGS", args.join(" "));

    exec(cmd).exit_on_error();

    Ok(())
}

pub(crate) fn reduce(config: &Config, _reduce: &ReduceArgs) -> Result<()> {
    let test_target = config.test_target(FLAGS, "libfuzzer")?;
    let corpus_dir = test_target.corpus_dir();
    let tmp_corpus = test_target.temp_dir();

    fs::create_dir_all(&corpus_dir)?;
    fs::create_dir_all(&tmp_corpus)?;

    let mut cmd = test_target.command();

    let args = vec![
        format!("{}", tmp_corpus.display()),
        format!("{}", corpus_dir.display()),
        "-merge=1".to_string(),
    ];

    cmd.env("BOLERO_LIBFUZZER_ARGS", args.join(" "));

    exec(cmd).exit_on_error();

    fs::remove_dir_all(&corpus_dir)?;
    fs::rename(&tmp_corpus, &corpus_dir)?;

    Ok(())
}
