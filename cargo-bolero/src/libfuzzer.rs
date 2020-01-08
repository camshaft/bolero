use crate::{exec, Config, FuzzArgs, ReduceArgs};
use failure::Error;
use std::fs;

macro_rules! optional_arg {
    ($cmd:ident, $arg:expr, $fmt:expr) => {
        if let Some(value) = $arg {
            $cmd.arg(&format!($fmt, value));
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

pub(crate) fn fuzz(config: &Config, fuzz: &FuzzArgs) -> Result<(), Error> {
    let mut cmd = config.cmd("test", FLAGS, "libfuzzer");
    let test_target = config.test_target()?;
    let corpus_dir = test_target.corpus_dir();
    let crashes_dir = test_target.crashes_dir();

    fs::create_dir_all(&corpus_dir).unwrap();
    fs::create_dir_all(&crashes_dir).unwrap();

    cmd.arg(corpus_dir)
        .arg(&format!("-artifact_prefix={}/", crashes_dir.display()));

    optional_arg!(cmd, fuzz.seed, "-seed={}");
    optional_arg!(cmd, fuzz.runs, "-runs={}");
    optional_arg!(cmd, fuzz.time, "-max_total_time={}");
    optional_arg!(cmd, fuzz.max_input_length, "-max_len={}");

    // TODO figure out log file location
    optional_arg!(cmd, fuzz.jobs, "-jobs={}");

    exec(cmd).exit_on_error();

    Ok(())
}

pub(crate) fn reduce(config: &Config, _reduce: &ReduceArgs) -> Result<(), Error> {
    let mut cmd = config.cmd("test", FLAGS, "libfuzzer");
    let test_target = config.test_target()?;
    let corpus_dir = test_target.corpus_dir();

    let tmp = tempfile::tempdir().expect("could not create tmpdir");
    let tmp_corpus = tmp.path().join("corpus");
    fs::create_dir(&tmp_corpus).unwrap();

    cmd.arg(&tmp_corpus)
        .arg(&corpus_dir)
        .arg("-shrink=1")
        .arg("-merge=1")
        .arg("-reduce_inputs=1");

    let status = exec(cmd);

    fs::remove_dir_all(&corpus_dir).unwrap();
    fs::rename(&tmp_corpus, &corpus_dir).unwrap();

    status.exit_on_error();

    Ok(())
}
