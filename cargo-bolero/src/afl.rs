use crate::{Config, FuzzArgs, ReduceArgs};
use failure::Error;

const FLAGS: &[&str] = &[
    "--cfg fuzzing_afl",
    "-Cllvm-args=-sanitizer-coverage-level=3",
    "-Cllvm-args=-sanitizer-coverage-trace-pc-guard",
    "-Cllvm-args=-sanitizer-coverage-prune-blocks=0",
];

fn bin() -> String {
    std::env::args().next().unwrap()
}

pub(crate) fn fuzz(config: &Config, fuzz: &FuzzArgs) -> Result<(), Error> {
    let bin_path = config.bin_path(FLAGS, "afl");
    let test_target = config.test_target()?;
    let corpus_dir = test_target.corpus_dir();
    let afl_state = test_target.workdir().join("afl_state");

    if let Some(runs) = fuzz.runs {
        std::env::set_var("AFL_EXIT_WHEN_DONE", "1");
        let cycles = runs / 100_000; // a cycle is about 100,000 runs
        std::env::set_var("BOLERO_AFL_MAX_CYCLES", format!("{}", cycles));
    }

    let args = vec![
        bin(),
        "-i".to_string(),
        corpus_dir.to_str().unwrap().to_string(),
        "-o".to_string(),
        afl_state.to_str().unwrap().to_string(),
        "--".to_string(),
        bin_path.to_str().unwrap().to_string(),
    ]
    .into_iter();

    unsafe { bolero_afl::exec(args) };

    Ok(())
}

pub(crate) fn reduce(_config: &Config, _shrink: &ReduceArgs) -> Result<(), Error> {
    unimplemented!()
}
