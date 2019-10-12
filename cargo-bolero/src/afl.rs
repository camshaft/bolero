use crate::{Config, FuzzArgs, ShrinkArgs};
use failure::Error;

const FLAGS: &[&str] = &["--cfg fuzzing_afl"];

fn bin() -> String {
    std::env::args().nth(0).unwrap()
}

pub(crate) fn fuzz(config: &Config, fuzz: &FuzzArgs) -> Result<(), Error> {
    let bin_path = config.bin_path(FLAGS);
    let workdir = config.workdir()?;
    let corpus_dir = workdir.join("corpus");
    let afl_state = workdir.join("afl_state");

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

pub(crate) fn shrink(_config: &Config, _shrink: &ShrinkArgs) -> Result<(), Error> {
    unimplemented!()
}
