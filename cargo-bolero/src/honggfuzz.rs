use crate::{Config, FuzzArgs, ShrinkArgs};
use failure::Error;

const FLAGS: &[&str] = &[
    "--cfg fuzzing_honggfuzz",
    "-Cllvm-args=-sanitizer-coverage-level=3",
    "-Cllvm-args=-sanitizer-coverage-trace-pc-guard",
    "-Cllvm-args=-sanitizer-coverage-prune-blocks=0",
    // "-Cllvm-args=-sanitizer-coverage-trace-compares",
    "-Cllvm-args=-sanitizer-coverage-trace-divs",
    "-Cllvm-args=-sanitizer-coverage-trace-geps",
    "-Clink-args=-lhfuzz",
];

fn bin() -> String {
    std::env::args().nth(0).unwrap()
}

pub(crate) fn fuzz(config: &Config, fuzz: &FuzzArgs) -> Result<(), Error> {
    let bin_path = config.bin_path(FLAGS);
    let workdir = config.workdir()?;
    let corpus_dir = workdir.join("corpus");
    let crashes_dir = workdir.join("crashes");

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
    args.push(bin_path.to_str().unwrap().to_string());

    unsafe { bolero_honggfuzz::exec(args.into_iter()) };

    Ok(())
}

pub(crate) fn shrink(config: &Config, _shrink: &ShrinkArgs) -> Result<(), Error> {
    let bin_path = config.bin_path(FLAGS);
    let workdir = config.workdir()?;
    let corpus_dir = workdir.join("corpus");
    let crashes_dir = workdir.join("crashes");

    let args = vec![
        bin(),
        "--persistent".to_string(),
        "-i".to_string(),
        corpus_dir.to_str().unwrap().to_string(),
        "--workspace".to_string(),
        crashes_dir.to_str().unwrap().to_string(),
        "-M".to_string(),
        "--".to_string(),
        bin_path.to_str().unwrap().to_string(),
    ];

    unsafe { bolero_honggfuzz::exec(args.into_iter()) };

    Ok(())
}
