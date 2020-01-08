use crate::{Config, FuzzArgs, ReduceArgs};
use failure::Error;

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
    std::env::args().next().unwrap()
}

pub(crate) fn fuzz(config: &Config, fuzz: &FuzzArgs) -> Result<(), Error> {
    let bin_path = config.bin_path(FLAGS, "honggfuzz");
    let test_target = config.test_target()?;
    let corpus_dir = test_target.corpus_dir();
    let crashes_dir = test_target.crashes_dir();

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

pub(crate) fn reduce(config: &Config, _reduce: &ReduceArgs) -> Result<(), Error> {
    let bin_path = config.bin_path(FLAGS, "honggfuzz");
    let test_target = config.test_target()?;
    let corpus_dir = test_target.corpus_dir();
    let crashes_dir = test_target.crashes_dir();

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
