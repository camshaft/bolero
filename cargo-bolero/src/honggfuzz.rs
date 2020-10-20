use crate::{flags, FuzzArgs, ReduceArgs, Selection};
use anyhow::Result;
use std::fs;

pub struct Honggfuzz;

impl crate::fuzzer::Env for Honggfuzz {
    const NAME: &'static str = "honggfuzz";

    fn sanitizer_flags(&self, target: &str) -> flags::Flags {
        flags::Flags {
            sanitizer_coverage_trace_compares: !target.contains("-apple-"),
            sanitizer_coverage_trace_divs: true,
            sanitizer_coverage_trace_pc_guard: true,
            ..flags::Flags::default()
        }
    }

    fn build_flags(&self, _: &str) -> std::vec::Vec<&'static str> {
        ["--cfg fuzzing_honggfuzz", "-Clink-args=-lhfuzz"].to_vec()
    }
}

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
            $cmd.push(format!("{}", value));
        }
    };
}

pub(crate) fn fuzz(selection: &Selection, fuzz: &FuzzArgs) -> Result<()> {
    let test_target = selection.test_target(Honggfuzz)?;
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
        "--timeout".to_string(),
        format!("{}", fuzz.timeout_as_secs()),
    ];

    optional_arg!(args, "--run_timeout", fuzz.time_as_secs());
    optional_arg!(args, "--iterations", fuzz.runs);
    optional_arg!(args, "--threads", fuzz.jobs);
    optional_arg!(args, "--max_file_size", fuzz.max_input_length);

    args.extend(fuzz.fuzzer_args.iter().cloned());

    args.push("--".to_string());

    for (k, v) in test_target.command_env() {
        std::env::set_var(k, v);
    }
    args.push(test_target.exe.to_string());
    args.extend(test_target.command_args().map(String::from));

    unsafe { bolero_honggfuzz::exec(args.into_iter()) };

    Ok(())
}

pub(crate) fn reduce(selection: &Selection, reduce: &ReduceArgs) -> Result<()> {
    let test_target = selection.test_target(Honggfuzz)?;
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
    ];

    args.extend(reduce.fuzzer_args.iter().cloned());

    args.push("--".to_string());
    for (k, v) in test_target.command_env() {
        std::env::set_var(k, v);
    }
    args.push(test_target.exe.to_string());
    args.extend(test_target.command_args().map(String::from));

    unsafe { bolero_honggfuzz::exec(args.into_iter()) };

    Ok(())
}
