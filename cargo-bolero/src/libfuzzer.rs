use crate::{exec, flags, FuzzArgs, ReduceArgs, Selection};
use anyhow::{anyhow, Result};
use bit_set::BitSet;
use core::cmp::Ordering;
use std::{
    fs,
    io::{BufRead, BufReader, Result as IOResult, Write},
    path::{Path, PathBuf},
};

macro_rules! optional_arg {
    ($cmd:ident, $arg:expr, $fmt:expr) => {
        if let Some(value) = $arg {
            $cmd.push(format!($fmt, value));
        }
    };
}

pub struct Libfuzzer;

impl crate::fuzzer::Env for Libfuzzer {
    const NAME: &'static str = "libfuzzer";

    fn sanitizer_flags(&self, target: &str) -> flags::Flags {
        flags::Flags {
            sanitizer_coverage_trace_pc_guard: true,
            sanitizer_coverage_inline_8bit_counters: true,
            sanitizer_coverage_pc_table: true,
            sanitizer_coverage_stack_depth: target.contains("-linux-"),
            sanitizer_coverage_trace_compares: true,
            ..flags::Flags::default()
        }
    }

    fn build_flags(&self, _: &str) -> std::vec::Vec<&'static str> {
        ["--cfg fuzzing_libfuzzer"].to_vec()
    }
}

pub(crate) fn fuzz(selection: &Selection, fuzz: &FuzzArgs) -> Result<()> {
    let test_target = selection.test_target(Libfuzzer)?;
    let corpus_dir = test_target.corpus_dir();
    let crashes_dir = test_target.crashes_dir();

    fs::create_dir_all(&corpus_dir)?;
    fs::create_dir_all(&crashes_dir)?;

    let mut cmd = test_target.command();

    let mut args = vec![
        format!("{}", corpus_dir.display()),
        format!("-artifact_prefix={}/", crashes_dir.display()),
        format!("-timeout={}", fuzz.timeout_as_secs()),
    ];

    optional_arg!(args, fuzz.seed, "-seed={}");
    optional_arg!(args, fuzz.runs, "-runs={}");
    optional_arg!(args, fuzz.time_as_secs(), "-max_total_time={}");
    optional_arg!(args, fuzz.max_input_length, "-max_len={}");

    // TODO figure out log file location
    optional_arg!(args, fuzz.jobs, "-jobs={}");

    args.extend(fuzz.fuzzer_args.iter().cloned());

    cmd.env("BOLERO_LIBFUZZER_ARGS", args.join(" "));

    exec(cmd)?;

    Ok(())
}

pub(crate) fn reduce(selection: &Selection, reduce: &ReduceArgs) -> Result<()> {
    let test_target = selection.test_target(Libfuzzer)?;
    let corpus_dir = test_target.corpus_dir();
    let tmp_corpus = test_target.temp_dir()?;

    fs::create_dir_all(&corpus_dir)?;
    fs::create_dir_all(&tmp_corpus)?;

    let mut control_file = tempfile::NamedTempFile::new()?;

    let inputs = write_control_file(&mut control_file, &corpus_dir)?;

    let mut cmd = test_target.command();

    let mut args = vec![
        format!("-merge_control_file={}", control_file.as_ref().display()),
        "-merge_inner=1".to_string(),
    ];

    args.extend(reduce.fuzzer_args.iter().cloned());

    cmd.env("BOLERO_LIBFUZZER_ARGS", args.join(" "));

    exec(cmd)?;

    let results = parse_control_file(&mut BufReader::new(control_file).lines(), &inputs)?;
    let mut covered_features = BitSet::<u64>::default();

    for result in results {
        let prev_len = covered_features.len();
        covered_features.union_with(&result.features);
        if prev_len != covered_features.len() {
            let new_file = tmp_corpus.path().join(result.path.file_name().unwrap());
            fs::rename(result.path, new_file)?;
        }
    }

    let backup = corpus_dir.parent().unwrap().join("_corpus_bkp");
    fs::rename(&corpus_dir, &backup)?;
    fs::rename(&tmp_corpus, &corpus_dir)?;
    fs::remove_dir_all(&backup)?;

    Ok(())
}

fn write_control_file<W: Write>(file: &mut W, corpus_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut inputs = vec![];
    for entry in fs::read_dir(corpus_dir)? {
        inputs.push(entry?.path());
    }
    inputs.sort();

    // The control file example:
    //
    // 3 # The number of inputs
    // 1 # The number of inputs in the first corpus, <= the previous number
    // file0
    // file1
    // file2  # One file name per line.
    // STARTED 0 123  # FileID, file size
    // FT 0 1 4 6 8  # FileID COV1 COV2 ...
    // COV 0 7 8 9 # FileID COV1 COV1
    // STARTED 1 456  # If FT is missing, the input crashed while processing.
    // STARTED 2 567
    // FT 2 8 9
    // COV 2 11 12

    writeln!(file, "{}", inputs.len())?;
    writeln!(file, "{}", inputs.len())?;
    for input in inputs.iter() {
        writeln!(file, "{}", input.display())?;
    }

    Ok(inputs)
}

#[derive(Debug)]
struct ControlResult<'a> {
    size: usize,
    features: BitSet<u64>,
    path: &'a Path,
}

fn parse_control_file<'a, I: Iterator<Item = IOResult<String>>>(
    lines: &mut I,
    inputs: &'a [PathBuf],
) -> Result<Vec<ControlResult<'a>>> {
    let mut results: Vec<_> = (0..inputs.len()).map(|_| None).collect();

    let mut state = None;

    for line in lines {
        let line = line?;
        let mut controls = line.split(' ');

        match controls.next() {
            Some("STARTED") => {
                let id: usize = controls.next().unwrap().parse()?;
                let size = controls.next().unwrap().parse()?;
                results[id] = Some(ControlResult {
                    size,
                    features: BitSet::default(),
                    path: &inputs[id],
                });
                state = Some(results[id].as_mut().unwrap());
            }
            Some("COV") => {
                // We only use features
                continue;
            }
            Some("FT") => {
                let res = state.as_mut().unwrap();
                for id in controls {
                    let id = id.parse()?;
                    res.features.insert(id);
                }
            }
            None => {
                continue;
            }
            _ => {
                return Err(anyhow!("invalid control"));
            }
        }
    }

    let mut results: Vec<_> = results.drain(..).filter_map(|r| r).collect();

    results.sort_by(|a, b| {
        let size_cmp = a.size.cmp(&b.size);
        if size_cmp == Ordering::Equal {
            a.features.len().cmp(&b.features.len())
        } else {
            size_cmp
        }
    });

    Ok(results)
}
