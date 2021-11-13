use crate::{exec, test, Selection};
use anyhow::{anyhow, Result};
use bit_set::BitSet;
use core::cmp::Ordering;
use std::{
    fs,
    io::{BufRead, BufReader, Result as IOResult, Write},
    path::{Path, PathBuf},
    process::Command,
};

pub(crate) fn test(selection: &Selection, test_args: &test::Args) -> Result<()> {
    let _ = selection;
    let _ = test_args;
    let mut rmc_cmd = String::from("cargo rmc");
    rmc_cmd.push_str(" --function ");
    rmc_cmd.push_str(&selection.test());
    rmc_cmd.push_str(" --cbmc-args --object-bits 16");
    Command::new("sh")
          .env("RUSTFLAGS", "--cfg=fuzzing_rmc --cfg=fuzzing")
          .arg("-c")
          .arg(rmc_cmd)
          .spawn()
          .expect("failed to execute process");

    Ok(())
}
