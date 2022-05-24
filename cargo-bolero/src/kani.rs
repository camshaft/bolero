use crate::{exec, test, Selection};
use anyhow::Result;
use std::process::Command;

pub(crate) fn test(selection: &Selection, test_args: &test::Args) -> Result<()> {
    let _ = selection;
    let _ = test_args;
    let mut cmd = Command::new("cargo");
    cmd.arg("kani")
        .arg("--harness")
        .arg(selection.test());

    exec(cmd)?;

    Ok(())
}
