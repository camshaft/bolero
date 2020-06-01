use super::{process::exec, test_target::TestTarget};
use anyhow::Error;

#[derive(Debug)]
pub struct FuzzArgs {
    // TODO
}

pub fn fuzz(test_target: TestTarget, _args: FuzzArgs) -> Result<(), Error> {
    exec(test_target.command())?;
    Ok(())
}
