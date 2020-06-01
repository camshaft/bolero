use crate::{test_target::TestTarget, FuzzArgs, ReduceArgs, Selection};
use anyhow::Result;
use bolero_ravel::cli::{
    FuzzArgs as RavelFuzzArgs, ReduceArgs as RavelReduceArgs, TestTarget as RavelTestTarget,
    BUILD_FLAGS,
};

impl Into<RavelTestTarget> for TestTarget {
    fn into(self) -> RavelTestTarget {
        RavelTestTarget {
            work_dir: self.workdir(),
            args: self.command_args().map(String::from).collect(),
            env: self
                .command_env()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            exe: self.exe.into(),
            package_name: self.package_name,
            test_name: self.test_name,
        }
    }
}

impl Into<RavelFuzzArgs> for &FuzzArgs {
    fn into(self) -> RavelFuzzArgs {
        // TODO
        RavelFuzzArgs {}
    }
}

impl Into<RavelReduceArgs> for &ReduceArgs {
    fn into(self) -> RavelReduceArgs {
        // TODO
        RavelReduceArgs {}
    }
}

pub(crate) fn fuzz(selection: &Selection, fuzz: &FuzzArgs) -> Result<()> {
    let test_target = selection.test_target(BUILD_FLAGS, "ravel")?;
    bolero_ravel::cli::fuzz(test_target.into(), fuzz.into())?;
    Ok(())
}

pub(crate) fn reduce(selection: &Selection, reduce: &ReduceArgs) -> Result<()> {
    let test_target = selection.test_target(BUILD_FLAGS, "ravel")?;
    bolero_ravel::cli::reduce(test_target.into(), reduce.into())?;
    Ok(())
}
