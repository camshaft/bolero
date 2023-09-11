use crate::{env, Result};
use xshell::{cmd, Shell};

pub fn test() -> Result {
    let rust_version = env::rustc();

    let use_stable = rust_version.map_or(false, |v| v.major > 1 && v.minor <= 65);

    Test { use_stable }.run()?;

    Ok(())
}

struct Test {
    use_stable: bool,
}

impl Test {
    fn run(&self) -> Result {
        let sh = Shell::new()?;
        sh.change_dir(env::bins());

        // make sure this is up-to-date
        let _ = sh.remove_path("Cargo.lock");

        let toolchain = &if self.use_stable {
            vec!["+stable"]
        } else {
            vec![]
        };

        cmd!(sh, "cargo {toolchain...} test").run()?;
        cmd!(sh, "cargo {toolchain...} build").run()?;

        Ok(())
    }
}
