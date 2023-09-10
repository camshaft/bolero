use crate::{env, Result};
use xshell::{cmd, Shell};

pub fn test() -> Result {
    Test {}.run()?;

    Ok(())
}

struct Test {}

impl Test {
    fn run(&self) -> Result {
        let sh = Shell::new()?;
        sh.change_dir(env::examples());

        env::configure_toolchain(&sh);

        for example in std::fs::read_dir(sh.current_dir())?.flatten() {
            if !example.path().is_dir() {
                continue;
            }

            let _dir = sh.push_dir(example.path());

            // make sure this is up-to-date
            let _ = sh.remove_path("Cargo.lock");

            cmd!(sh, "cargo test").run()?;

            // make sure bolero still works with a single thread
            cmd!(sh, "cargo test -- --test-threads=1").run()?;
        }

        Ok(())
    }
}
