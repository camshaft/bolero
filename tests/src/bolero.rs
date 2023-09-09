use crate::{env, Result};
use xshell::{cmd, Shell};

pub fn test() -> Result {
    let rust_version = env::rustc();

    let supports_arbitrary = rust_version.major > 1 && rust_version.minor >= 63;

    Test { supports_arbitrary }.run()?;

    Ok(())
}

struct Test {
    supports_arbitrary: bool,
}

impl Test {
    fn run(&self) -> Result {
        let sh = Shell::new()?;
        sh.change_dir(env::libs());

        env::configure_toolchain(&sh);

        // make sure this is up-to-date
        let _ = sh.remove_path("Cargo.lock");

        cmd!(sh, "cargo test").run()?;

        // if the rust version supports arbitrary, then use it
        if self.supports_arbitrary {
            cmd!(sh, "cargo test --features arbitrary").run()?;
        }

        for sub_project in ["bolero-generator", "bolero-engine", "bolero"] {
            cmd!(
                sh,
                "cargo build --manifest-path {sub_project}/Cargo.toml --no-default-features"
            )
            .run()?;

            if sub_project != "bolero-engine" {
                cmd!(
                    sh,
                    "cargo build --manifest-path {sub_project}/Cargo.toml --no-default-features --features alloc"
                )
                .run()?;
            }
        }

        Ok(())
    }
}
