use crate::Result;
use xshell::{cmd, Shell};

/// Where `test` writes the crate, in the repository's (gitignored) `target` directory.
const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../target/downstream");

/// A crate that depends on `bolero` and on a later `indexmap` 2.x than bolero's crates need.
///
/// Cargo selects one semver-compatible version of each crate for the whole dependency graph,
/// proc-macro dependencies included. An exact requirement in one of bolero's published crates,
/// such as the `indexmap = "=2.11.2"` that bolero-generator-derive 0.13.5 declares, therefore
/// applies to every crate that depends on bolero, and such a crate can't also depend on a later
/// release. The `bolero` path is relative to `DIR`.
const MANIFEST: &str = r#"[package]
name = "downstream"
version = "0.0.0"
edition = "2021"
publish = false

# keep this crate out of the repository's root workspace
[workspace]

[dependencies]
bolero = { path = "../../lib/bolero" }
indexmap = "2.12"
"#;

/// Checks that a crate that depends on bolero can also depend on `indexmap` 2.12.
///
/// It resolves the crate's dependencies and doesn't build them, so it runs the stable cargo on
/// every matrix row, as `env::regenerate_lockfile` does for the older toolchains.
pub fn test() -> Result {
    let sh = Shell::new()?;
    sh.change_dir(DIR);

    sh.create_dir("src")?;
    sh.write_file("src/lib.rs", "")?;
    sh.write_file("Cargo.toml", MANIFEST)?;

    cmd!(sh, "cargo +stable generate-lockfile").run()?;

    Ok(())
}
