pub use rustc_version::Version as Rustc;

pub fn libs() -> &'static str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/../lib")
}

pub fn bins() -> &'static str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/../bin")
}

pub fn examples() -> &'static str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/../examples")
}

pub fn rustc() -> Option<Rustc> {
    if let Ok(rustc) = std::env::var("BOLERO_RUSTUP_TOOLCHAIN") {
        rustc_version::Version::parse(&rustc).ok()
    } else {
        rustc_version::version().ok()
    }
}

pub fn rustc_build() -> Option<String> {
    if let Some(rustc) = rustc() {
        Some(rustc.build.as_str().to_string())
    } else {
        std::env::var("BOLERO_RUSTUP_TOOLCHAIN").ok()
    }
}

pub fn configure_toolchain(sh: &xshell::Shell) {
    if let Ok(rustc) = std::env::var("BOLERO_RUSTUP_TOOLCHAIN") {
        sh.set_var("RUSTUP_TOOLCHAIN", rustc);
    }
    let _ = xshell::cmd!(sh, "rustc -vV").run();
}

/// Refresh the (gitignored) `Cargo.lock` in the current directory.
///
/// The MSRV-aware dependency resolver — which honors each crate's declared
/// `rust-version` and falls back to older, compatible dependency versions — only
/// exists in cargo 1.84+. When the matrix toolchain predates that, resolving fresh
/// pulls in the latest dependencies, which now require a newer rustc than our MSRV
/// and break the build. For those older toolchains we therefore generate the lock
/// with a modern cargo (installed as `stable`) and the fallback resolver, so the
/// older toolchain only has to *build* an already-MSRV-compatible lock. Newer
/// toolchains keep resolving fresh so they still exercise the latest dependencies.
pub fn regenerate_lockfile(sh: &xshell::Shell) -> crate::Result {
    let _ = sh.remove_path("Cargo.lock");

    let predates_msrv_resolver = rustc().map_or(false, |v| v.major == 1 && v.minor < 84);
    if predates_msrv_resolver {
        xshell::cmd!(sh, "cargo +stable generate-lockfile")
            .env("CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS", "fallback")
            .run()?;
    }

    Ok(())
}
