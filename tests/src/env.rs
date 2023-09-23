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
