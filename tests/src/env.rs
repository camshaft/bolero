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

pub fn rustc() -> Rustc {
    if let Ok(rustc) = std::env::var("TARGET_RUSTC") {
        rustc_version::Version::parse(&rustc).unwrap()
    } else {
        rustc_version::version().unwrap()
    }
}

pub fn configure_toolchain(sh: &xshell::Shell) {
    if let Ok(rustc) = std::env::var("TARGET_RUSTC") {
        xshell::cmd!(sh, "rustup override set {rustc}")
            .run()
            .unwrap();
    }
}
