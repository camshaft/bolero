fn main() {
    println!(
        "cargo:rustc-env=DEFAULT_TARGET={}",
        std::env::var("TARGET").unwrap()
    );
}
