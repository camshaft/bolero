fn main() {
    if cfg!(target_os = "macos") {
        let mut build = cc::Build::new();
        build.file("src/dtrace_provider.c");
        build.compile("bolero_instrument_dtrace_provider.a");
    }
}
