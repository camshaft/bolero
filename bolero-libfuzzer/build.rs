extern crate cc;

fn main() {
    if std::env::var("CARGO_CFG_FUZZING_LIBFUZZER").is_ok() {
        let mut build = cc::Build::new();
        let sources = ::std::fs::read_dir("libfuzzer")
            .expect("listable source directory")
            .map(|de| de.expect("file in directory").path())
            .filter(|p| p.extension().map(|ext| ext == "cpp").unwrap_or(false))
            .filter(|p| {
                // We use FuzzerAPI instead
                p.file_stem()
                    .map(|name| name != "FuzzerMain")
                    .unwrap_or(false)
            });

        for source in sources {
            build.file(source.to_str().unwrap());
        }

        build.file("src/FuzzerAPI.cpp");
        build.flag("-std=c++11");
        build.flag("-fno-omit-frame-pointer");
        build.flag("-w");
        build.cpp(true);
        build.compile("libfuzzer.a");
    }
}
