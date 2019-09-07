use crate::workdir;

cfg_if::cfg_if! {
    if #[cfg(fuzzing_libfuzzer)] {
        use bolero_libfuzzer::fuzz;
    } else if #[cfg(fuzzing_afl)] {
        use bolero_afl::fuzz;
    } else {
        fn fuzz() {
            panic!("test not compiled with a valid fuzzer")
        }

    }
}

#[allow(dead_code)]
pub unsafe fn exec(file: &str) {
    if std::env::var("BOLERO_INFO").is_ok() {
        println!("{}", std::env::args().nth(0).unwrap());
        println!("{}", workdir(file));
        return;
    }

    fuzz()
}
