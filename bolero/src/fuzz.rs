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
pub unsafe fn exec(_file: &str) {
    if std::env::var("BOLERO_INFO").is_ok() {
        print!("{}", std::env::args().nth(0).unwrap());
        return;
    }

    fuzz()
}
