cfg_if::cfg_if! {
    if #[cfg(fuzzing_libfuzzer)] {
        use bolero_libfuzzer::fuzz;
    } else if #[cfg(fuzzing_afl)] {
        use bolero_afl::fuzz;
    } else if #[cfg(fuzzing_honggfuzz)] {
        use bolero_honggfuzz::fuzz;
    } else {
        fn fuzz(_testfn: fn(&[u8])) {
            panic!("test not compiled with a valid fuzzer")
        }

    }
}

#[allow(dead_code)]
pub unsafe fn exec(_file: &str, testfn: fn(&[u8])) {
    if std::env::var("BOLERO_INFO").is_ok() {
        print!("{}", std::env::args().nth(0).unwrap());
        return;
    }

    fuzz(testfn)
}
