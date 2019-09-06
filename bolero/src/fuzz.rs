use crate::workdir;

#[allow(dead_code)]
pub unsafe fn exec(file: &str) {
    if std::env::var("BOLERO_READ_WORKDIR").is_ok() {
        print!("{}", workdir(file));
        return;
    }

    let fuzzer = std::env::var("BOLERO_FUZZER").expect("BOLERO_FUZZER is not set");

    match fuzzer.as_ref() {
        "libfuzzer" => bolero_libfuzzer::exec(std::env::args()),
        _ => panic!("unknown fuzzer {:?}", fuzzer),
    }
}
