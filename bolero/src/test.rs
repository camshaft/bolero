use crate::testname;
use libtest_mimic::{run_tests, Arguments, Outcome, Test};
use std::{
    env, fs,
    panic::{self, catch_unwind, AssertUnwindSafe},
    sync::{Arc, Mutex},
};

lazy_static::lazy_static! {
    static ref ERROR: Arc<Mutex<String>> = Arc::new(Mutex::new("unknown failure".to_owned()));
}

#[allow(dead_code)]
pub unsafe fn exec(file: &str, testfn: fn(&[u8])) {
    let print_backtrace = env::var("RUST_BACKTRACE")
        .ok()
        .map(|v| v == "1")
        .unwrap_or(false);

    let panic_error = ERROR.clone();
    panic::set_hook(Box::new(move |reason| {
        let mut message = format!("test {}\n", reason);
        if print_backtrace {
            let backtrace = backtrace::Backtrace::new();
            message.push_str(&format!("{:?}", backtrace));
        } else {
            message.push_str(
                "note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace.",
            );
        }
        *panic_error.lock().unwrap() = message;
    }));

    // tests are executed in the crate root
    let mut workdir = std::env::current_dir().unwrap();
    workdir.push("tests");
    workdir.push(testname(file));

    let entries = fs::read_dir(workdir.join("corpus"))
        .expect("missing test corpus")
        .map(|item| item.unwrap().path())
        .filter(|path| path.is_file())
        .filter(|path| !path.file_name().unwrap().to_str().unwrap().starts_with('.'))
        .map(|path| Test {
            name: format!("corpus/{}", path.file_stem().unwrap().to_str().unwrap()),
            kind: "".into(),
            is_ignored: false,
            is_bench: false,
            data: fs::read(&path).unwrap(),
        })
        .collect();

    run_tests(&Arguments::from_args(), entries, move |test| {
        let result = catch_unwind(AssertUnwindSafe(|| testfn(&test.data)));

        if result.is_err() {
            Outcome::Failed {
                msg: Some(ERROR.lock().unwrap().to_string()),
            }
        } else {
            Outcome::Passed
        }
    })
    .exit();
}
