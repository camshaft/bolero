use crate::{__BOLERO__test, workdir};
use libtest_mimic::{run_tests, Arguments, Outcome, Test};
use std::{
    env, fs,
    panic::{self, catch_unwind},
    path::Path,
    sync::{Arc, Mutex},
};

lazy_static::lazy_static! {
    static ref ERROR: Arc<Mutex<String>> = Arc::new(Mutex::new("unknown failure".to_owned()));
}

#[allow(dead_code)]
pub unsafe fn exec(file: &str) {
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

    let workdir = workdir(file);

    let entries = fs::read_dir(Path::new(&workdir).join("corpus"))
        .expect("missing test corpus")
        .map(|item| item.unwrap().path())
        .filter(|path| path.is_file())
        .map(|path| Test {
            name: path.to_str().unwrap().to_owned(),
            kind: "".into(),
            is_ignored: false,
            is_bench: false,
            data: fs::read(&path).unwrap(),
        })
        .collect();

    let exec = move |data: &[u8]| {
        catch_unwind(|| __BOLERO__test(data)).map_err(|_err| ERROR.lock().unwrap().clone())
    };

    run_tests(&Arguments::from_args(), entries, |test| {
        if let Err(err) = exec(&test.data) {
            Outcome::Failed { msg: Some(err) }
        } else {
            Outcome::Passed
        }
    })
    .exit();
}
