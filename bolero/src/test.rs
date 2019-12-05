use bolero_generator::driver::DriverMode;
use libtest_mimic::{run_tests, Arguments, FormatSetting, Outcome, Test};
use std::{
    env, fs,
    panic::{self, catch_unwind, AssertUnwindSafe, RefUnwindSafe},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

lazy_static::lazy_static! {
    static ref ERROR: Arc<Mutex<String>> = Arc::new(Mutex::new("unknown failure".to_owned()));
}

// `run_tests` only accepts `Fn` instead of `FnMut`
// convert the function to a dynamic FnMut and drop the lifetime
static mut TESTFN: Option<&mut dyn FnMut(&[u8], Option<DriverMode>) -> bool> = None;

#[doc(hidden)]
#[allow(dead_code)]
pub unsafe fn exec<F: FnMut(&[u8], Option<DriverMode>) -> bool>(
    manifest_dir: &str,
    file: &str,
    testfn: &mut F,
) -> !
where
    F: RefUnwindSafe,
{
    TESTFN = Some(std::mem::transmute(
        testfn as &mut dyn FnMut(&[u8], Option<DriverMode>) -> bool,
    ));

    let fuzz_target = resolve_fuzz_target_path(manifest_dir, file);
    let corpus_dir = resolve_corpus_dir(fuzz_target);

    exec_tests(corpus_dir);
}

fn exec_tests(corpus_dir: PathBuf) -> ! {
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

    let mut entries = vec![];

    if let Ok(dir) = fs::read_dir(corpus_dir) {
        entries.extend(
            dir.map(|item| item.unwrap().path())
                .filter(|path| path.is_file())
                .filter(|path| !path.file_name().unwrap().to_str().unwrap().starts_with('.'))
                .map(|path| Test {
                    name: format!("corpus/{}", path.file_stem().unwrap().to_str().unwrap()),
                    kind: "".into(),
                    is_ignored: false,
                    is_bench: false,
                    data: (fs::read(&path).unwrap(), None),
                }),
        );
    };

    #[cfg(feature = "rand")]
    {
        use rand::{rngs::StdRng, Rng, SeedableRng};

        fn get_var<T: std::str::FromStr>(name: &str) -> Option<T> {
            env::var(name)
                .ok()
                .and_then(|value| value.parse::<T>().ok())
        }

        let iterations = get_var("BOLERO_RANDOM_ITERATIONS").unwrap_or(1000);
        let max_len = get_var("BOLERO_RANDOM_MAX_LEN").unwrap_or(4096);
        let seed = get_var("BOLERO_RANDOM_SEED").unwrap_or_else(|| rand::thread_rng().gen());
        let mut rng = StdRng::seed_from_u64(seed);

        let generate_test = |i| {
            use bolero_generator::prelude::*;
            let input = gen::<Vec<u8>>()
                .with()
                .len(0usize..max_len)
                .generate(&mut rng)
                .unwrap_or_default();

            Test {
                name: format!("randomized[seed={}, i={}]", seed, i),
                kind: "".into(),
                is_ignored: false,
                is_bench: false,
                data: (input, Some(DriverMode::Forced)),
            }
        };

        entries.extend((0..iterations).map(generate_test))
    }

    let mut arguments = Arguments::from_args();

    if arguments.format.is_none() {
        arguments.format = Some(FormatSetting::Terse);
    }

    run_tests(&arguments, entries, |test| {
        let result = catch_unwind(AssertUnwindSafe(|| unsafe {
            let (input, mode) = &test.data;
            (TESTFN.as_mut().expect("uninitialized test function"))(input, *mode)
        }));

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

fn resolve_fuzz_target_path(manifest_dir: &str, file: &str) -> PathBuf {
    let file = Path::new(file);

    if let Ok(file) = file.canonicalize() {
        return file;
    }

    Path::new(manifest_dir)
        .ancestors()
        .find_map(|ancestor| {
            let path = ancestor.join(file);
            if path.exists() {
                Some(path)
            } else {
                None
            }
        })
        .expect("Could not resolve fuzz target path")
}

fn resolve_corpus_dir(mut fuzz_target_path: PathBuf) -> PathBuf {
    fuzz_target_path.pop();
    fuzz_target_path.push("corpus");
    fuzz_target_path
}
