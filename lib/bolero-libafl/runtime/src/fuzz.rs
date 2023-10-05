//! A libfuzzer-like fuzzer with llmp-multithreading support and restarts
//! The example harness is built for libpng.
use core::{ffi::c_void, time::Duration};
use libafl::{
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus},
    events::{setup_restarting_mgr_std, simple::SimpleEventManager, EventConfig, EventRestarter},
    executors::{inprocess::InProcessExecutor, ExitKind, TimeoutExecutor},
    feedback_or, feedback_or_fast,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput, HasTargetBytes},
    monitors::MultiMonitor,
    mutators::{
        scheduled::{havoc_mutations, tokens_mutations, StdScheduledMutator},
        token_mutations::Tokens,
    },
    observers::{HitcountsMapObserver, StdMapObserver, TimeObserver},
    prelude::*,
    schedulers::{
        powersched::PowerSchedule, IndexesLenTimeMinimizerScheduler, StdWeightedScheduler,
    },
    stages::{calibrate::CalibrationStage, power::StdPowerMutationalStage},
    state::{HasCorpus, HasMetadata, StdState},
    Error,
};
use libafl_bolts::{
    current_nanos,
    rands::StdRand,
    tuples::{tuple_list, Merge},
    AsSlice,
};
use libafl_targets::{EDGES_MAP, MAX_EDGES_NUM};
use std::path::PathBuf;

#[derive(Clone, Copy, Debug)]
pub enum Outcome {
    Ok,
    Invalid,
    Crash,
}

type RunOnce = extern "C" fn(*const u8, usize, *mut c_void) -> u8;

/// Coverage map with explicit assignments due to the lack of instrumentation
static mut RETURN_SIGNALS: [u8; 8] = [0; 8];
static mut RETURN_SIGNALS_PTR: *mut u8 = unsafe { RETURN_SIGNALS.as_mut_ptr() };

/// Assign a signal to the signals map
fn was_valid_input() {
    unsafe { core::ptr::write(RETURN_SIGNALS_PTR, 1) };
}

/// The main fn, `no_mangle` as it is a C main
#[cfg_attr(not(test), no_mangle)]
#[cfg_attr(test, allow(dead_code))]
pub extern "C" fn bolero_libafl_runtime_start(run_once: RunOnce, ctx: *mut c_void) {
    // Registry the metadata types used in this fuzzer
    // Needed only on no_std
    // unsafe { RegistryBuilder::register::<Tokens>(); }

    let handle_input = move |slice: &[u8]| -> Outcome {
        match run_once(slice.as_ptr(), slice.len(), ctx) {
            0 => Outcome::Ok,
            1 => Outcome::Invalid,
            2 => Outcome::Crash,
            _ => panic!("unexpected return value"),
        }
    };

    println!("RUNNING FUZZER");

    BoleroFuzzer::default()
        .run(handle_input)
        .expect("An error occurred while fuzzing");
}

pub struct BoleroFuzzer {
    corpus_dirs: Vec<PathBuf>,
    crashes_dir: PathBuf,
    broker_port: u16,
}

impl Default for BoleroFuzzer {
    fn default() -> Self {
        // TODO load from env
        let corpus_dirs = vec![PathBuf::from("./corpus")];
        let crashes_dir = PathBuf::from("./crashes");
        let broker_port = 1337;
        Self {
            corpus_dirs,
            crashes_dir,
            broker_port,
        }
    }
}

impl BoleroFuzzer {
    pub fn run<F: FnMut(&[u8]) -> Outcome>(self, mut handle_input: F) -> Result<(), Error> {
        let corpus_dirs = &self.corpus_dirs;
        let objective_dir = &self.crashes_dir;
        let broker_port = self.broker_port;

        // The wrapped harness function, mapping outcomes to exit kinds
        let mut harness = |input: &BytesInput| {
            let target = input.target_bytes();
            let buf = target.as_slice();
            match handle_input(buf) {
                Outcome::Ok => {
                    was_valid_input();
                    ExitKind::Ok
                }
                Outcome::Invalid => ExitKind::Ok,
                Outcome::Crash => ExitKind::Crash,
            }
        };

        // Create an observation channel using the coverage map
        let edges_observer = unsafe {
            HitcountsMapObserver::new(StdMapObserver::from_mut_ptr(
                "edges",
                EDGES_MAP.as_mut_ptr(),
                MAX_EDGES_NUM,
            ))
        };

        let edges_feedback = MaxMapFeedback::tracking(&edges_observer, true, false);

        let edges_calibration = CalibrationStage::new(&edges_feedback);

        // Create an observation channel using the signals map
        let return_observer = unsafe {
            StdMapObserver::from_mut_ptr("generator", RETURN_SIGNALS_PTR, RETURN_SIGNALS.len())
        };

        // Feedback to rate the interestingness of an input
        let mut return_feedback = MaxMapFeedback::new(&return_observer);

        let time_observer = TimeObserver::new("time");

        let time_feedback = TimeFeedback::with_observer(&time_observer);

        let mut feedback = feedback_or!(
            // New maximization map feedback linked to the edges observer and the feedback state
            edges_feedback,
            return_feedback,
            time_feedback
        );

        let observer = tuple_list!(edges_observer, return_observer, time_observer);

        // A feedback to choose if an input is a solution or not
        let mut objective = CrashFeedback::new();

        // create a State from scratch
        let mut state = StdState::new(
            // RNG
            StdRand::with_seed(current_nanos()),
            // Corpus that will be evolved, we keep it in memory for performance
            InMemoryCorpus::new(),
            // Corpus in which we store solutions (crashes in this example),
            // on disk so the user can get them after stopping the fuzzer
            OnDiskCorpus::new(objective_dir)?,
            // States of the feedbacks.
            // The feedbacks can report the data that should persist in the State.
            &mut feedback,
            // Same for objective feedbacks
            &mut objective,
        )?;

        let monitor = SimpleMonitor::with_user_monitor(
            |s| {
                println!("{s}");
            },
            true,
        );

        let mut manager = SimpleEventManager::new(monitor);

        let scheduler = QueueScheduler::new();

        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        // Create the executor for an in-process function with one observer for edge coverage and one for the execution time
        let mut executor = InProcessExecutor::new(
            &mut harness,
            observer,
            &mut fuzzer,
            &mut state,
            &mut manager,
        )?;
        //let mut executor = TimeoutExecutor::new(executor, Duration::new(10, 0));

        // In case the corpus is empty (on first run), reset
        if state.must_load_initial_inputs() {
            let _ =
                state.load_initial_inputs(&mut fuzzer, &mut executor, &mut manager, corpus_dirs);

            if state.corpus().is_empty() {
                // Generator of printable bytearrays of max size 32
                let mut generator = RandPrintablesGenerator::new(32);

                state
                    .generate_initial_inputs(
                        &mut fuzzer,
                        &mut executor,
                        &mut generator,
                        &mut manager,
                        8,
                    )
                    .expect("Failed to generate the initial corpus");
            }

            println!("We imported {} inputs from disk.", state.corpus().count());
        }

        let mutator = StdScheduledMutator::new(havoc_mutations());
        let power = StdMutationalStage::new(mutator);

        let mut stages = tuple_list!(edges_calibration, power);

        // This fuzzer restarts after 1 mio `fuzz_one` executions.
        // Each fuzz_one will internally do many executions of the target.
        // If your target is very instable, setting a low count here may help.
        // However, you will lose a lot of performance that way.
        let iters = 1_000_000;
        fuzzer.fuzz_loop_for(&mut stages, &mut executor, &mut state, &mut manager, iters)?;

        // It's important, that we store the state before restarting!
        // Else, the parent will not respawn a new child and quit.
        // manager.on_restart(&mut state)?;

        Ok(())
    }
}
