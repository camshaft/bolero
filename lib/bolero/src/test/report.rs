#![cfg_attr(not(fuzzing_random), allow(dead_code))]

use core::fmt;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

pub struct Report {
    stats: Stats,
    worker: Option<usize>,
    should_print: Arc<AtomicBool>,
}

impl Default for Report {
    fn default() -> Self {
        let worker = std::env::var("BOLERO_RANDOM_WORKER")
            .ok()
            .and_then(|v| v.parse().ok());
        Self {
            worker,
            stats: Default::default(),
            should_print: Default::default(),
        }
    }
}

impl Report {
    pub fn spawn_timer(&self) {
        let should_print = self.should_print.clone();
        let duration = if self.worker.is_some() {
            Duration::from_millis(250)
        } else {
            Duration::from_secs(1)
        };
        std::thread::spawn(move || {
            while Arc::strong_count(&should_print) > 1 {
                std::thread::sleep(duration);
                should_print.store(true, Ordering::Relaxed);
            }
        });
    }

    #[inline]
    pub fn on_result(&mut self, is_valid: bool) {
        self.stats.window_runs += 1;
        if is_valid {
            self.stats.window_valid += 1;
        }

        if !self.should_print.swap(false, Ordering::Relaxed) {
            return;
        }

        self.stats.total_runs += self.stats.window_runs;
        self.stats.total_valid += self.stats.window_valid;

        if self.worker.is_some() {
            self.stats.print_worker();
        } else {
            self.stats.print();
        };

        self.stats.window_runs = 0;
        self.stats.window_valid = 0;
    }

    pub fn on_estimate(&mut self, estimate: f64) {
        self.stats.estimate = Some(estimate);
    }
}

#[derive(Default)]
struct Stats {
    total_runs: u64,
    window_runs: u64,
    total_valid: u64,
    window_valid: u64,
    estimate: Option<f64>,
}

impl Stats {
    fn print_worker(&self) {
        println!(
            "[bolero-report]{{\"iterations\":{},\"valid\":{},\"estimate\":{}}}",
            self.window_runs,
            self.window_valid,
            self.estimate.unwrap_or(0.0),
        );
    }

    fn print(&self) {
        // only report valid percentage if we drop below 100%
        struct Estimate<'a>(&'a Stats);

        impl fmt::Display for Estimate<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self.0.estimate {
                    Some(estimate) => {
                        let percent = self.0.total_runs as f64 / estimate * 100.0;

                        let remaining = estimate - self.0.total_runs as f64;
                        let rate = self.0.window_runs as f64;

                        let time_remaining =
                            PrintRemaining(core::time::Duration::from_secs_f64(remaining / rate));

                        if (0.001..99.999).contains(&percent) {
                            write!(f, "\tstate space estimate: {estimate} ({percent:.03}%, {time_remaining})",)
                        } else {
                            write!(
                                f,
                                "\tstate space estimate: {estimate} ({percent}%, {time_remaining})",
                            )
                        }
                    }
                    None => Ok(()),
                }
            }
        }

        let estimate = Estimate(self);

        if self.total_runs == self.total_valid {
            println!(
                "#{}\titerations/s: {}{estimate}",
                self.total_runs, self.window_runs
            );
        } else {
            let total_perc = self.total_valid as f32 / self.total_runs as f32 * 100.0;
            let window_perc = self.window_valid as f32 / self.window_runs as f32 * 100.0;
            println!(
                "#{}\titerations/s: {}{estimate} valid: {} ({:.2}%) valid/s: {} ({:.2}%)",
                self.total_runs,
                self.window_runs,
                self.total_valid,
                total_perc,
                self.window_valid,
                window_perc,
            );
        }
    }
}

struct PrintRemaining(core::time::Duration);

impl fmt::Display for PrintRemaining {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let duration = self.0;

        fn split(v: u64, by: u64) -> (u64, u64) {
            (v / by, v % by)
        }

        let state = duration.as_secs();
        let (state, secs) = split(state, 60);
        let (state, mins) = split(state, 60);
        let (state, hours) = split(state, 24);
        let (years, days) = split(state, 360);

        if years > 0 {
            write!(f, "{years} years")
        } else if days > 0 {
            write!(f, "{days} days")
        } else if hours > 0 {
            write!(f, "{hours}h{mins:02}m{secs:02}s")
        } else if mins > 0 {
            write!(f, "{mins:02}m{secs:02}s")
        } else {
            write!(f, "{secs:02}s")
        }
    }
}
