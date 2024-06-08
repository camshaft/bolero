#![cfg_attr(not(fuzzing_random), allow(dead_code))]

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

    pub fn on_result(&mut self, is_valid: bool) {
        self.stats.window_runs += 1;
        if is_valid {
            self.stats.window_valid += 1;
        }

        // check the should_print every 1024 runs
        if self.stats.window_runs % 1024 != 0 {
            return;
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
}

#[derive(Default)]
struct Stats {
    total_runs: u64,
    window_runs: u64,
    total_valid: u64,
    window_valid: u64,
}

impl Stats {
    fn print_worker(&self) {
        println!(
            "[bolero-report]{{\"iterations\":{},\"valid\":{}}}",
            self.window_runs, self.window_valid
        );
    }

    fn print(&self) {
        // only report valid percentage if we drop below 100%
        if self.total_runs == self.total_valid {
            println!("#{}\titerations/s: {}", self.total_runs, self.window_runs);
        } else {
            let total_perc = self.total_valid as f32 / self.total_runs as f32 * 100.0;
            let window_perc = self.window_valid as f32 / self.window_runs as f32 * 100.0;
            println!(
                "#{}\titerations/s: {} valid: {} ({:.2}%) valid/s: {} ({:.2}%)",
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
