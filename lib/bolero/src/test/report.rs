#![cfg_attr(not(fuzzing_random), allow(dead_code))]

use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

#[derive(Default)]
pub struct Report {
    total_runs: u64,
    window_runs: u64,
    total_valid: u64,
    window_valid: u64,
    should_print: Arc<AtomicBool>,
}

impl Report {
    pub fn spawn_timer(&self) {
        let should_print = self.should_print.clone();
        std::thread::spawn(move || {
            while Arc::strong_count(&should_print) > 1 {
                std::thread::sleep(Duration::from_secs(1));
                should_print.store(true, Ordering::Relaxed);
            }
        });
    }

    pub fn on_result(&mut self, is_valid: bool) {
        self.window_runs += 1;
        if is_valid {
            self.window_valid += 1;
        }

        // check the should_print every 1024 runs
        if self.window_runs % 1024 != 0 {
            return;
        }

        if !self.should_print.swap(false, Ordering::Relaxed) {
            return;
        }

        self.total_runs += self.window_runs;
        self.total_valid += self.window_valid;

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

        self.window_runs = 0;
        self.window_valid = 0;
    }
}
