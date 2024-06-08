use crate::{exec, test, test_target::TestTarget, Selection};
use anyhow::Result;
use core::time::Duration;
use serde::Deserialize;
use std::{
    io::{BufRead, BufReader},
    process::{Child, Stdio},
    sync::mpsc,
    time::Instant,
};

const FLAGS: &[&str] = &["--cfg fuzzing_random"];

pub(crate) fn test(selection: &Selection, test_args: &test::Args) -> Result<()> {
    let test_target = selection.test_target(FLAGS, "random")?;

    let jobs = test_args.jobs.unwrap_or(1);

    if jobs > 1 {
        let (sender, recv) = mpsc::channel();
        for id in 0..jobs {
            let args = (id, sender.clone());
            let args = Some(args);
            worker(&test_target, test_args, args)?;
        }

        let mut total = TotalStats::default();
        let mut remaining = 0;
        loop {
            match recv.recv_timeout(Duration::from_secs(1)) {
                Ok(Message::Shutdown { success: false }) => {
                    return Err(anyhow::anyhow!("worker exited with failure"));
                }
                Ok(Message::Shutdown { success: true }) => {
                    remaining -= 1;
                    if remaining <= 0 {
                        break;
                    }
                }
                Ok(Message::Stats(stats)) => {
                    total.add(stats);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    continue;
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    break;
                }
            }
            total.print(false);
        }

        total.print(true);
        drop(recv);
    } else {
        worker(&test_target, test_args, None)?;
    }

    Ok(())
}

fn worker(
    test_target: &TestTarget,
    test_args: &test::Args,
    worker_args: Option<(usize, mpsc::Sender<Message>)>,
) -> Result<()> {
    let mut cmd = test_target.command();

    macro_rules! optional_arg {
        ($arg:ident, $env:expr) => {
            if let Some(v) = test_args.$arg {
                cmd.env($env, v.to_string());
            }
        };
    }

    optional_arg!(seed, "BOLERO_RANDOM_SEED");
    optional_arg!(runs, "BOLERO_RANDOM_ITERATIONS");
    optional_arg!(max_input_length, "BOLERO_RANDOM_MAX_LEN");
    if let Some(t) = test_args.time {
        cmd.env("BOLERO_RANDOM_TEST_TIME_MS", t.as_millis().to_string());
    }
    // TODO implement other options
    /*
    /// Maximum amount of time to run a test target before
    /// failing
    #[structopt(short, long, default_value = "10s")]
    pub timeout: Duration,
    */

    let Some((worker, chan)) = worker_args else {
        exec(cmd)?;
        return Ok(());
    };

    cmd.env("BOLERO_RANDOM_WORKER", worker.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn()?;

    handle_worker_out(worker, child.stdout.take().unwrap(), true, chan.clone());
    handle_worker_out(worker, child.stderr.take().unwrap(), false, chan.clone());
    handle_worker_status(child, chan);

    Ok(())
}

fn handle_worker_out<B: 'static + Send + std::io::Read>(
    worker: usize,
    out: B,
    is_stdout: bool,
    chan: mpsc::Sender<Message>,
) {
    let mut out = BufReader::new(out);
    std::thread::spawn(move || {
        let mut line = String::new();
        loop {
            line.clear();
            match out.read_line(&mut line) {
                Ok(0) => break,
                Ok(_len) => {
                    if let Some(stats) = line
                        .strip_prefix("[bolero-report]")
                        .and_then(|v| serde_json::from_str(v).ok())
                    {
                        if chan.send(Message::Stats(stats)).is_err() {
                            break;
                        }
                        continue;
                    }

                    // filter out libtest noise
                    if is_stdout
                        && (line == "\n"
                            || line == ".\n"
                            || line == "running 1 test\n"
                            || line.starts_with("test result: "))
                    {
                        continue;
                    }

                    // send everything to stderr so it formats better between the workers
                    eprint!("[worker {worker:>3}] {line}");
                }
                Err(_) => {
                    break;
                }
            }
        }
    });
}

fn handle_worker_status(mut child: Child, chan: mpsc::Sender<Message>) {
    std::thread::spawn(move || {
        let success = child.wait().map_or(false, |status| status.success());

        let _ = chan.send(Message::Shutdown { success });
    });
}

#[derive(Debug)]
enum Message {
    Stats(Stats),
    Shutdown { success: bool },
}

#[derive(Debug, Deserialize)]
struct Stats {
    iterations: u64,
    valid: u64,
}

#[derive(Debug)]
struct TotalStats {
    total_runs: u64,
    window_runs: u64,
    total_valid: u64,
    window_valid: u64,
    last_print: Instant,
    target_print: Instant,
}

impl Default for TotalStats {
    fn default() -> Self {
        let now = Instant::now();
        Self {
            total_runs: 0,
            window_runs: 0,
            total_valid: 0,
            window_valid: 0,
            last_print: now,
            target_print: now + Duration::from_secs(1),
        }
    }
}

impl TotalStats {
    fn add(&mut self, stats: Stats) {
        self.total_runs += stats.iterations;
        self.window_runs += stats.iterations;
        self.total_valid += stats.valid;
        self.window_valid += stats.valid;
    }

    fn print(&mut self, forced: bool) {
        let now = Instant::now();
        if !forced && self.target_print > now {
            return;
        }
        let elapsed = now - self.last_print;
        self.last_print = now;
        self.target_print = now + Duration::from_secs(1);

        let prefix = "[supervisor] ";
        let ips = (self.window_runs as f32 / elapsed.as_secs_f32()).round();

        // only report valid percentage if we drop below 100%
        if self.total_runs == self.total_valid {
            println!("{prefix}#{}\titerations/s: {ips}", self.total_runs);
        } else {
            let total_perc = self.total_valid as f32 / self.total_runs as f32 * 100.0;
            let window_perc = self.window_valid as f32 / self.window_runs as f32 * 100.0;
            let vps = (self.window_valid as f32 / elapsed.as_secs_f32()).round();
            println!(
                "{prefix}#{}\titerations/s: {ips} valid: {} ({:.2}%) valid/s: {vps} ({:.2}%)",
                self.total_runs, self.total_valid, total_perc, window_perc,
            );
        }

        self.window_runs = 0;
        self.window_valid = 0;
    }
}
