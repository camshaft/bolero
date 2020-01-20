use crate::{Instrument, Measurement};
use fxhash::FxHashMap;

unsafe fn init() {
    #[cfg(all(not(test), target_os = "linux"))]
    libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0);
}

#[cfg(target_os = "linux")]
unsafe fn set_trace(enabled: bool) {
    /// Tuxcall is unused so we abuse it to start and stop the traces
    /// https://linux.die.net/man/2/tuxcall
    const SYSCALL_ID: i64 = libc::SYS_tuxcall;

    libc::syscall(SYSCALL_ID, if enabled { 1 } else { 0 });
}

#[cfg(target_os = "macos")]
extern "C" {
    #[link_name = "bolero_instrument_dtrace"]
    fn set_trace(enabled: bool);
}

unsafe fn start() {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    set_trace(true);
}

unsafe fn stop() {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    set_trace(false);
}

#[derive(Clone, Debug)]
pub struct SyscallParentInstrument {
    stats: FxHashMap<u64, u64>,
}

#[derive(Copy, Clone, Debug)]
pub struct SyscallInstrument(());

impl Default for SyscallInstrument {
    fn default() -> Self {
        Self::new()
    }
}

impl SyscallInstrument {
    pub fn new() -> Self {
        unsafe { init() }
        Self(())
    }
}

#[derive(Debug)]
pub struct SyscallMeasurement(());

#[derive(Debug)]
pub struct SyscallRecord(());

impl Measurement for SyscallMeasurement {
    type Record = SyscallRecord;

    fn stop(self) -> Self::Record {
        SyscallRecord(())
    }
}

impl Instrument for SyscallInstrument {
    type Measurement = SyscallMeasurement;
    type Record = SyscallRecord;

    fn start(&mut self) -> Self::Measurement {
        unsafe { start() };
        SyscallMeasurement(())
    }

    fn record<Input: core::fmt::Debug>(&mut self, _: Self::Record, _input: &Input) {
        unsafe { stop() }
    }
}

#[test]
fn syscall_test() {
    println!("NEW");
    let mut instrument = SyscallInstrument::new();
    println!("START");
    let measurement = instrument.start();
    println!("MIDDLE");
    let record = measurement.stop();
    instrument.record(record, &());
    println!("STOP");
}
