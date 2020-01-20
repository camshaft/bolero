use crate::{
    histogram::{Histogram, HistogramUnit},
    Instrument, Measurement,
};

#[derive(Clone, Debug)]
pub struct CyclesInstrument {
    stats: Histogram<CyclesUnit>,
}

impl CyclesInstrument {
    pub fn new(max_cycles: u64) -> Self {
        let stats = Histogram::new(max_cycles);
        Self { stats }
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    #[inline(always)]
    fn cycles() -> u64 {
        0
    }

    #[cfg(target_arch = "x86_64")]
    #[inline(always)]
    fn cycles() -> u64 {
        unsafe {
            core::arch::x86_64::_mm_lfence();
            let count = core::arch::x86_64::_rdtsc();
            core::arch::x86_64::_mm_lfence();
            count
        }
    }

    #[cfg(target_arch = "x86")]
    #[inline(always)]
    fn cycles() -> u64 {
        unsafe {
            core::arch::x86::_mm_lfence();
            let count = core::arch::x86::_rdtsc();
            core::arch::x86::_mm_lfence();
            count
        }
    }
}

impl Default for CyclesInstrument {
    fn default() -> Self {
        // TODO figure out a good default
        Self::new(1_000_000_000)
    }
}

#[derive(Debug)]
pub struct CycleMeasurement(u64);

impl Measurement for CycleMeasurement {
    type Record = u64;

    fn stop(self) -> Self::Record {
        let end = CyclesInstrument::cycles();
        end - self.0
    }
}

impl Instrument for CyclesInstrument {
    type Measurement = CycleMeasurement;
    type Record = u64;

    #[inline(always)]
    fn start(&mut self) -> Self::Measurement {
        CycleMeasurement(Self::cycles())
    }

    #[inline(always)]
    fn record<Input: core::fmt::Debug>(&mut self, diff: Self::Record, input: &Input) {
        let _ = self.stats.record_input(diff, input);
    }
}

#[derive(Clone, Copy, Debug)]
struct CyclesUnit;

impl HistogramUnit for CyclesUnit {
    type Float = f64;
    type Whole = u64;

    fn name() -> &'static str {
        "Cycles"
    }

    fn display(value: u64) -> Self::Whole {
        value
    }

    fn display_float(value: f64) -> Self::Float {
        value
    }
}

#[test]
fn cycles_test() {
    use rand::Rng;

    let count = rand::thread_rng().gen();

    let mut instrument = CyclesInstrument::default();
    for _check in 0..1000 {
        let measurement = instrument.start();
        let mut value = 0u8;
        for i in 0u8..count {
            value = value.wrapping_add(i);
        }
        let record = measurement.stop();
        instrument.record(record, &count);
    }
    println!("{:#?}", instrument);

    // use plotters::prelude::*;
    // let b = BitMapBackend::new("graphs/cycles.png", (1024, 768)).into_drawing_area();
    // b.fill(&WHITE).unwrap();
    // instrument.stats.draw_chart("Cycles", b).unwrap();
}
