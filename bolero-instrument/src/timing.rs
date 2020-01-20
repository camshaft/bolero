use crate::{histogram::Histogram, Instrument, Measurement};
use core::time::Duration;
use quanta::Clock;

thread_local! {
    static CLOCK: Clock = Clock::new();
}

#[derive(Clone, Debug)]
pub struct TimingInstrument {
    stats: Histogram<Duration>,
}

impl TimingInstrument {
    pub fn new(max_duration: Duration) -> Self {
        let nanos = max_duration.as_nanos() as u64;
        let stats = Histogram::new(nanos);
        Self { stats }
    }
}

impl Default for TimingInstrument {
    fn default() -> Self {
        Self::new(Duration::from_secs(1))
    }
}

#[derive(Debug)]
pub struct TimingMeasurement(u64);

impl Measurement for TimingMeasurement {
    type Record = u64;

    fn stop(self) -> Self::Record {
        CLOCK.with(|clock| {
            let end = clock.end();
            clock.delta(self.0, end)
        })
    }
}

impl Instrument for TimingInstrument {
    type Measurement = TimingMeasurement;
    type Record = u64;

    fn start(&mut self) -> Self::Measurement {
        let start = CLOCK.with(|clock| clock.start());
        TimingMeasurement(start)
    }

    fn record<Input: core::fmt::Debug>(&mut self, record: Self::Record, input: &Input) {
        let _ = self.stats.record_input(record, input);
    }
}

#[test]
fn timing_test() {
    use rand::Rng;

    let mut instrument = TimingInstrument::default();
    for _check in 0..1000 {
        let measurement = instrument.start();
        let count: u8 = rand::thread_rng().gen();
        let mut value = 0u8;
        for i in 0u8..count {
            value = value.wrapping_add(i);
        }
        instrument.record(measurement.stop(), &count);
    }

    // use plotters::prelude::*;
    // let b = BitMapBackend::new("graphs/timing.png", (1024, 768)).into_drawing_area();
    // b.fill(&WHITE).unwrap();
    // instrument.stats.draw_chart("Timing", b).unwrap();
}
