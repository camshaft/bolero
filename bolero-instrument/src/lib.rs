#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg_attr(test, global_allocator)]
#[cfg(test)]
pub(crate) static GLOBAL_ALLOC: allocations::System = allocations::System::system();

mod histogram;

pub mod allocations;
pub mod cycles;
#[cfg(any(test, feature = "syscalls"))]
pub mod syscalls;
pub mod timing;

use core::fmt::Debug;

pub trait Instrument {
    type Measurement: Measurement<Record = Self::Record>;
    type Record;

    fn start(&mut self) -> Self::Measurement;

    fn record<Input: Debug>(&mut self, measurement: Self::Record, input: &Input);
}

pub trait Measurement {
    type Record;

    fn stop(self) -> Self::Record;
}

impl Instrument for () {
    type Measurement = ();
    type Record = ();

    fn start(&mut self) -> Self::Measurement {}

    fn record<Input: Debug>(&mut self, _measurement: Self::Measurement, _input: &Input) {}
}

impl Measurement for () {
    type Record = ();

    fn stop(self) -> Self::Record {}
}

impl<A: Instrument> Instrument for (A,) {
    type Measurement = (A::Measurement,);
    type Record = (A::Record,);

    fn start(&mut self) -> Self::Measurement {
        let a = self.0.start();
        (a,)
    }

    fn record<Input: Debug>(&mut self, record: Self::Record, input: &Input) {
        self.0.record(record.0, input);
    }
}

impl<A: Measurement> Measurement for (A,) {
    type Record = (A::Record,);

    fn stop(self) -> Self::Record {
        let a = self.0.stop();
        (a,)
    }
}

impl<A: Instrument, B: Instrument> Instrument for (A, B) {
    type Measurement = (A::Measurement, B::Measurement);
    type Record = (A::Record, B::Record);

    fn start(&mut self) -> Self::Measurement {
        let a = self.0.start();
        let b = self.1.start();
        (a, b)
    }

    fn record<Input: Debug>(&mut self, record: Self::Record, input: &Input) {
        self.1.record(record.1, input);
        self.0.record(record.0, input);
    }
}

impl<A: Measurement, B: Measurement> Measurement for (A, B) {
    type Record = (A::Record, B::Record);

    fn stop(self) -> Self::Record {
        let b = self.1.stop();
        let a = self.0.stop();
        (a, b)
    }
}

impl<A: Instrument, B: Instrument, C: Instrument> Instrument for (A, B, C) {
    type Measurement = (A::Measurement, B::Measurement, C::Measurement);
    type Record = (A::Record, B::Record, C::Record);

    fn start(&mut self) -> Self::Measurement {
        let a = self.0.start();
        let b = self.1.start();
        let c = self.2.start();
        (a, b, c)
    }

    fn record<Input: Debug>(&mut self, record: Self::Record, input: &Input) {
        self.2.record(record.2, input);
        self.1.record(record.1, input);
        self.0.record(record.0, input);
    }
}

impl<A: Measurement, B: Measurement, C: Measurement> Measurement for (A, B, C) {
    type Record = (A::Record, B::Record, C::Record);

    fn stop(self) -> Self::Record {
        let c = self.2.stop();
        let b = self.1.stop();
        let a = self.0.stop();
        (a, b, c)
    }
}
