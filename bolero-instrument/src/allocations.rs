use crate::{
    histogram::{ByteUnit, Histogram, HistogramUnit},
    Instrument, Measurement,
};
use core::{
    alloc::{GlobalAlloc, Layout},
    fmt,
    sync::atomic::{AtomicU64, Ordering},
};

pub struct InstrumentedAllocator<A> {
    inner: A,
    allocations: AtomicU64,
    allocated_bytes: AtomicU64,
    reallocations: AtomicU64,
    reallocated_bytes: AtomicU64,
}

#[cfg(feature = "std")]
pub type System = InstrumentedAllocator<std::alloc::System>;

#[cfg(feature = "std")]
impl System {
    pub const fn system() -> Self {
        Self::new(std::alloc::System)
    }
}

unsafe impl<A: GlobalAlloc> GlobalAlloc for InstrumentedAllocator<A> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = self.inner.alloc(layout);
        if !ptr.is_null() {
            self.allocations.fetch_add(1, Ordering::SeqCst);
            self.allocated_bytes
                .fetch_add(layout.size() as u64, Ordering::SeqCst);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.inner.dealloc(ptr, layout);
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = self.inner.alloc_zeroed(layout);
        if !ptr.is_null() {
            self.allocations.fetch_add(1, Ordering::SeqCst);
            self.allocated_bytes
                .fetch_add(layout.size() as u64, Ordering::SeqCst);
        }
        ptr
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let ptr = self.inner.realloc(ptr, layout, new_size);
        if !ptr.is_null() {
            self.reallocations.fetch_add(1, Ordering::SeqCst);
            self.reallocated_bytes
                .fetch_add(layout.size() as u64, Ordering::SeqCst);
        }
        ptr
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct AllocationRecord {
    allocations: u64,
    allocated_bytes: u64,
    reallocations: u64,
    reallocated_bytes: u64,
}

impl<A> InstrumentedAllocator<A> {
    pub const fn new(inner: A) -> Self {
        InstrumentedAllocator {
            inner,
            allocations: AtomicU64::new(0),
            allocated_bytes: AtomicU64::new(0),
            reallocations: AtomicU64::new(0),
            reallocated_bytes: AtomicU64::new(0),
        }
    }

    pub fn take(&self) -> AllocationRecord {
        let allocations = self.allocations.swap(0, Ordering::SeqCst);
        let allocated_bytes = self.allocated_bytes.swap(0, Ordering::SeqCst);
        let reallocations = self.reallocations.swap(0, Ordering::SeqCst);
        let reallocated_bytes = self.reallocated_bytes.swap(0, Ordering::SeqCst);
        AllocationRecord {
            allocations,
            allocated_bytes,
            reallocations,
            reallocated_bytes,
        }
    }
}

#[derive(Clone)]
pub struct AllocatorInstrument<A: 'static> {
    allocator: &'static InstrumentedAllocator<A>,
    allocations: Histogram<AllocationUnit>,
    allocated_bytes: Histogram<ByteUnit>,
    reallocations: Histogram<AllocationUnit>,
    reallocated_bytes: Histogram<ByteUnit>,
}

impl<A: 'static> AllocatorInstrument<A> {
    pub fn new(allocator: &'static InstrumentedAllocator<A>) -> Self {
        let allocations = Histogram::new(1_000_000);
        let allocated_bytes = Histogram::new(1_000_000_000);
        let reallocations = Histogram::new(1_000_000);
        let reallocated_bytes = Histogram::new(1_000_000_000);
        Self {
            allocator,
            allocations,
            allocated_bytes,
            reallocations,
            reallocated_bytes,
        }
    }
}

pub struct AllocationMeasurement<A: 'static>(&'static InstrumentedAllocator<A>);

impl<A: 'static> Measurement for AllocationMeasurement<A> {
    type Record = AllocationRecord;

    fn stop(self) -> Self::Record {
        self.0.take()
    }
}

impl<A: 'static> Instrument for AllocatorInstrument<A> {
    type Measurement = AllocationMeasurement<A>;
    type Record = AllocationRecord;

    fn start(&mut self) -> Self::Measurement {
        let _ = self.allocator.take();
        AllocationMeasurement(self.allocator)
    }

    fn record<Input: core::fmt::Debug>(&mut self, record: Self::Record, input: &Input) {
        let _ = self.allocations.record_input(record.allocations, input);
        let _ = self
            .allocated_bytes
            .record_input(record.allocated_bytes, input);
        let _ = self.reallocations.record_input(record.reallocations, input);
        let _ = self
            .reallocated_bytes
            .record_input(record.reallocated_bytes, input);
    }

    fn finish(&mut self) {}
}

impl<A: 'static> fmt::Debug for AllocatorInstrument<A> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("AllocatorInstrument")
            .field("allocations", &self.allocations)
            .field("allocated_bytes", &self.allocated_bytes)
            .field("reallocations", &self.reallocations)
            .field("reallocated_bytes", &self.reallocated_bytes)
            .finish()
    }
}

#[derive(Clone, Copy, Debug)]
struct AllocationUnit;

impl HistogramUnit for AllocationUnit {
    type Float = f64;
    type Whole = u64;

    fn name() -> &'static str {
        "Allocations"
    }

    fn display(value: u64) -> Self::Whole {
        value
    }

    fn display_float(value: f64) -> Self::Float {
        value
    }
}

#[test]
fn allocations_test() {
    use rand::Rng;

    let mut instrument = AllocatorInstrument::new(&crate::GLOBAL_ALLOC);
    for _check in 0..1000 {
        let measurement = instrument.start();
        let count: u8 = rand::thread_rng().gen();
        let mut items = vec![];
        for i in 0u8..count {
            items.push(i);
        }
        let record = measurement.stop();
        instrument.record(record, &count);
    }

    // use plotters::prelude::*;
    // let b = BitMapBackend::new("graphs/allocations.png", (1024, 768)).into_drawing_area();
    // b.fill(&WHITE).unwrap();
    // instrument.allocations.draw_chart("Allocations", b).unwrap();

    // let b = BitMapBackend::new("graphs/allocated_bytes.png", (1024, 768)).into_drawing_area();
    // b.fill(&WHITE).unwrap();
    // instrument
    //     .allocated_bytes
    //     .draw_chart("Allocated bytes", b)
    //     .unwrap();
    // // draw_chart(b)?;
    // println!("{:#?}", instrument.allocated_bytes.max_input);
}
