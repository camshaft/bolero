pub use byte_unit::AdjustedByte as ByteUnit;
use core::{
    cmp::Ordering,
    fmt,
    fmt::Write,
    marker::PhantomData,
    ops::{Deref, DerefMut},
};
pub use hdrhistogram::{Counter, RecordError};

#[derive(Clone)]
pub struct Input {
    value: u64,
    input: String,
    ordering: Ordering,
}

impl Input {
    fn min() -> Self {
        Self {
            value: core::u64::MAX,
            input: String::new(),
            ordering: Ordering::Less,
        }
    }

    fn max() -> Self {
        Self {
            value: 0,
            input: String::new(),
            ordering: Ordering::Greater,
        }
    }

    fn record<I: fmt::Debug>(&mut self, value: u64, input: &I) {
        if value.cmp(&self.value) == self.ordering {
            self.value = value;
            self.input.clear();
            write!(&mut self.input, "{:#?}", input).unwrap();
        }
    }
}

impl fmt::Debug for Input {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.input)
    }
}

#[derive(Clone)]
pub struct Histogram<D> {
    pub(crate) hist: hdrhistogram::Histogram<u64>,
    pub(crate) min_input: Input,
    pub(crate) max_input: Input,
    pub(crate) max_overflow: Option<u64>,
    pub(crate) display: PhantomData<D>,
}

impl<D> Histogram<D> {
    pub fn new(max: u64) -> Self {
        let hist = hdrhistogram::Histogram::new_with_bounds(1, max, 2).unwrap();
        Self {
            hist,
            min_input: Input::min(),
            max_input: Input::max(),
            max_overflow: None,
            display: PhantomData,
        }
    }

    pub fn record(&mut self, value: u64) -> Result<(), RecordError> {
        let res = self.hist.record(value);
        if res.is_err() {
            if let Some(prev) = self.max_overflow.as_mut() {
                *prev = (*prev).max(value);
            }
        }
        res
    }

    pub fn record_input<Input: fmt::Debug>(
        &mut self,
        value: u64,
        input: &Input,
    ) -> Result<(), RecordError> {
        self.record(value)?;

        self.min_input.record(value, input);
        self.max_input.record(value, input);

        Ok(())
    }
}

impl<D> Deref for Histogram<D> {
    type Target = hdrhistogram::Histogram<u64>;

    fn deref(&self) -> &Self::Target {
        &self.hist
    }
}
impl<D> DerefMut for Histogram<D> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.hist
    }
}

impl<D: HistogramUnit> fmt::Debug for Histogram<D> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let hdr = &self.hist;
        let percentile = |v| hdr.value_at_percentile(v);
        f.debug_struct("Histogram")
            .field("samples", &hdr.len())
            .field("min", &D::display(hdr.min()))
            .field("max", &D::display(hdr.max()))
            .field("mean", &D::display_float(hdr.mean()))
            .field("stdev", &D::display_float(hdr.stdev()))
            .field("90p", &D::display(percentile(90.0)))
            .field("95p", &D::display(percentile(95.0)))
            .field("99p", &D::display(percentile(99.0)))
            .field("99.9p", &D::display(percentile(99.9)))
            .field("min_input", &self.min_input)
            .field("max_input", &self.max_input)
            .finish()
    }
}

pub trait HistogramUnit {
    type Whole: fmt::Debug;
    type Float: fmt::Debug;

    fn name() -> &'static str;
    fn display(value: u64) -> Self::Whole;
    fn display_float(value: f64) -> Self::Float;
}

impl HistogramUnit for u64 {
    type Float = f64;
    type Whole = u64;

    fn name() -> &'static str {
        "Unit"
    }

    fn display(value: u64) -> Self::Whole {
        value
    }

    fn display_float(value: f64) -> Self::Float {
        value
    }
}

impl HistogramUnit for core::time::Duration {
    type Float = Self;
    type Whole = Self;

    fn name() -> &'static str {
        "Nanoseconds"
    }

    fn display(value: u64) -> Self {
        Self::from_nanos(value)
    }

    fn display_float(value: f64) -> Self::Float {
        Self::from_nanos(value.round() as u64)
    }
}

impl HistogramUnit for ByteUnit {
    type Float = Self;
    type Whole = Self;

    fn name() -> &'static str {
        "Bytes"
    }

    fn display(value: u64) -> Self {
        byte_unit::Byte::from_bytes(value as _).get_appropriate_unit(true)
    }

    fn display_float(value: f64) -> Self {
        byte_unit::Byte::from_unit(value, byte_unit::ByteUnit::B)
            .unwrap()
            .get_appropriate_unit(true)
    }
}

use plotters::prelude::*;

impl<D: HistogramUnit> Histogram<D> {
    #[allow(dead_code)]
    pub fn draw_chart<DB: DrawingBackend>(
        &self,
        name: &str,
        b: DrawingArea<DB, plotters::coord::Shift>,
    ) -> Result<(), Box<dyn std::error::Error>>
    where
        DB::ErrorType: 'static,
    {
        let len = self
            .hist
            .iter_recorded()
            .map(|entry| entry.count_at_value())
            .max()
            .unwrap_or(0);

        let min = self.hist.min().saturating_sub(1);
        let max = self.hist.max().saturating_add(1);

        let mut chart = ChartBuilder::on(&b)
            .set_label_area_size(LabelAreaPosition::Left, (5i32).percent_width())
            .set_label_area_size(LabelAreaPosition::Bottom, (10i32).percent_height())
            .margin(5)
            .caption(name, ("sans-serif", (5).percent_height()))
            .build_ranged(min..max, 0..len)?;

        chart
            .configure_mesh()
            .disable_x_mesh()
            .disable_y_mesh()
            .y_desc("Count")
            .x_desc(D::name())
            // .axis_desc_style(("sans-serif", 15).into_font())
            .draw()?;

        let data = self.hist.iter_recorded().map(|entry| {
            let x = entry.value_iterated_to();
            // let x = D::display(x);
            let y = entry.count_at_value();
            (x, y)
        });

        chart.draw_series(
            plotters::prelude::Histogram::vertical(&chart)
                .style(RED.mix(0.5).filled())
                .data(data),
        )?;

        // chart.draw_series(AreaSeries::new(data, 0, &RED.mix(0.2)).border_style(&RED))?;

        b.present()?;

        Ok(())
    }
}
