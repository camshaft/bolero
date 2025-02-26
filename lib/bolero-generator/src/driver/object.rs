use super::Driver;
use core::ops::{self, Bound};

/// An object-safe Driver trait
pub trait DynDriver {
    fn depth(&self) -> usize;
    fn set_depth(&mut self, depth: usize);
    fn max_depth(&self) -> usize;
    fn gen_variant(&mut self, variants: usize, base_case: usize) -> Option<usize>;
    fn gen_u8(&mut self, min: Bound<&u8>, max: Bound<&u8>) -> Option<u8>;
    fn gen_i8(&mut self, min: Bound<&i8>, max: Bound<&i8>) -> Option<i8>;
    fn gen_u16(&mut self, min: Bound<&u16>, max: Bound<&u16>) -> Option<u16>;
    fn gen_i16(&mut self, min: Bound<&i16>, max: Bound<&i16>) -> Option<i16>;
    fn gen_u32(&mut self, min: Bound<&u32>, max: Bound<&u32>) -> Option<u32>;
    fn gen_i32(&mut self, min: Bound<&i32>, max: Bound<&i32>) -> Option<i32>;
    fn gen_u64(&mut self, min: Bound<&u64>, max: Bound<&u64>) -> Option<u64>;
    fn gen_i64(&mut self, min: Bound<&i64>, max: Bound<&i64>) -> Option<i64>;
    fn gen_u128(&mut self, min: Bound<&u128>, max: Bound<&u128>) -> Option<u128>;
    fn gen_i128(&mut self, min: Bound<&i128>, max: Bound<&i128>) -> Option<i128>;
    fn gen_usize(&mut self, min: Bound<&usize>, max: Bound<&usize>) -> Option<usize>;
    fn gen_isize(&mut self, min: Bound<&isize>, max: Bound<&isize>) -> Option<isize>;
    fn gen_f32(&mut self, min: Bound<&f32>, max: Bound<&f32>) -> Option<f32>;
    fn gen_f64(&mut self, min: Bound<&f64>, max: Bound<&f64>) -> Option<f64>;
    fn gen_char(&mut self, min: Bound<&char>, max: Bound<&char>) -> Option<char>;
    fn gen_bool(&mut self, probability: Option<f32>) -> Option<bool>;
    fn gen_from_bytes(
        &mut self,
        hint: &mut dyn FnMut() -> (usize, Option<usize>),
        gen: &mut dyn FnMut(&[u8]) -> Option<usize>,
    ) -> Option<()>;
}

/// `&dyn FnOnce()` doesn't work since invoking it takes ownership. So wrap it as a `FnMut()`.
#[inline]
fn hint_fn<F: FnOnce() -> (usize, Option<usize>)>(f: F) -> impl FnMut() -> (usize, Option<usize>) {
    enum Hint<F> {
        Pending(F),
        Resolved((usize, Option<usize>)),
    }

    impl<F: FnOnce() -> (usize, Option<usize>)> Hint<F> {
        #[inline]
        fn get(&mut self) -> (usize, Option<usize>) {
            match core::mem::replace(self, Hint::Resolved((0, None))) {
                Hint::Pending(f) => {
                    let value = f();
                    *self = Hint::Resolved(value);
                    value
                }
                Hint::Resolved(value) => {
                    *self = Hint::Resolved(value);
                    value
                }
            }
        }
    }

    let mut hint = Hint::Pending(f);

    move || hint.get()
}

pub struct Borrowed<'a>(pub &'a mut dyn DynDriver);

impl Driver for Borrowed<'_> {
    #[inline]
    fn depth(&self) -> usize {
        self.0.depth()
    }

    #[inline]
    fn set_depth(&mut self, depth: usize) {
        self.0.set_depth(depth);
    }

    #[inline]
    fn max_depth(&self) -> usize {
        self.0.max_depth()
    }

    #[inline]
    fn gen_variant(&mut self, variants: usize, base_case: usize) -> Option<usize> {
        self.0.gen_variant(variants, base_case)
    }

    #[inline]
    fn gen_u8(&mut self, min: Bound<&u8>, max: Bound<&u8>) -> Option<u8> {
        self.0.gen_u8(min, max)
    }

    #[inline]
    fn gen_i8(&mut self, min: Bound<&i8>, max: Bound<&i8>) -> Option<i8> {
        self.0.gen_i8(min, max)
    }

    #[inline]
    fn gen_u16(&mut self, min: Bound<&u16>, max: Bound<&u16>) -> Option<u16> {
        self.0.gen_u16(min, max)
    }

    #[inline]
    fn gen_i16(&mut self, min: Bound<&i16>, max: Bound<&i16>) -> Option<i16> {
        self.0.gen_i16(min, max)
    }

    #[inline]
    fn gen_u32(&mut self, min: Bound<&u32>, max: Bound<&u32>) -> Option<u32> {
        self.0.gen_u32(min, max)
    }

    #[inline]
    fn gen_i32(&mut self, min: Bound<&i32>, max: Bound<&i32>) -> Option<i32> {
        self.0.gen_i32(min, max)
    }

    #[inline]
    fn gen_u64(&mut self, min: Bound<&u64>, max: Bound<&u64>) -> Option<u64> {
        self.0.gen_u64(min, max)
    }

    #[inline]
    fn gen_i64(&mut self, min: Bound<&i64>, max: Bound<&i64>) -> Option<i64> {
        self.0.gen_i64(min, max)
    }

    #[inline]
    fn gen_u128(&mut self, min: Bound<&u128>, max: Bound<&u128>) -> Option<u128> {
        self.0.gen_u128(min, max)
    }

    #[inline]
    fn gen_i128(&mut self, min: Bound<&i128>, max: Bound<&i128>) -> Option<i128> {
        self.0.gen_i128(min, max)
    }

    #[inline]
    fn gen_usize(&mut self, min: Bound<&usize>, max: Bound<&usize>) -> Option<usize> {
        self.0.gen_usize(min, max)
    }

    #[inline]
    fn gen_isize(&mut self, min: Bound<&isize>, max: Bound<&isize>) -> Option<isize> {
        self.0.gen_isize(min, max)
    }

    #[inline]
    fn gen_f32(&mut self, min: Bound<&f32>, max: Bound<&f32>) -> Option<f32> {
        self.0.gen_f32(min, max)
    }

    #[inline]
    fn gen_f64(&mut self, min: Bound<&f64>, max: Bound<&f64>) -> Option<f64> {
        self.0.gen_f64(min, max)
    }

    #[inline]
    fn gen_char(&mut self, min: Bound<&char>, max: Bound<&char>) -> Option<char> {
        self.0.gen_char(min, max)
    }

    #[inline]
    fn gen_bool(&mut self, probability: Option<f32>) -> Option<bool> {
        self.0.gen_bool(probability)
    }

    #[inline]
    fn gen_from_bytes<Hint, Gen, T>(&mut self, hint: Hint, mut gen: Gen) -> Option<T>
    where
        Hint: FnOnce() -> (usize, Option<usize>),
        Gen: FnMut(&[u8]) -> Option<(usize, T)>,
    {
        let mut value = None;
        let mut hint = hint_fn(hint);
        self.0.gen_from_bytes(&mut hint, &mut |bytes| {
            let (len, v) = gen(bytes)?;
            value = Some(v);
            Some(len)
        })?;
        value
    }
}

impl<D: DynDriver> Driver for D {
    #[inline]
    fn depth(&self) -> usize {
        <D as DynDriver>::depth(self)
    }

    #[inline]
    fn set_depth(&mut self, depth: usize) {
        <D as DynDriver>::set_depth(self, depth)
    }

    #[inline]
    fn max_depth(&self) -> usize {
        <D as DynDriver>::max_depth(self)
    }

    #[inline]
    fn gen_variant(&mut self, variants: usize, base_case: usize) -> Option<usize> {
        <D as DynDriver>::gen_variant(self, variants, base_case)
    }

    #[inline]
    fn gen_u8(&mut self, min: Bound<&u8>, max: Bound<&u8>) -> Option<u8> {
        <D as DynDriver>::gen_u8(self, min, max)
    }

    #[inline]
    fn gen_i8(&mut self, min: Bound<&i8>, max: Bound<&i8>) -> Option<i8> {
        <D as DynDriver>::gen_i8(self, min, max)
    }

    #[inline]
    fn gen_u16(&mut self, min: Bound<&u16>, max: Bound<&u16>) -> Option<u16> {
        <D as DynDriver>::gen_u16(self, min, max)
    }

    #[inline]
    fn gen_i16(&mut self, min: Bound<&i16>, max: Bound<&i16>) -> Option<i16> {
        <D as DynDriver>::gen_i16(self, min, max)
    }

    #[inline]
    fn gen_u32(&mut self, min: Bound<&u32>, max: Bound<&u32>) -> Option<u32> {
        <D as DynDriver>::gen_u32(self, min, max)
    }

    #[inline]
    fn gen_i32(&mut self, min: Bound<&i32>, max: Bound<&i32>) -> Option<i32> {
        <D as DynDriver>::gen_i32(self, min, max)
    }

    #[inline]
    fn gen_u64(&mut self, min: Bound<&u64>, max: Bound<&u64>) -> Option<u64> {
        <D as DynDriver>::gen_u64(self, min, max)
    }

    #[inline]
    fn gen_i64(&mut self, min: Bound<&i64>, max: Bound<&i64>) -> Option<i64> {
        <D as DynDriver>::gen_i64(self, min, max)
    }

    #[inline]
    fn gen_u128(&mut self, min: Bound<&u128>, max: Bound<&u128>) -> Option<u128> {
        <D as DynDriver>::gen_u128(self, min, max)
    }

    #[inline]
    fn gen_i128(&mut self, min: Bound<&i128>, max: Bound<&i128>) -> Option<i128> {
        <D as DynDriver>::gen_i128(self, min, max)
    }

    #[inline]
    fn gen_usize(&mut self, min: Bound<&usize>, max: Bound<&usize>) -> Option<usize> {
        <D as DynDriver>::gen_usize(self, min, max)
    }

    #[inline]
    fn gen_isize(&mut self, min: Bound<&isize>, max: Bound<&isize>) -> Option<isize> {
        <D as DynDriver>::gen_isize(self, min, max)
    }

    #[inline]
    fn gen_f32(&mut self, min: Bound<&f32>, max: Bound<&f32>) -> Option<f32> {
        <D as DynDriver>::gen_f32(self, min, max)
    }

    #[inline]
    fn gen_f64(&mut self, min: Bound<&f64>, max: Bound<&f64>) -> Option<f64> {
        <D as DynDriver>::gen_f64(self, min, max)
    }

    #[inline]
    fn gen_char(&mut self, min: Bound<&char>, max: Bound<&char>) -> Option<char> {
        <D as DynDriver>::gen_char(self, min, max)
    }

    #[inline]
    fn gen_bool(&mut self, probability: Option<f32>) -> Option<bool> {
        <D as DynDriver>::gen_bool(self, probability)
    }

    #[inline]
    fn gen_from_bytes<Hint, Gen, T>(&mut self, hint: Hint, mut gen: Gen) -> Option<T>
    where
        Hint: FnOnce() -> (usize, Option<usize>),
        Gen: FnMut(&[u8]) -> Option<(usize, T)>,
    {
        let mut value = None;
        let mut hint = hint_fn(hint);
        <D as DynDriver>::gen_from_bytes(self, &mut hint, &mut |bytes| {
            let (len, v) = gen(bytes)?;
            value = Some(v);
            Some(len)
        })?;
        value
    }
}

#[derive(Clone, Default, Debug)]
pub struct Object<D: super::Driver>(pub D);

impl<D: Driver> ops::Deref for Object<D> {
    type Target = D;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<D: Driver> ops::DerefMut for Object<D> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<D: super::Driver> DynDriver for Object<D> {
    #[inline]
    fn depth(&self) -> usize {
        <D as Driver>::depth(self)
    }

    #[inline]
    fn set_depth(&mut self, depth: usize) {
        <D as Driver>::set_depth(self, depth)
    }

    #[inline]
    fn max_depth(&self) -> usize {
        <D as Driver>::max_depth(self)
    }

    #[inline]
    fn gen_variant(&mut self, variants: usize, base_case: usize) -> Option<usize> {
        <D as Driver>::gen_variant(self, variants, base_case)
    }

    #[inline]
    fn gen_u8(&mut self, min: Bound<&u8>, max: Bound<&u8>) -> Option<u8> {
        <D as Driver>::gen_u8(self, min, max)
    }

    #[inline]
    fn gen_i8(&mut self, min: Bound<&i8>, max: Bound<&i8>) -> Option<i8> {
        <D as Driver>::gen_i8(self, min, max)
    }

    #[inline]
    fn gen_u16(&mut self, min: Bound<&u16>, max: Bound<&u16>) -> Option<u16> {
        <D as Driver>::gen_u16(self, min, max)
    }

    #[inline]
    fn gen_i16(&mut self, min: Bound<&i16>, max: Bound<&i16>) -> Option<i16> {
        <D as Driver>::gen_i16(self, min, max)
    }

    #[inline]
    fn gen_u32(&mut self, min: Bound<&u32>, max: Bound<&u32>) -> Option<u32> {
        <D as Driver>::gen_u32(self, min, max)
    }

    #[inline]
    fn gen_i32(&mut self, min: Bound<&i32>, max: Bound<&i32>) -> Option<i32> {
        <D as Driver>::gen_i32(self, min, max)
    }

    #[inline]
    fn gen_u64(&mut self, min: Bound<&u64>, max: Bound<&u64>) -> Option<u64> {
        <D as Driver>::gen_u64(self, min, max)
    }

    #[inline]
    fn gen_i64(&mut self, min: Bound<&i64>, max: Bound<&i64>) -> Option<i64> {
        <D as Driver>::gen_i64(self, min, max)
    }

    #[inline]
    fn gen_u128(&mut self, min: Bound<&u128>, max: Bound<&u128>) -> Option<u128> {
        <D as Driver>::gen_u128(self, min, max)
    }

    #[inline]
    fn gen_i128(&mut self, min: Bound<&i128>, max: Bound<&i128>) -> Option<i128> {
        <D as Driver>::gen_i128(self, min, max)
    }

    #[inline]
    fn gen_usize(&mut self, min: Bound<&usize>, max: Bound<&usize>) -> Option<usize> {
        <D as Driver>::gen_usize(self, min, max)
    }

    #[inline]
    fn gen_isize(&mut self, min: Bound<&isize>, max: Bound<&isize>) -> Option<isize> {
        <D as Driver>::gen_isize(self, min, max)
    }

    #[inline]
    fn gen_f32(&mut self, min: Bound<&f32>, max: Bound<&f32>) -> Option<f32> {
        <D as Driver>::gen_f32(self, min, max)
    }

    #[inline]
    fn gen_f64(&mut self, min: Bound<&f64>, max: Bound<&f64>) -> Option<f64> {
        <D as Driver>::gen_f64(self, min, max)
    }

    #[inline]
    fn gen_char(&mut self, min: Bound<&char>, max: Bound<&char>) -> Option<char> {
        <D as Driver>::gen_char(self, min, max)
    }

    #[inline]
    fn gen_bool(&mut self, probability: Option<f32>) -> Option<bool> {
        <D as Driver>::gen_bool(self, probability)
    }

    #[inline]
    fn gen_from_bytes(
        &mut self,
        hint: &mut dyn FnMut() -> (usize, Option<usize>),
        gen: &mut dyn FnMut(&[u8]) -> Option<usize>,
    ) -> Option<()> {
        <D as Driver>::gen_from_bytes(self, hint, |bytes| {
            let len = gen(bytes)?;
            Some((len, ()))
        })?;
        Some(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(dead_code)]
    fn assert_object_safe(_: &dyn DynDriver) {}

    #[allow(dead_code)]
    fn assert_dyn_cast<T: 'static + Driver>(driver: T) -> Box<dyn DynDriver> {
        Box::new(Object(driver))
    }
}
