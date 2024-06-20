use super::*;

#[cfg(feature = "alloc")]
use buffer_alloc::Buffer;
#[cfg(not(feature = "alloc"))]
use buffer_no_alloc::Buffer;

#[derive(Debug)]
pub struct Rng<R: RngCore> {
    rng: R,
    depth: usize,
    max_depth: usize,
    consumed_len: usize,
    max_len: usize,
    #[allow(dead_code)] // this isn't used in no_std mode
    buffer: Buffer,
}

impl<R: RngCore> Rng<R> {
    pub fn new(rng: R, options: &Options) -> Self {
        Self {
            rng,
            depth: 0,
            max_depth: options.max_depth_or_default(),
            consumed_len: 0,
            max_len: options.max_len_or_default(),
            buffer: Default::default(),
        }
    }

    #[inline]
    fn fill_bytes(&mut self, bytes: &mut [u8]) -> Option<()> {
        let len = bytes.len().min(self.remaining_len());
        let (to_rng, to_fill) = bytes.split_at_mut(len);
        fill_bytes(&mut self.rng, to_rng)?;
        to_fill.fill(0);
        Some(())
    }

    #[inline]
    fn has_remaining(&self) -> bool {
        self.consumed_len < self.max_len
    }

    #[inline]
    fn remaining_len(&self) -> usize {
        self.max_len.saturating_sub(self.consumed_len)
    }

    #[inline]
    fn fill_buffer(&mut self, len: usize) -> Option<&[u8]> {
        self.buffer.fill(len, &mut self.rng)?;
        Some(self.buffer.slice_mut(len))
    }
}

impl<R: RngCore> AsRef<R> for Rng<R> {
    #[inline]
    fn as_ref(&self) -> &R {
        &self.rng
    }
}

#[inline]
fn fill_bytes<R: RngCore>(rng: &mut R, bytes: &mut [u8]) -> Option<()> {
    if RngCore::try_fill_bytes(rng, bytes).is_err() {
        // if the rng fails to fill the remaining bytes, then we just start returning 0s
        for byte in bytes.iter_mut() {
            *byte = 0;
        }
    }

    Some(())
}

macro_rules! impl_sample {
    ($sample:ident, $ty:ty, $inner:ident) => {
        #[inline(always)]
        fn $sample(&mut self) -> Option<$ty> {
            if self.has_remaining() {
                self.consumed_len += core::mem::size_of::<$ty>();
                Some(self.rng.$inner() as $ty)
            } else {
                Some(0)
            }
        }
    };
}

impl<R: RngCore> FillBytes for Rng<R> {
    // prefer sampling the larger values since it's faster to pull from the RNG
    const SHOULD_SHRINK: bool = false;

    #[inline]
    fn peek_bytes(&mut self, _offset: usize, bytes: &mut [u8]) -> Option<()> {
        self.fill_bytes(bytes)
    }

    #[inline(always)]
    fn consume_bytes(&mut self, consumed: usize) {
        self.consumed_len += consumed;
    }

    #[inline(always)]
    fn sample_bool(&mut self) -> Option<bool> {
        if self.has_remaining() {
            self.consumed_len += 1;
            let value = self.rng.next_u32();
            Some(value < (u32::MAX / 2))
        } else {
            Some(false)
        }
    }

    impl_sample!(sample_u8, u8, next_u32);
    impl_sample!(sample_i8, i8, next_u32);
    impl_sample!(sample_u16, u16, next_u32);
    impl_sample!(sample_i16, i16, next_u32);
    impl_sample!(sample_u32, u32, next_u32);
    impl_sample!(sample_i32, i32, next_u32);
    impl_sample!(sample_u64, u64, next_u64);
    impl_sample!(sample_i64, i64, next_u64);
    impl_sample!(sample_usize, usize, next_u64);
    impl_sample!(sample_isize, isize, next_u64);
}

impl<R: RngCore> Driver for Rng<R> {
    gen_from_bytes!();

    #[inline]
    fn depth(&self) -> usize {
        self.depth
    }

    #[inline]
    fn set_depth(&mut self, depth: usize) {
        self.depth = depth;
    }

    #[inline]
    fn max_depth(&self) -> usize {
        self.max_depth
    }

    #[inline]
    fn gen_from_bytes<Hint, Gen, T>(&mut self, hint: Hint, mut gen: Gen) -> Option<T>
    where
        Hint: FnOnce() -> (usize, Option<usize>),
        Gen: FnMut(&[u8]) -> Option<(usize, T)>,
    {
        let (min, max) = hint();

        let max = max
            .unwrap_or(usize::MAX)
            // make sure max is at least min
            .max(min)
            .min(self.remaining_len())
            .min(Buffer::MAX_CAPACITY);

        let len = self.gen_usize(Bound::Included(&min), Bound::Included(&max))?;
        let bytes = self.fill_buffer(len)?;
        let (consumed, value) = gen(bytes)?;
        self.consume_bytes(consumed);
        self.buffer.clear();
        Some(value)
    }
}

#[cfg(feature = "alloc")]
mod buffer_alloc {
    use super::*;

    #[derive(Debug, Default)]
    pub struct Buffer {
        bytes: alloc::vec::Vec<u8>,
    }

    impl Buffer {
        pub const MAX_CAPACITY: usize = isize::MAX as _;

        #[inline]
        pub fn fill<R: RngCore>(&mut self, len: usize, rng: &mut R) -> Option<()> {
            let data = &mut self.bytes;

            let initial_len = data.len();

            // we don't need any more bytes, just return what we have
            if initial_len >= len {
                return Some(());
            }

            // extend the random bytes
            data.try_reserve(len).ok()?;
            data.resize(len, 0);
            fill_bytes(rng, &mut data[initial_len..])?;

            Some(())
        }

        #[inline]
        pub fn slice_mut(&mut self, len: usize) -> &mut [u8] {
            &mut self.bytes[..len]
        }

        #[inline]
        pub fn clear(&mut self) {
            self.bytes.clear();
        }
    }
}

#[cfg_attr(feature = "alloc", allow(dead_code))]
mod buffer_no_alloc {
    use super::*;

    #[derive(Debug)]
    pub struct Buffer {
        bytes: [u8; Self::MAX_CAPACITY],
        len: usize,
    }

    impl Default for Buffer {
        fn default() -> Self {
            Self {
                bytes: [0; Self::MAX_CAPACITY],
                len: Default::default(),
            }
        }
    }

    impl Buffer {
        pub const MAX_CAPACITY: usize = 256;

        #[inline]
        pub fn fill<R: RngCore>(&mut self, len: usize, rng: &mut R) -> Option<()> {
            if cfg!(test) {
                assert!(len <= Self::MAX_CAPACITY);
            }

            let initial_len = self.len;

            // we don't need any more bytes, just return what we have
            if initial_len >= len {
                return Some(());
            }

            // extend the random bytes
            fill_bytes(rng, &mut self.bytes[initial_len..])?;
            self.len = len;

            Some(())
        }

        #[inline]
        pub fn slice_mut(&mut self, len: usize) -> &mut [u8] {
            &mut self.bytes[..len]
        }

        #[inline]
        pub fn clear(&mut self) {
            self.len = 0;
        }
    }
}
