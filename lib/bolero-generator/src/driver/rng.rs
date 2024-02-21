use super::*;

#[derive(Debug, Default)]
struct Buffer {
    #[cfg(feature = "alloc")]
    bytes: alloc::vec::Vec<u8>,
}

impl Buffer {
    #[cfg(feature = "alloc")]
    fn consume(&mut self, len: usize) {
        self.bytes.drain(..len);
    }
}

#[derive(Debug)]
pub struct Rng<R: RngCore> {
    rng: R,
    depth: usize,
    max_depth: usize,
    mode: DriverMode,
    #[allow(dead_code)] // this isn't used in no_std mode
    buffer: Buffer,
}

impl<R: RngCore> Rng<R> {
    pub fn new(rng: R, options: &Options) -> Self {
        Self {
            rng,
            depth: 0,
            max_depth: options.max_depth_or_default(),
            mode: options.driver_mode.unwrap_or(DriverMode::Forced),
            buffer: Default::default(),
        }
    }

    #[inline]
    fn fill_bytes(&mut self, bytes: &mut [u8]) -> Option<()> {
        fill_bytes(&mut self.rng, bytes, self.mode)
    }

    #[cfg(feature = "alloc")]
    fn fill_buffer(&mut self, len: usize) -> Option<&[u8]> {
        let data = &mut self.buffer.bytes;

        let initial_len = data.len();

        // we don't need any more bytes, just return what we have
        if initial_len >= len {
            return Some(&data[..len]);
        }

        // extend the random bytes
        data.try_reserve(len).ok()?;
        data.resize(len, 0);
        fill_bytes(&mut self.rng, &mut data[initial_len..], self.mode)?;

        Some(&data[..len])
    }
}

fn fill_bytes<R: RngCore>(rng: &mut R, bytes: &mut [u8], mode: DriverMode) -> Option<()> {
    match mode {
        DriverMode::Direct => RngCore::try_fill_bytes(rng, bytes).ok(),
        DriverMode::Forced => {
            if RngCore::try_fill_bytes(rng, bytes).is_err() {
                // if the rng fails to fill the remaining bytes, then we just start returning 0s
                for byte in bytes.iter_mut() {
                    *byte = 0;
                }
            }

            Some(())
        }
    }
}

impl<R: RngCore> FillBytes for Rng<R> {
    #[inline]
    fn mode(&self) -> DriverMode {
        self.mode
    }

    #[inline]
    fn peek_bytes(&mut self, _offset: usize, bytes: &mut [u8]) -> Option<()> {
        self.fill_bytes(bytes)
    }

    #[inline]
    fn consume_bytes(&mut self, _consumed: usize) {}
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

    #[cfg(feature = "alloc")]
    fn gen_from_bytes<Hint, Gen, T>(&mut self, hint: Hint, mut gen: Gen) -> Option<T>
    where
        Hint: FnOnce() -> (usize, Option<usize>),
        Gen: FnMut(&[u8]) -> Option<(usize, T)>,
    {
        // Even attempting an alloc of more than 0x10000000000 bytes makes asan crash.
        // LibFuzzer limits memory to 2G (by default) and try_reserve() does not fail in oom situations then.
        // With all the above, limit memory allocations to 1M total here.
        const NONSENSICAL_SIZE: usize = 1024 * 1024;
        const ABUSIVE_SIZE: usize = 1024;
        const MIN_INCREASE: usize = 32;

        let hint = match hint() {
            (min, None) => min..=usize::MAX,
            (min, Some(max)) => min..=max,
        };

        match self.mode {
            DriverMode::Direct => {
                let len = match (hint.start(), hint.end()) {
                    (s, e) if s == e => *s,
                    (s, e) => self.gen_usize(Bound::Included(s), Bound::Included(e))?,
                };
                if len >= NONSENSICAL_SIZE {
                    return None;
                }
                let bytes = self.fill_buffer(len)?;
                let (consumed, value) = gen(bytes)?;
                self.buffer.consume(consumed);
                Some(value)
            }
            DriverMode::Forced => {
                let mut len = hint.start()
                    + self.gen_usize(
                        Bound::Included(&0),
                        Bound::Included(&core::cmp::min(ABUSIVE_SIZE, hint.end() - hint.start())),
                    )?;
                loop {
                    let data = self.fill_buffer(len)?;
                    match gen(data) {
                        Some((consumed, res)) => {
                            self.buffer.consume(consumed);
                            return Some(res);
                        }
                        None => {
                            let max_additional_size =
                                core::cmp::min(ABUSIVE_SIZE, hint.end().saturating_sub(data.len()));
                            if max_additional_size == 0 {
                                self.buffer.bytes.clear();
                                return None; // we actually tried feeding the max amount of data already
                            }

                            let additional_size = self.gen_usize(
                                Bound::Included(&core::cmp::min(MIN_INCREASE, max_additional_size)),
                                Bound::Included(&max_additional_size),
                            )?;
                            len += additional_size;
                            if len >= NONSENSICAL_SIZE {
                                return None;
                            }
                        }
                    }
                }
            }
        }
    }

    #[cfg(not(feature = "alloc"))]
    fn gen_from_bytes<Hint, Gen, T>(&mut self, hint: Hint, mut gen: Gen) -> Option<T>
    where
        Hint: FnOnce() -> (usize, Option<usize>),
        Gen: FnMut(&[u8]) -> Option<(usize, T)>,
    {
        // In alloc-free mode, we can't support FORCED driver mode so just do our best to fill
        // the data
        const DATA_LEN: usize = 256;

        let mut data = [0; DATA_LEN];

        let hint = match hint() {
            (min, None) => min..=DATA_LEN,
            (min, Some(max)) => min..=max.min(DATA_LEN),
        };

        let len = match (hint.start(), hint.end()) {
            (s, e) if s == e => *s,
            (s, e) => self.gen_usize(Bound::Included(s), Bound::Included(e))?,
        };

        let data = &mut data[..len];

        self.peek_bytes(0, data)?;
        let (_consumed, value) = gen(data)?;
        Some(value)
    }
}
