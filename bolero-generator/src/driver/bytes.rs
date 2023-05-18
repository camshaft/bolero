use super::*;

#[derive(Debug)]
pub struct ByteSliceDriver<'a> {
    mode: DriverMode,
    input: &'a [u8],
    depth: usize,
    max_depth: usize,
}

impl<'a> ByteSliceDriver<'a> {
    pub fn new(input: &'a [u8], options: &Options) -> Self {
        let mode = options.driver_mode.unwrap_or(DriverMode::Direct);
        let max_depth = options.max_depth_or_default();

        Self {
            input,
            mode,
            depth: 0,
            max_depth,
        }
    }
}

impl<'a> FillBytes for ByteSliceDriver<'a> {
    #[inline]
    fn mode(&self) -> DriverMode {
        self.mode
    }

    #[inline]
    fn peek_bytes(&mut self, offset: usize, bytes: &mut [u8]) -> Option<()> {
        match self.mode {
            DriverMode::Direct => {
                if (offset + bytes.len()) > self.input.len() {
                    None
                } else {
                    bytes.copy_from_slice(&self.input[offset..(offset + bytes.len())]);
                    Some(())
                }
            }
            DriverMode::Forced => {
                if offset < self.input.len() {
                    let copy_len = core::cmp::min(bytes.len(), self.input.len() - offset);
                    bytes[..copy_len].copy_from_slice(&self.input[offset..(offset + copy_len)]);
                    bytes[copy_len..].fill(0);
                } else {
                    bytes.fill(0);
                }
                Some(())
            }
        }
    }

    #[inline]
    fn consume_bytes(&mut self, consumed: usize) {
        self.input = &self.input[core::cmp::min(consumed, self.input.len())..];
    }
}

impl<'a> Driver for ByteSliceDriver<'a> {
    gen_from_bytes!();

    #[inline]
    fn gen_from_bytes<Hint, Gen, T>(&mut self, _hint: Hint, mut gen: Gen) -> Option<T>
    where
        Hint: FnOnce() -> (usize, Option<usize>),
        Gen: FnMut(&[u8]) -> Option<(usize, T)>,
    {
        let slice = self.input;
        let (len, value) = gen(slice)?;
        self.consume_bytes(len);
        Some(value)
    }

    #[inline]
    fn gen_recursive<F, R>(&mut self, f: F) -> Option<R>
    where
        F: FnOnce(&mut Self) -> Option<R>,
    {
        if *self.depth() == self.max_depth() {
            return None;
        }

        *self.depth() += 1;

        let value = f(self);

        *self.depth() -= 1;

        value
    }

    #[inline]
    fn depth(&mut self) -> &mut usize {
        &mut self.depth
    }

    #[inline]
    fn max_depth(&self) -> usize {
        self.max_depth
    }
}
