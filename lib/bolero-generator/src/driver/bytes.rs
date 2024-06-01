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

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        self.input
    }
}

impl<'a> FillBytes for ByteSliceDriver<'a> {
    #[inline]
    fn mode(&self) -> DriverMode {
        self.mode
    }

    #[inline]
    fn peek_bytes(&mut self, offset: usize, bytes: &mut [u8]) -> Option<()> {
        match self.input.len().checked_sub(offset) {
            None | Some(0) => {
                // no bytes left so fill in zeros
                bytes.fill(0);
            }
            Some(remaining_len) if remaining_len >= bytes.len() => {
                let input = &self.input[offset..];
                let input = &input[..bytes.len()];
                bytes.copy_from_slice(input);
            }
            Some(remaining_len) => {
                let input = &self.input[offset..];
                // we don't have enough bytes to fill the whole output
                let (head, tail) = bytes.split_at_mut(remaining_len);
                head.copy_from_slice(input);
                tail.fill(0);
            }
        }

        Some(())
    }

    #[inline]
    fn consume_bytes(&mut self, consumed: usize) {
        let consumed = consumed.min(self.input.len());
        self.input = &self.input[consumed..];
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
}
