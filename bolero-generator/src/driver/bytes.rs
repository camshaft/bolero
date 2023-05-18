use super::*;

#[derive(Debug)]
pub struct ByteSliceDriver<'a> {
    mode: DriverMode,
    input: &'a [u8],
    depth: usize,
    max_depth: usize,
}

impl<'a> ByteSliceDriver<'a> {
    pub fn new(input: &'a [u8], mode: Option<DriverMode>) -> Self {
        let mode = mode.unwrap_or(DriverMode::Direct);

        Self {
            input,
            mode,
            depth: 0,
            max_depth: super::DEFAULT_MAX_DEPTH,
        }
    }

    #[inline]
    pub fn new_direct(input: &'a [u8]) -> Self {
        Self::new(input, Some(DriverMode::Direct))
    }

    #[inline]
    pub fn new_forced(input: &'a [u8]) -> Self {
        Self::new(input, Some(DriverMode::Forced))
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
    fn gen_from_bytes<Gen, T>(&mut self, len: RangeInclusive<usize>, mut gen: Gen) -> Option<T>
    where
        Gen: FnMut(&[u8]) -> Option<(usize, T)>,
    {
        let end = self.input.len().min(*len.end());
        let slice = &self.input[..end];
        let (len, value) = gen(slice)?;
        self.consume_bytes(len);
        Some(value)
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
