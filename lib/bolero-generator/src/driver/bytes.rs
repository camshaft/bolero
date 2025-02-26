use super::*;

#[derive(Debug)]
pub struct Driver<I> {
    input: I,
    depth: usize,
    max_depth: usize,
    len: usize,
    cursor: usize,
}

impl<I> Driver<I>
where
    I: AsRef<[u8]>,
{
    pub fn new(input: I, options: &Options) -> Self {
        let max_depth = options.max_depth_or_default();
        let len = options.max_len_or_default().min(input.as_ref().len());

        Self {
            input,
            depth: 0,
            max_depth,
            len,
            cursor: 0,
        }
    }

    pub fn reset(&mut self, input: I, options: &Options) -> I {
        let max_depth = options.max_depth_or_default();
        let len = options.max_len_or_default().min(input.as_ref().len());

        let prev = core::mem::replace(&mut self.input, input);
        self.depth = 0;
        self.max_depth = max_depth;
        self.cursor = 0;
        self.len = len;

        prev
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.input.as_ref()[self.cursor..self.len]
    }

    #[inline]
    pub fn into_inner(self) -> I {
        self.input
    }
}

impl<I> FillBytes for Driver<I>
where
    I: AsRef<[u8]>,
{
    #[inline]
    fn peek_bytes(&mut self, offset: usize, bytes: &mut [u8]) -> Option<()> {
        let slice = self.as_slice();
        match slice.len().checked_sub(offset) {
            None | Some(0) => {
                // no bytes left so fill in zeros
                bytes.fill(0);
            }
            Some(remaining_len) if remaining_len >= bytes.len() => {
                let input = &slice[offset..];
                let input = &input[..bytes.len()];
                bytes.copy_from_slice(input);
            }
            Some(remaining_len) => {
                let input = &slice[offset..];
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
        let remaining = self.len - self.cursor;
        let consumed = consumed.min(remaining);
        self.cursor += consumed;
    }
}

impl<I> super::Driver for Driver<I>
where
    I: AsRef<[u8]>,
{
    gen_from_bytes!();

    #[inline]
    fn gen_from_bytes<Hint, Gen, T>(&mut self, _hint: Hint, mut produce: Gen) -> Option<T>
    where
        Hint: FnOnce() -> (usize, Option<usize>),
        Gen: FnMut(&[u8]) -> Option<(usize, T)>,
    {
        let slice = self.as_slice();
        let (len, value) = produce(slice)?;
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

#[derive(Debug)]
pub struct ByteSliceDriver<'a>(Driver<&'a [u8]>);

impl<'a> ByteSliceDriver<'a> {
    pub fn new(input: &'a [u8], options: &Options) -> Self {
        Self(Driver::new(input, options))
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl FillBytes for ByteSliceDriver<'_> {
    #[inline]
    fn peek_bytes(&mut self, offset: usize, bytes: &mut [u8]) -> Option<()> {
        self.0.peek_bytes(offset, bytes)
    }

    #[inline]
    fn consume_bytes(&mut self, consumed: usize) {
        self.0.consume_bytes(consumed)
    }
}

impl super::Driver for ByteSliceDriver<'_> {
    gen_from_bytes!();

    #[inline]
    fn gen_from_bytes<Hint, Gen, T>(&mut self, hint: Hint, produce: Gen) -> Option<T>
    where
        Hint: FnOnce() -> (usize, Option<usize>),
        Gen: FnMut(&[u8]) -> Option<(usize, T)>,
    {
        self.0.gen_from_bytes(hint, produce)
    }

    #[inline]
    fn depth(&self) -> usize {
        self.0.depth
    }

    #[inline]
    fn set_depth(&mut self, depth: usize) {
        self.0.depth = depth;
    }

    #[inline]
    fn max_depth(&self) -> usize {
        self.0.max_depth
    }
}
