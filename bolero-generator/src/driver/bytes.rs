use super::*;

#[derive(Debug)]
pub struct ByteSliceDriver<'a> {
    mode: DriverMode,
    input: &'a [u8],
}

impl<'a> ByteSliceDriver<'a> {
    pub fn new(input: &'a [u8], mode: Option<DriverMode>) -> Self {
        let mode = mode.unwrap_or(DriverMode::Direct);

        Self { input, mode }
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
    fn fill_bytes(&mut self, bytes: &mut [u8]) -> Option<()> {
        match self.mode {
            DriverMode::Forced => {
                let offset = self.input.len().min(bytes.len());
                let (current, remaining) = self.input.split_at(offset);
                let (bytes_to_fill, bytes_to_zero) = bytes.split_at_mut(offset);
                bytes_to_fill.copy_from_slice(current);
                for byte in bytes_to_zero.iter_mut() {
                    *byte = 0;
                }
                self.input = remaining;
                Some(())
            }
            DriverMode::Direct => {
                if bytes.len() > self.input.len() {
                    return None;
                }
                let (current, remaining) = self.input.split_at(bytes.len());
                bytes.copy_from_slice(current);
                self.input = remaining;
                Some(())
            }
        }
    }
}

impl<'a> Driver for ByteSliceDriver<'a> {
    gen_from_bytes!();
}
