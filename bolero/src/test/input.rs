use bolero_engine::ForcedRngInput;
use bolero_generator::{driver::ForcedRng, TypeGenerator};
use rand::{rngs::StdRng, SeedableRng};
use std::{io::Read, path::PathBuf};

pub enum TestInput {
    FileTest(FileTest),
    RngTest(RngTest),
}

impl TestInput {
    pub fn seed(&self) -> Option<u64> {
        match self {
            TestInput::FileTest(_) => None,
            TestInput::RngTest(t) => Some(t.seed),
        }
    }
}

pub struct FileTest {
    pub path: PathBuf,
}

impl FileTest {
    pub fn read_into(&self, input: &mut Vec<u8>) {
        std::fs::File::open(&self.path)
            .unwrap()
            .read_to_end(input)
            .unwrap();
    }
}

pub struct RngTest {
    pub seed: u64,
    pub max_len: usize,
}

impl RngTest {
    pub fn input<'a>(&self, buffer: &'a mut Vec<u8>) -> ForcedRngInput<'a, StdRng> {
        ForcedRngInput::new(StdRng::seed_from_u64(self.seed), buffer)
    }

    pub fn buffered_input<'a>(&self, buffer: &'a mut Vec<u8>) -> RngBufferedInput<'a> {
        let rng = StdRng::seed_from_u64(self.seed);
        let driver = RngBufferedDriver { rng, buffer };
        let driver = ForcedRng::new(driver);
        RngBufferedInput {
            driver,
            slice: vec![],
        }
    }
}

pub struct RngBufferedDriver<'a> {
    rng: StdRng,
    buffer: &'a mut Vec<u8>,
}

impl<'a> rand::RngCore for RngBufferedDriver<'a> {
    fn next_u32(&mut self) -> u32 {
        let mut data = [0; 4];
        self.fill_bytes(&mut data);
        u32::from_le_bytes(data)
    }

    fn next_u64(&mut self) -> u64 {
        let mut data = [0; 8];
        self.fill_bytes(&mut data);
        u64::from_le_bytes(data)
    }

    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), rand::Error> {
        self.rng.try_fill_bytes(bytes)?;
        self.buffer.extend_from_slice(bytes);
        Ok(())
    }

    fn fill_bytes(&mut self, bytes: &mut [u8]) {
        self.try_fill_bytes(bytes).unwrap()
    }
}

pub struct RngBufferedInput<'a> {
    driver: ForcedRng<RngBufferedDriver<'a>>,
    slice: Vec<u8>,
}

impl<'a, Output> bolero_engine::TestInput<Output> for RngBufferedInput<'a> {
    type Driver = ForcedRng<RngBufferedDriver<'a>>;

    fn with_slice<F: FnMut(&[u8]) -> Output>(&mut self, f: &mut F) -> Output {
        self.slice.mutate(&mut self.driver);
        f(&self.slice)
    }

    fn with_driver<F: FnMut(&mut Self::Driver) -> Output>(&mut self, f: &mut F) -> Output {
        f(&mut self.driver)
    }
}
