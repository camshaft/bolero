use std::{io::Read, path::PathBuf};

pub enum TestInput {
    FileTest(FileTest),
    #[cfg(feature = "rand")]
    RngTest(RngTest),
}

impl TestInput {
    pub fn read_into(&self, input: &mut Vec<u8>) {
        match self {
            TestInput::FileTest(t) => t.read_into(input),
            #[cfg(feature = "rand")]
            TestInput::RngTest(t) => t.read_into(input),
        }
    }

    pub fn seed(&self) -> Option<u64> {
        match self {
            TestInput::FileTest(_) => None,
            #[cfg(feature = "rand")]
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

#[cfg(feature = "rand")]
pub struct RngTest {
    pub seed: u64,
    pub max_len: usize,
}

#[cfg(feature = "rand")]
impl RngTest {
    pub fn read_into(&self, input: &mut Vec<u8>) {
        use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};
        let mut rng = StdRng::seed_from_u64(self.seed);
        let len = rng.gen_range(0..self.max_len);
        input.resize(len, 0);
        rng.fill_bytes(input);
    }
}
