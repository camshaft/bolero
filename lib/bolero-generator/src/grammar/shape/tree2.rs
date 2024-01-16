use crate::Driver;
use core::{fmt, ops};

pub trait Output {
    fn push_front(&mut self, choice: usize);
}

impl Output for Vec<usize> {
    fn push_front(&mut self, choice: usize) {
        self.push(choice);
    }
}

#[derive(Clone)]
pub struct Tree {
    depth: usize,
    bytes: usize,
    values: Vec<(usize, usize)>,
}

impl Default for Tree {
    #[inline]
    fn default() -> Self {
        Self {
            depth: 0,
            bytes: 0,
            values: vec![],
        }
    }
}

impl Tree {
    pub fn traverse<D: Driver, O: Output>(&self, driver: &mut D, out: &mut O) {
        let mut index = Self::index_for(driver, self.depth);

        while let Some(idx) = index {
            let (value, parent) = self.values[idx];
            out.push_front(value);
            if parent != usize::MAX {
                index = Some(parent);
            } else {
                index = None;
            }
        }
    }

    fn index_for<D: Driver>(driver: &mut D, mut depth: usize) -> Option<usize> {
        let mut index = 0usize;

        while depth > 8 {
            let level = (depth / 8) - 1;
            let mul = 1 << (depth - 1);
            let b: u8 = driver.gen()?;
            let b = (b >> level) as usize & 0b1;
            index += mul * b;
            depth -= 1;
        }

        let mask = (1 << depth) - 1;
        let b: u8 = driver.gen()?;
        let b = b as usize;
        index += b & mask;

        Some(index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t<O: IntoIterator<Item = S>, S: AsRef<[usize]>>(tree: Tree, outcomes: O) {
        let mut out = vec![];
        for (idx, expected) in outcomes.into_iter().enumerate() {
            let bytes = (idx as u64).to_be_bytes();
            let bytes = &bytes[8 - tree.bytes..];
            let mut driver = crate::driver::ByteSliceDriver::new(bytes, &Default::default());
            tree.traverse(&mut driver, &mut out);
            out.reverse();
            eprintln!("{idx}\t{out:?}");
            assert_eq!(expected.as_ref(), &out);
            out.clear();
        }
    }

    #[cfg(kani)]
    #[kani::proof]
    #[kani::unwind(9)]
    fn index_for_proof() {
        let idx = kani::any::<usize>();
        let depth = kani::any::<usize>();
        kani::assume((1..64).contains(&depth));
        let max_value = (1 << depth) - 1;
        let expected = idx & max_value;
        let byte_len = (depth + 7) / 8;
        let bytes = idx.to_be_bytes();
        let mut driver =
            crate::driver::ByteSliceDriver::new(&bytes[..byte_len], &Default::default());
        let index = Tree::index_for(&mut driver, depth);
        if idx <= max_value {
            assert_eq!(index, Some(expected));
        }
    }

    #[test]
    fn test1() {
        t(
            Tree {
                depth: 2,
                bytes: 1,
                values: vec![
                    (0, usize::MAX),
                    (1, usize::MAX),
                    (2, usize::MAX),
                    (3, usize::MAX),
                ],
            },
            &[&[0], &[1], &[2], &[3]],
        )
    }

    #[test]
    fn test2() {
        t(
            Tree {
                depth: 3,
                bytes: 1,
                values: vec![
                    (0, usize::MAX),
                    (1, usize::MAX),
                    (2, usize::MAX),
                    (3, usize::MAX),
                    (4, usize::MAX),
                    (5, usize::MAX),
                    (6, usize::MAX),
                    (7, usize::MAX),
                ],
            },
            &[&[0], &[1], &[2], &[3]],
        )
    }

    #[test]
    fn test3() {
        t(
            Tree {
                depth: 9,
                bytes: 2,
                values: (0..=256).map(|i| (i, usize::MAX)).collect(),
            },
            (0..=256).map(|v| [v]),
        )
    }
}
