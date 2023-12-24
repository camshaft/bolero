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
    pub fn traverse<O: Output>(&self, mut bytes: &[u8], out: &mut O) {
        let mut depth = self.depth;
        let mut index = 0usize;

        debug_assert_eq!(bytes.len(), self.bytes);
        while depth > 8 {
            let level = (depth % 8) - 1;
            let mul = 1 << (depth - 1);
            let b = (bytes[0] >> level) as usize & 0b1;
            // eprintln!("\t{b} * {mul} = {}", mul * b);
            index += mul * b;
            depth -= 1;
            bytes = &bytes[1..];
        }

        // eprintln!("\t{:08b}", bytes[0]);

        macro_rules! levels {
            () => {
                levels!([8, 7, 6, 5, 4, 3, 2, 1]);
            };
            ([$($level:literal),*]) => {
                $(
                    levels!($level);
                )*
            };
            ($level:literal) => {
                if depth == $level {
                    let mul = 1 << ($level - 1);
                    let b = (bytes[0] >> ($level - 1)) as usize & 0b1;
                    // eprintln!("\t{b} * {mul} = {}", mul * b);
                    index += mul * b;
                    depth -= 1;
                }
            };
        }

        assert_eq!(bytes.len(), 1);
        // eprintln!("\t{:08b}", bytes[0]);

        // levels!();

        let mask = (1 << depth) - 1;
        let b = bytes[0] as usize;
        eprintln!("\t{b} & {mask:08b} = {}", b & mask);
        index += b & mask;

        let mut index = Some(index);
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t<O: IntoIterator<Item = S>, S: AsRef<[usize]>>(tree: Tree, outcomes: O) {
        let mut out = vec![];
        for (idx, expected) in outcomes.into_iter().enumerate() {
            let bytes = (idx as u64).to_be_bytes();
            let bytes = &bytes[8 - tree.bytes..];
            tree.traverse(&bytes, &mut out);
            out.reverse();
            eprintln!("{idx}\t{out:?}");
            assert_eq!(expected.as_ref(), &out);
            out.clear();
        }
        // panic!();
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
