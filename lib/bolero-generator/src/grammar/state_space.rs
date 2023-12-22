use super::*;
use core::convert::TryInto;

pub type Estimate = f64;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Kind {
    #[default]
    StateSpace,
    Topology,
}

pub(super) fn estimate(grammar: &Grammar, kind: Kind, options: &Options) -> Estimate {
    let mut estimator = Estimator {
        options,
        kind,
        depth: 0,
    };
    let root = grammar.root();
    estimator.estimate_term(root, grammar)
}

struct Estimator<'a> {
    options: &'a Options,
    kind: Kind,
    depth: usize,
}

impl<'a> Estimator<'a> {
    #[inline]
    fn estimate_term(&mut self, term: &Term, grammar: &Grammar) -> Estimate {
        if !self.options.check_depth(self.depth) {
            return 0.0;
        }

        use Term::*;
        match term {
            Product { id } => {
                self.depth += 1;
                let mut estimates = 1.0;
                let product = &grammar.products[*id];
                for idx in &product.elements {
                    let term = &grammar.terms[*idx];
                    estimates *= self.estimate_term(term, grammar);
                }
                self.depth -= 1;
                estimates
            }
            Sum { id } => {
                self.depth += 1;
                let mut estimates = 0.0;
                let sum = &grammar.sums[*id];
                for element in &sum.elements {
                    let mut product = 1.0;
                    for idx in &element.elements {
                        let term = &grammar.terms[*idx];
                        product *= self.estimate_term(term, grammar);
                    }
                    estimates += product;
                }
                self.depth -= 1;

                estimates
            }
            List { id } => {
                self.depth += 1;
                let list = &grammar.lists[*id];
                let len = match grammar.terms[list.len] {
                    UnsignedInteger { range } => range,
                    _ => panic!("invalid len generator"),
                };
                let value = self.estimate_term(&grammar.terms[list.value], grammar);
                let min = len.min.try_into().unwrap_or(usize::MAX);
                let max = len.max.try_into().unwrap_or(usize::MAX);
                let estimate = Self::estimate_list(min, max, value);
                self.depth -= 1;
                estimate
            }
            Bytes { min, max } => {
                let max = max.or(self.options.max_bytes).unwrap_or(DEFAULT_MAX_BYTES);
                let value = match self.kind {
                    Kind::Topology => 1.0,
                    Kind::StateSpace => 256.0,
                };
                Self::estimate_list(*min as _, max as _, value)
            }
            // if we're only estimating the topology then skip all of the individual values
            _ if matches!(self.kind, Kind::Topology) => 1.0,
            Constant => 1.0,
            Bool => 2.0,
            SignedInteger { range } => {
                if range.empty {
                    0.0
                } else {
                    range.min.abs_diff(range.max).saturating_add(1) as Estimate
                }
            }
            UnsignedInteger { range } => {
                if range.empty {
                    0.0
                } else {
                    range.min.abs_diff(range.max).saturating_add(1) as Estimate
                }
            }
            Float32 { range } => {
                todo!()
            }
            Float64 { range } => {
                todo!()
            }
            Char { range } => {
                if range.empty {
                    0.0
                } else {
                    // TODO remove the char gap
                    let max = range.max.min(char::MAX as u32);
                    range.min.abs_diff(max).saturating_add(1) as Estimate
                }
            }
        }
    }

    #[inline(always)]
    fn estimate_list(min: usize, max: usize, value: Estimate) -> Estimate {
        debug_assert!(min <= max);

        if value < 1.0 {
            return 0.0;
        }

        // just return `1` for the empty list
        if min == 0 && max == 0 {
            return 1.0;
        }

        // special-case with triangular numbers when value is 1.0
        if value == 1.0 {
            // https://en.wikipedia.org/wiki/Triangular_number#Formula
            #[inline(always)]
            fn triangle(v: f64) -> f64 {
                v * (v + 1.0) * 0.5
            }

            let minf = triangle(min as f64 - 1.0);
            let maxf = triangle(max as f64);

            let mut estimate = maxf - minf;

            // include the empty list in the estimate
            if min == 0 {
                estimate += 1.0;
            }

            return estimate;
        }

        // f(value, n) = (1 / (value - 1)) * (value ^ n - 1)
        let coef = 1.0 / (value - 1.0);
        let minf = value.powf(min as f64);
        let maxf = value.powf(max as f64 + 1.0);

        coef * (maxf - minf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_estimate_test() {
        let values = [
            // 1-choice
            (1..=1, 1, 1),
            (0..=1, 1, 2),
            (2..=2, 1, 2),
            (0..=2, 1, 4),
            (3..=3, 1, 3),
            (0..=3, 1, 7),
            (4..=4, 1, 4),
            (0..=4, 1, 11),
            (5..=5, 1, 5),
            (4..=5, 1, 9),
            (3..=5, 1, 12),
            (0..=5, 1, 16),
            // 2-choice
            (0..=0, 2, 1),
            (1..=1, 2, 2),
            (0..=1, 2, 3),
            (2..=2, 2, 4),
            (0..=2, 2, 7),
            (3..=3, 2, 8),
            (0..=3, 2, 15),
            (4..=4, 2, 16),
            (0..=4, 2, 31),
            (5..=5, 2, 32),
            (4..=5, 2, 48),
            (0..=5, 2, 63),
            // 3-choice
            (0..=0, 3, 1),
            (1..=1, 3, 3),
            (0..=1, 3, 4),
            (2..=2, 3, 9),
            (0..=2, 3, 13),
            (3..=3, 3, 27),
            (0..=3, 3, 40),
            (4..=4, 3, 81),
            (0..=4, 3, 121),
            // 4-choice
            (0..=0, 4, 1),
            (1..=1, 4, 4),
            (0..=1, 4, 5),
            (2..=2, 4, 16),
            (0..=2, 4, 21),
            (3..=3, 4, 64),
            (0..=3, 4, 85),
            (4..=4, 4, 256),
            (0..=4, 4, 341),
        ];
        for (range, value, expected) in values {
            assert_eq!(
                Estimator::estimate_list(*range.start(), *range.end(), value as f64),
                expected as f64,
                "range = {range:?}, value = {value}"
            );
        }
    }
}
