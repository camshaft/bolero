use super::*;
use core::convert::TryInto;

#[derive(Clone, Debug)]
pub enum Estimate<Value = u128> {
    Value(Value),
    // https://en.wikipedia.org/wiki/Triangular_number
    Triangle { min: usize, max: usize },
    Add(Vec<Estimate<Value>>),
    Mul(Vec<Estimate<Value>>),
}

impl Estimate {
    pub(super) fn reduce(mut self) -> Self {
        match &mut self {
            Self::Value(_) => self,
            Self::Triangle { min, max } if min == max => Self::Value(*min as u128),
            Self::Add(el) if el.is_empty() => Self::Value(0),
            Self::Mul(el) if el.is_empty() => Self::Value(1),
            Self::Add(el) | Self::Mul(el) if el.len() == 1 => el.pop().unwrap(),
            _ => self,
        }
    }

    pub(super) fn push(&mut self, estimate: Estimate) {
        match (self, estimate) {
            (Self::Value(_) | Self::Triangle { .. }, _) => unreachable!(),
            (Self::Add(_), Self::Value(0)) => {}
            (Self::Add(lhs), Self::Add(rhs)) => {
                lhs.extend(rhs);
            }
            (Self::Add(lhs), estimate) => {
                lhs.push(estimate);
            }
            (Self::Mul(_), Self::Value(1)) => {}
            (Self::Mul(lhs), Self::Mul(rhs)) => {
                lhs.extend(rhs);
            }
            (Self::Mul(lhs), estimate) => {
                lhs.push(estimate);
            }
        }
    }

    pub fn eval(&self) -> Option<u128> {
        match self {
            Self::Value(v) => Some(*v),
            Self::Triangle { min, max } => {
                // TODO make this more efficient with the formula
                let mut v = 0u128;
                for item in *min..=*max {
                    v = v.checked_add(item as u128)?;
                }
                Some(v)
            }
            Self::Add(items) => {
                let mut v = 0u128;
                for item in items {
                    v = v.checked_add(item.eval()?)?;
                }
                Some(v)
            }
            Self::Mul(items) => {
                let mut v = 1u128;
                for item in items {
                    v = v.checked_mul(item.eval()?)?;
                }
                Some(v)
            }
        }
    }
}

impl Estimate<f64> {
    pub(super) fn reduce_f64(mut self) -> Self {
        match &mut self {
            Self::Value(_) => self,
            Self::Triangle { min, max } if min == max => Self::Value(*min as f64),
            Self::Add(el) if el.is_empty() => Self::Value(0.0),
            Self::Mul(el) if el.is_empty() => Self::Value(1.0),
            Self::Add(el) | Self::Mul(el) if el.len() == 1 => el.pop().unwrap(),
            _ => self,
        }
    }

    pub(super) fn push_f64(&mut self, estimate: Self) {
        match (self, estimate) {
            (Self::Value(_) | Self::Triangle { .. }, _) => unreachable!(),
            (Self::Add(_), Self::Value(0.0)) => {}
            (Self::Add(lhs), Self::Add(rhs)) => {
                lhs.extend(rhs);
            }
            (Self::Add(lhs), estimate) => {
                lhs.push(estimate);
            }
            (Self::Mul(_), Self::Value(1.0)) => {}
            (Self::Mul(lhs), Self::Mul(rhs)) => {
                lhs.extend(rhs);
            }
            (Self::Mul(lhs), estimate) => {
                lhs.push(estimate);
            }
        }
    }

    pub fn eval_f64(&self) -> f64 {
        match self {
            Self::Value(v) => *v,
            Self::Triangle { min, max } => {
                // TODO make this more efficient with the formula
                let mut v = 0.0;
                for item in *min..=*max {
                    v += item as f64;
                }
                v
            }
            Self::Add(items) => {
                let mut v = 0.0;
                for item in items {
                    v += item.eval_f64();
                }
                v
            }
            Self::Mul(items) => {
                let mut v = 1.0;
                for item in items {
                    v *= item.eval_f64();
                }
                v
            }
        }
    }
}

pub(super) fn estimate(grammar: &Grammar, options: &Options) -> Estimate {
    let mut estimator = Estimator { options, depth: 0 };
    let root = grammar.root();
    estimator.estimate_term(root, grammar)
}

struct Estimator<'a> {
    options: &'a Options,
    depth: usize,
}

impl<'a> Estimator<'a> {
    fn estimate_term(&mut self, term: &Term, grammar: &Grammar) -> Estimate {
        if self
            .options
            .max_depth
            .map_or(false, |max_depth| max_depth < self.depth)
        {
            return Estimate::Value(1);
        }

        use Term::*;
        match term {
            Constant => Estimate::Value(1),
            Bool => Estimate::Value(2),
            SignedInteger { range } => {
                if range.empty {
                    Estimate::Value(0)
                } else {
                    Estimate::Value(range.min.abs_diff(range.max).saturating_add(1))
                }
            }
            UnsignedInteger { range } => {
                if range.empty {
                    Estimate::Value(0)
                } else {
                    Estimate::Value(range.min.abs_diff(range.max).saturating_add(1))
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
                    Estimate::Value(0)
                } else {
                    // TODO remove the char gap
                    let max = range.max.min(char::MAX as u32);
                    Estimate::Value(range.min.abs_diff(max).saturating_add(1) as _)
                }
            }
            Product { id } => {
                self.depth += 1;
                let mut estimates = Estimate::Mul(vec![]);
                let product = &grammar.products[*id];
                for idx in &product.elements {
                    let term = &grammar.terms[*idx];
                    estimates.push(self.estimate_term(term, grammar));
                }
                self.depth -= 1;
                estimates.reduce()
            }
            Sum { id } => {
                self.depth += 1;
                let mut estimates = Estimate::Add(vec![]);
                let sum = &grammar.sums[*id];
                for element in &sum.elements {
                    let mut product = Estimate::Mul(vec![]);
                    for idx in &element.elements {
                        let term = &grammar.terms[*idx];
                        product.push(self.estimate_term(term, grammar));
                    }
                    estimates.push(product.reduce());
                }
                self.depth -= 1;

                estimates.reduce()
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
                let value = Estimate::Value(256);
                Self::estimate_list(*min as _, max as _, value)
            }
        }
    }

    fn estimate_list(mut min: usize, max: usize, value: Estimate) -> Estimate {
        debug_assert!(min <= max);

        if min == 0 && max == 0 {
            return Estimate::Value(1);
        }

        let mut has_zero_sized_list = min == 0;

        if has_zero_sized_list {
            min += 1;
        }

        let mut lens = Estimate::Triangle { min, max };

        let mut estimate = Estimate::Mul(vec![]);
        estimate.push(value);
        estimate.push(lens);

        if has_zero_sized_list {
            estimate = Estimate::Add(vec![estimate.reduce(), Estimate::Value(1)]);
        }

        estimate.reduce()
    }
}
