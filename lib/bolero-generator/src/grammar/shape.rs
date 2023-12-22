use super::*;
use core::fmt;

pub mod tree;

#[derive(Clone)]
pub enum Shape {
    Constant,
    Product {
        elements: Vec<Shape>,
        descendant_outcomes: usize,
    },
    Sum {
        elements: Vec<Shape>,
        descendant_max_outcomes: usize,
    },
    List {
        min: usize,
        max: usize,
        value: Box<Shape>,
        descendant_max_outcomes: usize,
    },
}

impl fmt::Debug for Shape {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let alt = f.alternate();

        let mut f = match self {
            Self::Constant => f.debug_struct("Constant"),
            Self::Product { elements, .. } => {
                let mut f = f.debug_struct("Product");
                f.field("elements", elements);
                f
            }
            Self::Sum { elements, .. } => {
                let mut f = f.debug_struct("Sum");
                f.field("elements", elements);
                f
            }
            Self::List { .. } => f.debug_struct("List"),
        };

        if alt {
            f.field("outcomes", &self.outcomes())
                .field("descendant_outcomes", &self.descendant_outcomes())
                .field("max_outcomes", &self.max_outcomes())
                .field("bits", &self.bits())
                .field("bytes", &self.bytes())
                .field("total_outcomes", &self.total_outcomes().eval())
                .field(
                    "expected_bits",
                    &self.total_outcomes_f64().eval_f64().log2().ceil(),
                );
        }

        f.finish()
    }
}

impl Shape {
    pub fn bits(&self) -> usize {
        (self.max_outcomes() + 1) / 2
    }

    pub fn bytes(&self) -> usize {
        (self.bits() + 7) / 8
    }

    pub fn max_outcomes(&self) -> usize {
        self.outcomes() + self.descendant_outcomes()
    }

    pub fn total_outcomes(&self) -> super::state_space::Estimate {
        use super::state_space::Estimate;
        match self {
            Self::Constant => Estimate::Value(1),
            Self::Product { elements, .. } => {
                let mut v = Estimate::Mul(vec![]);
                for el in elements {
                    v.push(el.total_outcomes());
                }
                v.reduce()
            }
            Self::Sum { elements, .. } => {
                let mut v = Estimate::Add(vec![]);
                for el in elements {
                    v.push(el.total_outcomes());
                }
                v.reduce()
            }
            Self::List { value, .. } => {
                // TODO
                todo!()
            }
        }
    }

    pub fn total_outcomes_f64(&self) -> super::state_space::Estimate<f64> {
        use super::state_space::Estimate;
        match self {
            Self::Constant => Estimate::Value(1.0),
            Self::Product { elements, .. } => {
                let mut v = Estimate::Mul(vec![]);
                for el in elements {
                    v.push_f64(el.total_outcomes_f64());
                }
                v.reduce_f64()
            }
            Self::Sum { elements, .. } => {
                let mut v = Estimate::Add(vec![]);
                for el in elements {
                    v.push_f64(el.total_outcomes_f64());
                }
                v.reduce_f64()
            }
            Self::List { value, .. } => {
                // TODO
                todo!()
            }
        }
    }

    pub fn outcomes(&self) -> usize {
        0
        /*
        match self {
            Self::Constant => 0,
            Self::Product { elements, .. } => 0,
            Self::Sum { elements, .. } => elements.len(),
            Self::List { value, .. } => {
                // TODO
                todo!()
            }
        }
        */
    }

    pub fn descendant_outcomes(&self) -> usize {
        match self {
            Self::Constant => 1,
            Self::Product {
                descendant_outcomes,
                ..
            } => *descendant_outcomes,
            Self::Sum {
                descendant_max_outcomes,
                ..
            } => *descendant_max_outcomes,
            Self::List {
                descendant_max_outcomes,
                ..
            } => *descendant_max_outcomes,
        }
    }

    fn push(&mut self, shape: Shape) {
        match self {
            Self::Constant => unreachable!(),
            Self::Product {
                elements,
                descendant_outcomes,
            } => match shape {
                Self::Constant => {}
                Self::Product {
                    elements: els,
                    descendant_outcomes: outcomes,
                } => {
                    elements.extend(els);
                    *descendant_outcomes *= outcomes;
                }
                shape => {
                    *descendant_outcomes *= shape.max_outcomes();
                    elements.push(shape)
                }
            },
            Self::Sum {
                elements,
                descendant_max_outcomes,
            } => {
                *descendant_max_outcomes += shape.max_outcomes();
                elements.push(shape);
            }
            Self::List { value, .. } => {
                // TODO
                todo!()
            }
        }
    }

    fn reduce(self) -> Self {
        match self {
            Self::Product {
                mut elements,
                descendant_outcomes,
            } => {
                if elements.is_empty() {
                    Shape::Constant
                } else if elements.len() == 1 {
                    elements.pop().unwrap()
                } else {
                    Shape::Product {
                        elements,
                        descendant_outcomes,
                    }
                }
            }
            Self::Sum {
                mut elements,
                descendant_max_outcomes,
            } => {
                if elements.is_empty() {
                    Self::Constant
                } else if elements.len() == 1 {
                    elements.pop().unwrap()
                } else {
                    Self::Sum {
                        elements,
                        descendant_max_outcomes,
                    }
                }
            }
            other => other,
        }
    }
}

pub(super) fn calculate(grammar: &Grammar, options: &Options) -> Shape {
    let mut builder = Builder { options, depth: 0 };
    let root = grammar.root();
    builder.build(root, grammar)
}

struct Builder<'a> {
    options: &'a Options,
    depth: usize,
}

impl<'a> Builder<'a> {
    fn build(&mut self, term: &Term, grammar: &Grammar) -> Shape {
        if self
            .options
            .max_depth
            .map_or(false, |max_depth| max_depth < self.depth)
        {
            return Shape::Constant;
        }

        use Term::*;
        match term {
            Product { id } => {
                self.depth += 1;
                let mut product = Shape::Product {
                    descendant_outcomes: 1,
                    elements: vec![],
                };
                let node = &grammar.products[*id];
                for idx in &node.elements {
                    let term = &grammar.terms[*idx];
                    product.push(self.build(term, grammar));
                }
                self.depth -= 1;
                product.reduce()
            }
            Sum { id } => {
                self.depth += 1;

                let mut elements = Shape::Sum {
                    descendant_max_outcomes: 0,
                    elements: vec![],
                };
                let mut descendants = 0;

                let node = &grammar.sums[*id];
                for child in &node.elements {
                    let mut product = Shape::Product {
                        descendant_outcomes: 1,
                        elements: vec![],
                    };
                    for idx in &child.elements {
                        let term = &grammar.terms[*idx];
                        product.push(self.build(term, grammar));
                    }

                    elements.push(product.reduce());
                }

                self.depth -= 1;

                elements.reduce()
            }
            List { id } => {
                self.depth += 1;
                todo!("{:?}", id);
                // TODO
                self.depth -= 1;
                Shape::Constant
            }
            Bytes { min, max } => {
                todo!("{:?} {:?}", min, max);
                // TODO
                Shape::Constant
            }
            _ => Shape::Constant,
        }

        /*
                List { id } => {
                    self.depth += 1;
                    let list = &grammar.lists[*id];
                    let mut lens = Estimate::Add(vec![]);
                    let len = match grammar.terms[list.len] {
                        UnsignedInteger { range } => range,
                        _ => panic!("invalid len generator"),
                    };
                    let value = self.estimate_term(&grammar.terms[list.value], grammar);
                    let estimate = Self::estimate_list(len.min, len.max, value);
                    self.depth -= 1;
                    estimate
                }
                Bytes { min, max } => {
                    let max = max.or(self.options.max_bytes).unwrap_or(DEFAULT_MAX_BYTES);
                    let value = Estimate::Value(256);
                    Self::estimate_list(*min as _, max as _, value)
                }
            }
        */
    }
}
