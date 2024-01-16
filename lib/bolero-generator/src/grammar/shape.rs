use super::*;
use core::fmt;

//pub mod tree;
pub mod tree2;

#[derive(Clone, Debug)]
pub struct Shape {
    leaves: f64,
    bytes: Option<usize>,
}

#[derive(Clone, Debug, Default)]
struct Nodes {
    nodes: Vec<Node>,
}

impl Nodes {
    fn push(&mut self, node: Node) -> usize {
        let id = self.nodes.len();
        self.nodes.push(node);
        id
    }
}

#[derive(Clone, Debug)]
struct Variant {
    leaves: f64,
}

#[derive(Clone, Debug)]
pub enum Node {
    Constant,
    Product {
        leaves: f64,
        children: Vec<usize>,
    },
    Sum {
        leaves: f64,
        bits: usize,
        children: Vec<usize>,
    },
    List {
        leaves: f64,
        bits: usize,
        min: usize,
        max: usize,
        value: usize,
    },
    Bytes {
        leaves: f64,
        bits: usize,
        min: usize,
        max: usize,
    },
}

impl Shape {
    pub fn bytes(&self) -> usize {
        self.bytes.unwrap()
    }
}

pub(super) fn calculate(grammar: &Grammar, options: &Options) -> Shape {
    let mut builder = Builder {
        options,
        nodes: Default::default(),
        depth: 0,
    };
    let root = grammar.root();
    let leaves = builder.build(root, grammar);

    /*
    let bytes = (leaves.log2() / 8.0).ceil();
    let conv = bytes as usize;
    let bytes = if conv as f64 == bytes {
        Some(conv)
    } else {
        None
    };

    Shape { leaves, bytes }
    */
    Shape {
        leaves,
        bytes: Some(1),
    }
}

struct Builder<'a> {
    options: &'a Options,
    nodes: Nodes,
    depth: usize,
}

impl<'a> Builder<'a> {
    fn build(&mut self, term: &Term, grammar: &Grammar) -> f64 {
        if self
            .options
            .max_depth
            .map_or(false, |max_depth| max_depth < self.depth)
        {
            return 1.0;
        }

        use Term::*;
        match term {
            Product { id } => {
                self.depth += 1;
                let mut product = 1.0;
                let node = &grammar.products[*id];
                for idx in &node.elements {
                    let term = &grammar.terms[*idx];
                    product *= self.build(term, grammar);
                }
                self.depth -= 1;
                product
            }
            Sum { id } => {
                self.depth += 1;

                let mut elements = 0.0;
                let mut variants = vec![];

                let node = &grammar.sums[*id];
                for child in &node.elements {
                    let mut product = 1.0;
                    for idx in &child.elements {
                        let term = &grammar.terms[*idx];
                        product *= self.build(term, grammar);
                    }

                    let variant = Variant { leaves: product };
                    variants.push(variant);

                    elements += product;
                }

                self.depth -= 1;
                dbg!(variants);

                elements
            }
            List { id } => {
                self.depth += 1;
                let list = &grammar.lists[*id];
                let len = match grammar.terms[list.len] {
                    UnsignedInteger { range } => range,
                    _ => panic!("invalid len generator"),
                };
                let value = self.build(&grammar.terms[list.value], grammar);
                let estimate = Self::estimate_list(len.min as _, len.max as _, value);
                self.depth -= 1;
                estimate
            }
            Bytes { min, max } => {
                let max = max.or(self.options.max_bytes).unwrap_or(DEFAULT_MAX_BYTES);
                let value = 1.0;
                Self::estimate_list(*min as _, max as _, value)
            }
            _ => 1.0,
        }
    }

    fn estimate_list(mut min: usize, max: usize, value: f64) -> f64 {
        debug_assert!(min <= max);

        if min == 0 && max == 0 {
            return 1.0;
        }

        let mut estimate = 0.0;
        if min == 0 {
            estimate += 1.0;
        }

        let mut lens = super::state_space::Estimate::Triangle { min, max }.eval_f64();
        estimate += value * lens;

        estimate
    }
}
