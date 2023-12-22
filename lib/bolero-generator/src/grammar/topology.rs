use super::*;

mod generator;
pub mod selection;
mod tree;

pub use generator::Generator;
pub use selection::Selection;
pub use tree::Tree;

pub(super) fn calculate(grammar: &Grammar, options: &Options) -> Tree {
    let mut tree = tree::Builder::default();
    let root = grammar.root();
    let mut scope = tree.root();

    Builder {
        grammar,
        options,
        depth: 0,
    }
    .build(root, &mut scope);

    tree.build()
}

struct Builder<'a> {
    options: &'a Options,
    grammar: &'a Grammar,
    depth: usize,
}

impl<'a> Builder<'a> {
    fn build(&mut self, term: &Term, scope: &mut tree::builder::Scope) {
        if !self.options.check_depth(self.depth) {
            scope.on_max_depth();
            return;
        }

        use Term::*;
        match term {
            Product { id } => {
                self.depth += 1;

                let node = &self.grammar.products[*id];
                let mut product = scope.product(node.elements.len());
                for idx in &node.elements {
                    let term = &self.grammar.terms[*idx];
                    let child = product.enter();
                    self.build(term, child);
                }

                self.depth -= 1;
            }
            Sum { id } => {
                self.depth += 1;

                let node = &self.grammar.sums[*id];
                let mut sum = scope.sum(node.elements.len());
                for child in &node.elements {
                    let mut scope = sum.enter();
                    let mut product = scope.product(child.elements.len());
                    for idx in &child.elements {
                        let term = &self.grammar.terms[*idx];
                        let child = product.enter();
                        self.build(term, child);
                    }
                }

                self.depth -= 1;
            }
            List { id } => {
                self.depth += 1;

                let list = &self.grammar.lists[*id];
                let len = match self.grammar.terms[list.len] {
                    UnsignedInteger { range } => range,
                    _ => panic!("invalid len generator"),
                };
                if len.empty {
                    panic!("invalid list length");
                }
                let term = &self.grammar.terms[list.value];
                let min = len.min.try_into().expect("min list exceeds usize range");
                let max = len.max.try_into().expect("max list exceeds usize range");
                let mut list = scope.list(min..=max);
                for len in min..=max {
                    let mut value = list.enter(len);
                    let scope = value.scope();
                    for _ in 0..len {
                        self.build(term, scope);
                    }
                }

                self.depth -= 1;
            }
            Bytes { min, max } => {
                let min = *min;
                let max = max.or(self.options.max_bytes).unwrap_or(DEFAULT_MAX_BYTES);
                if max < min {
                    panic!("invalid bytes length");
                }
                let mut list = scope.list(min..=max);
                for len in min..=max {
                    // no sub-generator shapes for bytes
                    let _ = list.enter(len);
                }
            }
            _ => {}
        }
    }
}
