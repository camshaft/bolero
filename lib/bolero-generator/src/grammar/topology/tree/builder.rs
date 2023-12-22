use super::{Node, Tree};
use alloc::vec::Vec;
use core::ops::RangeInclusive;

#[derive(Default)]
pub struct Builder {
    positions: Vec<usize>,
    nodes: Vec<NodeBuilder>,
}

impl Builder {
    #[inline]
    pub fn root(&mut self) -> Scope {
        Scope {
            parents: vec![usize::MAX..=usize::MAX],
            builder: self,
            hit_max_depth: false,
        }
    }

    #[inline]
    pub fn build(self) -> Tree {
        if self.positions.is_empty() {
            return Tree::default();
        }

        let mut positions = self.positions;
        let mut nodes = self.nodes;

        let mut leaves = 0;

        nodes.sort_unstable();

        // record all of the new positions
        for (new_idx, node) in nodes.iter().enumerate() {
            positions[node.position] = new_idx;
            if matches!(node.status, Status::Leaf) {
                leaves += 1;
            }
        }

        let nodes = nodes
            .into_iter()
            .filter_map(|node| {
                let NodeBuilder {
                    mut node, status, ..
                } = node;

                // if it's invalid then remove it
                if matches!(status, Status::Invalid) {
                    return None;
                }

                // update the new parent id
                if let Some(parent) = node.parent() {
                    node.parent = positions[parent].try_into().unwrap();
                }

                Some(node)
            })
            .collect();

        let bits = leaves;
        let bytes = (bits + 7) / 8;

        Tree {
            bytes,
            nodes,
            leaves,
        }
    }

    #[inline]
    fn push_child(&mut self, choice: usize, parent: usize, hit_max_depth: bool) {
        let index = self.positions.len();

        let choice = choice.try_into().unwrap();

        let parent = if parent != usize::MAX {
            let status = &mut self.nodes[parent].status;
            if matches!(status, Status::Leaf) {
                *status = Status::Ancestor;
            }
            parent.try_into().unwrap()
        } else {
            u32::MAX
        };

        let node = Node { choice, parent };
        let node = NodeBuilder {
            node,
            position: index,
            status: if hit_max_depth {
                Status::Invalid
            } else {
                Status::Leaf
            },
        };
        self.nodes.push(node);
        self.positions.push(index);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Status {
    Leaf,
    Ancestor,
    Invalid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct NodeBuilder {
    status: Status,
    position: usize,
    node: Node,
}

type Parents = Vec<RangeInclusive<usize>>;

pub struct Scope<'builder> {
    parents: Parents,
    builder: &'builder mut Builder,
    hit_max_depth: bool,
}

impl<'builder> Scope<'builder> {
    #[inline]
    fn choices<C>(&mut self, choices: C)
    where
        C: IntoIterator<Item = usize>,
    {
        let start = self.builder.positions.len();

        for choice in choices {
            for group in self.parents.iter() {
                for parent in group.clone() {
                    self.builder.push_child(choice, parent, self.hit_max_depth);
                }
            }
        }

        let end = self.builder.positions.len();
        if start < end {
            self.parents.clear();
            self.parents.push(start..=(end - 1));
        }
    }

    #[inline]
    pub fn sum(&mut self, len: usize) -> Sum<'_, 'builder> {
        Sum::new(self, len)
    }

    #[inline]
    pub fn product(&mut self, len: usize) -> Product<'_, 'builder> {
        Product::new(self, len)
    }

    #[inline]
    pub fn list(&mut self, len: RangeInclusive<usize>) -> List<'_, 'builder> {
        List::new(self, len)
    }

    #[inline]
    pub fn on_max_depth(&mut self) {
        for group in self.parents.iter() {
            for parent in group.clone() {
                self.builder.nodes[parent].status = Status::Invalid;
            }
        }
        self.hit_max_depth = true;
    }
}

pub struct Sum<'scope, 'builder> {
    scope: &'scope mut Scope<'builder>,
    sum_parents: Parents,
    next_parents: Parents,
    index: usize,
    hit_max_depth: bool,
}

impl<'scope, 'builder> Sum<'scope, 'builder> {
    #[inline]
    fn new(scope: &'scope mut Scope<'builder>, _len: usize) -> Self {
        let index = 0;
        let sum_parents = scope.parents.clone();
        let next_parents = vec![];
        let hit_max_depth = scope.hit_max_depth;
        Self {
            scope,
            sum_parents,
            next_parents,
            index,
            hit_max_depth,
        }
    }

    #[inline]
    pub fn enter(&mut self) -> Variant<'_, 'scope, 'builder> {
        let index = self.index;
        self.index += 1;

        // restore our original parents
        self.scope.parents.clone_from(&self.sum_parents);
        self.scope.hit_max_depth = self.hit_max_depth;
        self.scope.choices(index..=index);

        Variant { sum: self }
    }
}

impl<'scope, 'builder> Drop for Sum<'scope, 'builder> {
    #[inline]
    fn drop(&mut self) {
        if !self.scope.hit_max_depth {
            core::mem::swap(&mut self.scope.parents, &mut self.next_parents);
        }
        self.scope.hit_max_depth = self.hit_max_depth;
    }
}

pub struct Variant<'sum, 'scope, 'builder> {
    sum: &'sum mut Sum<'scope, 'builder>,
}

impl<'sum, 'scope, 'builder> Variant<'sum, 'scope, 'builder> {
    #[inline]
    pub fn product(&mut self, len: usize) -> Product<'_, 'builder> {
        Product::new(self.sum.scope, len)
    }
}

impl<'sum, 'scope, 'builder> Drop for Variant<'sum, 'scope, 'builder> {
    #[inline]
    fn drop(&mut self) {
        if !self.sum.scope.hit_max_depth {
            self.sum.next_parents.append(&mut self.sum.scope.parents);
        }
        self.sum.scope.hit_max_depth = self.sum.hit_max_depth;
    }
}

pub struct Product<'scope, 'builder> {
    scope: &'scope mut Scope<'builder>,
}

impl<'scope, 'builder> Product<'scope, 'builder> {
    #[inline]
    fn new(scope: &'scope mut Scope<'builder>, _len: usize) -> Self {
        Self { scope }
    }

    #[inline]
    pub fn enter(&mut self) -> &mut Scope<'builder> {
        self.scope
    }
}

pub struct List<'scope, 'builder> {
    scope: &'scope mut Scope<'builder>,
    list_parents: Parents,
    next_parents: Parents,
    hit_max_depth: bool,
}

impl<'scope, 'builder> List<'scope, 'builder> {
    #[inline]
    fn new(scope: &'scope mut Scope<'builder>, _range: RangeInclusive<usize>) -> Self {
        let list_parents = scope.parents.clone();
        let next_parents = vec![];
        let hit_max_depth = scope.hit_max_depth;
        Self {
            scope,
            list_parents,
            next_parents,
            hit_max_depth,
        }
    }

    #[inline]
    pub fn enter(&mut self, len: usize) -> ListItem<'_, 'scope, 'builder> {
        // restore our original parents
        self.scope.parents.clone_from(&self.list_parents);
        self.scope.hit_max_depth = self.hit_max_depth;
        self.scope.choices(len..=len);

        ListItem { list: self }
    }
}

impl<'scope, 'builder> Drop for List<'scope, 'builder> {
    #[inline]
    fn drop(&mut self) {
        //
    }
}

pub struct ListItem<'list, 'scope, 'builder> {
    list: &'list mut List<'scope, 'builder>,
}

impl<'list, 'scope, 'builder> ListItem<'list, 'scope, 'builder> {
    #[inline]
    pub fn scope(&mut self) -> &mut Scope<'builder> {
        self.list.scope
    }
}

impl<'list, 'scope, 'builder> Drop for ListItem<'list, 'scope, 'builder> {
    #[inline]
    fn drop(&mut self) {
        if !self.list.scope.hit_max_depth {
            self.list.next_parents.append(&mut self.list.scope.parents);
        }
        self.list.scope.hit_max_depth = self.list.hit_max_depth;
    }
}
