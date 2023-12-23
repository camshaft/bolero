use core::{fmt, ops};

#[derive(Clone)]
pub struct Tree {
    events: Vec<(usize, usize)>,
    left: Vec<usize>,
    right: Vec<usize>,
    parents: Vec<usize>,
    heights: Vec<u16>,
    root: usize,
}

impl Default for Tree {
    #[inline]
    fn default() -> Self {
        Self {
            events: vec![],
            left: vec![],
            right: vec![],
            parents: vec![],
            heights: vec![],
            root: usize::MAX,
        }
    }
}

impl fmt::Debug for Tree {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut t = f.debug_struct("Tree");

        if self.root == usize::MAX {
            t.field("root", &None::<Node>);
        } else {
            t.field(
                "root",
                &Some(Node {
                    idx: self.root,
                    tree: &self,
                }),
            );
        }

        t.finish()
    }
}

// fn rotate_left(&mut self, node: usize) {
//     if let Some(right) = self.right(node) {
//         self.right[node] = self.left[right];
//         if let Some(right_left) = self.left(right) {
//             self.parents[right_left] = node;
//         }

//         let parent = self.parents[node];
//         self.parents[right] = parent;
//         if parent == usize::MAX {
//             self.root = right;
//         } else {
//             if self.left[parent] == node {
//                 self.left[parent] = right;
//             } else {
//                 self.right[parent] = right;
//             }
//         }

//         self.left[right] = node;
//         self.parents[node] = right;

//         self.update_height(node);
//         self.update_height(right);
//     }
// }

macro_rules! rotate {
    ($name:ident, $sibling:ident, $opposite:ident) => {
        fn $name(&mut self, node: usize) {
            if let Some(sibling) = self.$sibling(node) {
                self.$sibling[node] = self.$opposite[sibling];
                if let Some(sibling) = self.$opposite(sibling) {
                    self.parents[sibling] = node;
                }

                let parent = self.parents[node];
                self.parents[sibling] = parent;
                if parent == usize::MAX {
                    self.root = sibling;
                } else {
                    if self.$opposite[parent] == node {
                        self.$opposite[parent] = sibling;
                    } else {
                        self.$sibling[parent] = sibling;
                    }
                }

                self.$opposite[sibling] = node;
                self.parents[node] = sibling;

                self.update_height(node);
                self.update_height(sibling);
            }
        }
    };
}

impl Tree {
    rotate!(rotate_left, right, left);
    rotate!(rotate_right, left, right);

    fn is_empty(&self) -> bool {
        self.heights.is_empty()
    }

    fn len(&self) -> usize {
        self.heights.len()
    }

    fn left(&self, node: usize) -> Option<usize> {
        let node = self.left[node];
        if node == usize::MAX {
            None
        } else {
            Some(node)
        }
    }

    fn right(&self, node: usize) -> Option<usize> {
        let node = self.right[node];
        if node == usize::MAX {
            None
        } else {
            Some(node)
        }
    }

    fn event(&self, node: usize) -> Option<&(usize, usize)> {
        let node = &self.events[node];
        if node.0 == usize::MAX {
            None
        } else {
            Some(node)
        }
    }

    fn update_height(&mut self, node: usize) {
        self.heights[node] = self.computed_height(node);
    }

    fn computed_height(&self, node: usize) -> u16 {
        self.left_height(node).max(self.right_height(node))
    }

    fn left_height(&self, node: usize) -> u16 {
        self.left(node).map_or(0, |node| self.heights[node] + 1)
    }

    fn right_height(&self, node: usize) -> u16 {
        self.right(node).map_or(0, |node| self.heights[node] + 1)
    }

    fn rebalance(&mut self, node: usize) {
        let mut current = Some(node);
        while let Some(node) = current {
            let parent = self.parents[node];
            self.rebalance_node(node);
            current = if parent == usize::MAX {
                None
            } else {
                Some(parent)
            };
        }

        // debug_assert_eq!(
        //     self.event(self.root),
        //     None,
        //     "tried to make an event node the root: {:#?}",
        //     self
        // );
    }

    fn rebalance_once(&mut self, node: usize) {
        let mut current = Some(node);
        while let Some(node) = current {
            let parent = self.parents[node];
            let did_rebalance = self.rebalance_node(node);
            if did_rebalance {
                break;
            }
            current = if parent == usize::MAX {
                None
            } else {
                Some(parent)
            };
        }
    }

    fn rebalance_node(&mut self, node: usize) -> bool {
        let left_height = self.left_height(node);
        let right_height = self.right_height(node);
        debug_assert!(left_height <= right_height + 2);
        debug_assert!(right_height <= left_height + 2);
        if left_height > right_height + 1 {
            // rebalance right
            let left = self.left[node];
            if self.right_height(left) > self.left_height(left) {
                self.rotate_left(left);
            }
            self.rotate_right(node);
            true
        } else if right_height > left_height + 1 {
            // rebalance left
            let right = self.right[node];
            if self.left_height(right) > self.right_height(right) {
                self.rotate_right(right);
            }
            self.rotate_left(node);
            true
        } else {
            self.update_height(node);
            false
        }
    }

    fn push(&mut self) -> usize {
        if self.root == usize::MAX {
            self.root = self.push_impl();
        }

        self.push_impl()
    }

    fn push_impl(&mut self) -> usize {
        let id = self.heights.len();
        self.heights.push(0);
        self.left.push(usize::MAX);
        self.right.push(usize::MAX);
        self.parents.push(usize::MAX);
        self.events.push((usize::MAX, 0));
        id
    }
}

struct Node<'a> {
    idx: usize,
    tree: &'a Tree,
}

impl<'a> fmt::Debug for Node<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut n = f.debug_struct("Node");

        let tree = self.tree;

        n.field("height", &tree.heights[self.idx]);

        if let Some(event) = tree.event(self.idx) {
            n.field("event", event);
        }

        if let Some(idx) = tree.left(self.idx) {
            n.field("left", &Self { idx, tree });
        }

        if let Some(idx) = tree.right(self.idx) {
            n.field("right", &Self { idx, tree });
        }

        n.finish()
    }
}

pub trait Output {
    fn emit(&mut self, index: usize, choice: usize);
}

impl Output for Vec<usize> {
    fn emit(&mut self, index: usize, choice: usize) {
        // if index >= self.len() {
        self.resize(index + 1, 0);
        // }
        self[index] = choice;
    }
}

impl Tree {
    pub fn traverse<O: Output>(&self, bytes: &[u8], o: &mut O) {
        debug_assert_eq!(bytes.len(), self.bytes());

        if bytes.is_empty() || self.is_empty() {
            return;
        }

        let mut idx = Some(self.root);
        let (byte, mut bytes) = bytes.split_at(1);
        let mut byte = byte[0];
        let mut remaining = 8u8;
        while let Some(current) = idx {
            debug_assert!(self.len() > current);

            if let Some((index, choice)) = self.event(current) {
                o.emit(*index, *choice);
            }

            let value = byte & 0b1 == 1;
            if value {
                idx = self.right(current);
            } else {
                idx = self.left(current);
            }

            if let Some(r) = remaining.checked_sub(1) {
                remaining = r;
                byte >>= 1;
            } else {
                let (b, r) = bytes.split_at(1);
                byte = b[0];
                bytes = r;
                remaining = 8;
            }
        }
    }

    pub fn height(&self) -> usize {
        if self.is_empty() {
            0
        } else {
            self.heights[self.root] as _
        }
    }

    pub fn leafs(&self) -> usize {
        self.heights.iter().filter(|v| **v == 0).count()
    }

    pub fn bytes(&self) -> usize {
        (self.height() + 7) / 8
    }

    fn insert_right(&mut self, stack: &mut Vec<usize>, node: usize) {
        let mut parent = usize::MAX;

        if let Some(p) = stack.last().copied() {
            parent = p;
        } else {
            debug_assert_ne!(self.root, usize::MAX);
            parent = self.root;
        }

        while let Some(next) = self.right(parent) {
            parent = next;
        }
        debug_assert_eq!(self.right[parent], usize::MAX);
        debug_assert_eq!(self.parents[node], usize::MAX);
        self.right[parent] = node;
        self.parents[node] = parent;

        self.rebalance(node);
    }

    fn insert_left(&mut self, stack: &mut Vec<usize>, node: usize) {
        let mut parent = usize::MAX;

        if let Some(p) = stack.last().copied() {
            parent = p;
        } else {
            debug_assert_ne!(self.root, usize::MAX);
            parent = self.root;
        }

        while let Some(next) = self.left(parent) {
            parent = next;
        }
        debug_assert_eq!(self.left[parent], usize::MAX);
        debug_assert_eq!(self.parents[node], usize::MAX);
        self.left[parent] = node;
        self.parents[node] = parent;

        self.rebalance(node);
    }
}

#[derive(Clone, Debug, Default)]
pub struct Builder {
    tree: Tree,
    index: usize,
    stack: Vec<usize>,
}

impl Builder {
    pub fn insert<F>(&mut self, choices: usize, mut f: F)
    where
        F: FnMut(&mut Self, usize),
    {
        if choices == 0 {
            return;
        }

        if choices == 1 {
            return f(self, 0);
        }

        let prev_index = self.index;
        self.index += 1;

        let initial_depth = self.stack.len();

        let mut tmp_stack = vec![];

        let last = choices - 1;
        for choice in 0..choices {
            match choice {
                0 => {
                    let id = self.tree.push();
                    self.tree.events[id] = (prev_index, choice);

                    self.tree.insert_left(&mut self.stack, id);
                    tmp_stack.push(id);
                }
                choice if choice == last => {
                    let id = self.tree.push();
                    self.tree.events[id] = (prev_index, choice);

                    self.tree.insert_right(&mut self.stack, id);
                    tmp_stack.push(id);
                }
                _ => {
                    let decision = self.tree.push();
                    self.tree.insert_right(&mut self.stack, decision);
                    self.stack.push(decision);

                    let id = self.tree.push();
                    self.tree.events[id] = (prev_index, choice);
                    self.tree.insert_left(&mut self.stack, id);

                    self.tree.events[id] = (prev_index, choice);
                }
            }
        }

        for (choice, node) in tmp_stack.into_iter().enumerate().rev() {
            self.stack.push(node);
            f(self, choice);
            self.stack.pop();
        }

        self.stack.truncate(initial_depth);
        self.index -= 1;
    }

    pub fn finish(self) -> Tree {
        self.tree
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_test() {
        let mut builder = Builder::default();

        builder.insert(2, |builder, choice| match choice {
            0 => builder.insert(2, |_builder, _choice| {}),
            1 => builder.insert(3, |_builder, _choice| {}),
            _ => panic!(),
        });

        let tree = builder.finish();
        dump(&tree);
        // panic!();
    }

    #[test]
    fn skew_test() {
        let mut builder = Builder::default();

        fn skew(builder: &mut Builder, limit: usize) {
            builder.insert(2, |builder, choice| match choice {
                0 => {}
                1 if limit == 0 => {}
                1 => skew(builder, limit - 1),
                _ => panic!(),
            })
        }

        skew(&mut builder, 3);

        let tree = builder.finish();
        dump(&tree);
        panic!();
    }

    #[test]
    fn wide_test() {
        let mut builder = Builder::default();

        builder.insert(8, |_builder, _choice| {});

        let tree = builder.finish();
        dump(&tree);
        // panic!();
    }

    fn dump(tree: &Tree) {
        let iterations = 1u64 << tree.height();
        let leafs = tree.leafs() as u64;
        eprintln!(
            "iterations: {iterations}, leafs: {leafs}, duplicates: {}",
            iterations - leafs
        );
        eprintln!("{tree:#?}");
        let len = tree.bytes();
        let mut out = vec![];
        let dup = 2;
        for v in 0..(iterations * dup) {
            if v == iterations {
                eprintln!("===");
            }
            let bytes = v.to_le_bytes();
            let bytes = &bytes[..len];
            tree.traverse(bytes, &mut out);
            eprintln!("{:b} {:?}", v, out);
            out.clear();
        }
    }
}
