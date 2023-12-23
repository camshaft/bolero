use core::{fmt, ops};

#[derive(Clone)]
pub struct Tree {
    left: Vec<usize>,
    right: Vec<usize>,
    parents: Vec<usize>,
    heights: Vec<u16>,
    values: Vec<(usize, usize)>,
    leaves: Vec<bool>,
    root: usize,
}

impl Default for Tree {
    #[inline]
    fn default() -> Self {
        Self {
            left: vec![],
            right: vec![],
            parents: vec![],
            heights: vec![],
            values: vec![],
            leaves: vec![],
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

    fn value(&self, node: usize) -> usize {
        self.values[node].0
    }

    fn parent_value(&self, node: usize) -> Option<usize> {
        let node = self.values[node].1;
        if node == usize::MAX {
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

    fn push(&mut self, choice: usize, parent_value: usize) -> usize {
        let id = self.heights.len();
        self.heights.push(0);
        self.left.push(usize::MAX);
        self.right.push(usize::MAX);
        self.parents.push(usize::MAX);
        self.values.push((choice, parent_value));
        self.leaves.push(false);

        id
    }

    fn insert_right(&mut self, node: usize, mut parent: usize) {
        if self.root == usize::MAX {
            self.root = node;
            return;
        }

        if parent == usize::MAX {
            parent = self.root;
        }

        while let Some(next) = self.right(parent) {
            parent = next;
        }
        self.right[parent] = node;
        self.parents[node] = parent;

        //self.rebalance(node);
    }

    fn insert_left(&mut self, node: usize, mut parent: usize) {
        if self.root == usize::MAX {
            self.root = node;
            return;
        }

        if parent == usize::MAX {
            parent = self.root;
        }

        while let Some(next) = self.left(parent) {
            parent = next;
        }
        self.left[parent] = node;
        self.parents[node] = parent;

        //self.rebalance(node);
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

        if tree.leaves[self.idx] {
            let mut idx = Some(self.idx);
            let mut path = vec![];
            while let Some(id) = idx {
                path.push(tree.value(id));
                idx = tree.parent_value(id);
            }
            path.reverse();

            if !path.is_empty() {
                n.field("value", &path);
            }
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
    fn emit(&mut self, choice: usize);
}

impl Output for Vec<usize> {
    fn emit(&mut self, choice: usize) {
        self.push(choice);
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
        let mut selected = usize::MAX;

        while let Some(current) = idx {
            debug_assert!(self.len() > current);
            if self.leaves[current] {
                selected = current;
            }

            // eprintln!("{byte:b}, {remaining}, {}", byte >> remaining);
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

        while selected != usize::MAX {
            let (value, parent_value) = self.values[selected];
            o.emit(value);
            selected = parent_value;
        }
    }

    pub fn height(&self) -> usize {
        if self.is_empty() {
            0
        } else {
            self.heights[self.root] as _
        }
    }

    pub fn choices(&self) -> usize {
        self.heights.iter().filter(|v| **v == 0).count()
    }

    pub fn bytes(&self) -> usize {
        (self.height() + 7) / 8
    }
}

#[derive(Clone, Debug)]
pub struct Builder {
    tree: Tree,
    parent_node: usize,
    parent_value: usize,
    is_leaf: bool,
    insert_left: bool,
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            tree: Default::default(),
            parent_node: usize::MAX,
            parent_value: usize::MAX,
            is_leaf: true,
            insert_left: true,
        }
    }
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

        let mut parent_node = self.parent_node;
        for choice in 0..choices {
            let is_first = choice == 0;
            let is_last = choice == choices - 1;

            let new_parent_node;
            if !is_first {
                new_parent_node = self.tree.push(choice, self.parent_value);
                self.tree.insert_right(new_parent_node, parent_node);
            } else {
                new_parent_node = parent_node;
            }

            let id;
            if !is_last {
                id = self.tree.push(choice, self.parent_node);
                self.tree.insert_left(id, new_parent_node);
            } else {
                id = new_parent_node;
            }

            let prev_node = core::mem::replace(&mut self.parent_node, id);
            let prev_value = core::mem::replace(&mut self.parent_value, id);

            self.is_leaf = true;
            f(self, choice);

            self.parent_node = prev_node;
            self.parent_value = prev_value;

            if self.is_leaf {
                //self.tree.leaves[id] = true;
                self.tree.leaves[id] = true;
            }

            parent_node = new_parent_node;
        }

        self.is_leaf = false;
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
        check(&tree, &[&[0, 0], &[0, 1], &[1, 0], &[1, 1], &[1, 2]]);
    }

    fn skew(builder: &mut Builder, limit: usize) {
        builder.insert(2, |builder, choice| match choice {
            0 => {}
            1 if limit == 0 => {}
            1 => skew(builder, limit - 1),
            _ => panic!(),
        })
    }

    #[test]
    fn skew_2_test() {
        let mut builder = Builder::default();

        skew(&mut builder, 2);

        let tree = builder.finish();
        check(&tree, &[&[0], &[1, 0], &[1, 1, 0], &[1, 1, 1]]);
    }

    #[test]
    fn skew_3_test() {
        let mut builder = Builder::default();

        skew(&mut builder, 3);

        let tree = builder.finish();
        check(
            &tree,
            &[&[0], &[1, 0], &[1, 1, 0], &[1, 1, 1, 0], &[1, 1, 1, 1]],
        );
    }

    #[test]
    fn skew_4_test() {
        let mut builder = Builder::default();

        skew(&mut builder, 4);

        let tree = builder.finish();
        check(
            &tree,
            &[
                &[0],
                &[1, 0],
                &[1, 1, 0],
                &[1, 1, 1, 0],
                &[1, 1, 1, 1, 0],
                &[1, 1, 1, 1, 1],
            ],
        );
    }

    #[test]
    fn balanced_test() {
        let mut builder = Builder::default();

        builder.insert(2, |builder, choice| match choice {
            0 => builder.insert(2, |_builder, _choice| {}),
            1 => builder.insert(2, |_builder, _choice| {}),
            _ => panic!(),
        });

        let tree = builder.finish();
        check(&tree, &[&[0, 0], &[0, 1], &[1, 0], &[1, 1]]);
    }

    #[test]
    fn unbalanced_test() {
        let mut builder = Builder::default();

        builder.insert(2, |builder, choice| match choice {
            0 => builder.insert(2, |_builder, _choice| {}),
            1 => builder.insert(10, |_builder, _choice| {}),
            _ => panic!(),
        });

        let tree = builder.finish();
        check(
            &tree,
            &[
                &[0, 0],
                &[0, 1],
                &[1, 0],
                &[1, 1],
                &[1, 2],
                &[1, 3],
                &[1, 4],
                &[1, 5],
                &[1, 6],
                &[1, 7],
                &[1, 8],
                &[1, 9],
            ],
        );
    }

    #[test]
    fn wide_test() {
        let mut builder = Builder::default();

        builder.insert(8, |_builder, _choice| {});

        let tree = builder.finish();
        check(&tree, &[&[0], &[1], &[2], &[3], &[4], &[5], &[6], &[7]]);
    }

    fn check(tree: &Tree, expected: &[&[usize]]) {
        let iterations = 1u64 << tree.height();
        let choices = tree.choices() as u64;
        eprintln!("iterations: {iterations} choices: {choices}",);
        eprintln!("{tree:#?}");
        let len = tree.bytes();
        let mut out = vec![];
        let dup = 2;

        let mut actual = std::collections::BTreeSet::new();

        for v in 0..(iterations * dup) {
            if v == iterations {
                eprintln!("===");
            }
            let bytes = v.to_le_bytes();
            let bytes = &bytes[..len];
            tree.traverse(bytes, &mut out);
            out.reverse();
            eprintln!("{:b} {:?}", v, out);
            actual.insert(out.clone());
            out.clear();
        }

        for expected in expected {
            assert!(
                actual.remove(*expected),
                "expected {expected:?} to be present"
            );
        }

        assert!(actual.is_empty(), "{actual:?}");
    }
}
