use core::{fmt, ops};

#[derive(Clone)]
pub struct Tree {
    events: Vec<(usize, usize)>,
    lefts: Vec<usize>,
    rights: Vec<usize>,
    heights: Vec<u16>,
    root: usize,
}

impl Default for Tree {
    #[inline]
    fn default() -> Self {
        Self {
            events: vec![],
            lefts: vec![],
            rights: vec![],
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

impl Tree {
    fn is_empty(&self) -> bool {
        self.heights.is_empty()
    }

    fn len(&self) -> usize {
        self.heights.len()
    }

    fn left(&self, node: usize) -> Option<usize> {
        let node = self.lefts[node];
        if node == usize::MAX {
            None
        } else {
            Some(node)
        }
    }

    fn right(&self, node: usize) -> Option<usize> {
        let node = self.rights[node];
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

    fn rotate_left(&mut self, node: usize, parents: &mut [usize]) {
        if let Some(right) = self.right(node) {
            self.rights[node] = self.lefts[right];
            if let Some(right_left) = self.left(right) {
                parents[right_left] = node;
            }

            let parent = parents[node];
            parents[right] = parent;
            if parent == usize::MAX {
                self.root = right;
            } else {
                if self.lefts[parent] == node {
                    self.lefts[parent] = right;
                } else {
                    self.rights[parent] = right;
                }
            }

            self.lefts[right] = node;
            parents[node] = right;

            self.update_height(node);
            self.update_height(right);
        }
    }

    fn rotate_right(&mut self, node: usize, parents: &mut [usize]) {
        if let Some(left) = self.left(node) {
            self.lefts[node] = self.rights[left];
            if let Some(left_right) = self.right(left) {
                parents[left_right] = node;
            }

            let parent = parents[node];
            parents[left] = parent;
            if parent == usize::MAX {
                self.root = left;
            } else {
                if self.lefts[parent] == node {
                    self.lefts[parent] = left;
                } else {
                    self.rights[parent] = left;
                }
            }

            self.rights[left] = node;
            parents[node] = left;

            self.update_height(node);
            self.update_height(left);
        }
    }

    fn rebalance(&mut self, node: usize, parents: &mut [usize]) {
        let mut current = Some(node);
        while let Some(node) = current {
            let parent = parents[node];
            self.rebalance_node(node, parents);
            current = if parent == usize::MAX {
                None
            } else {
                Some(parent)
            };
        }
    }

    fn rebalance_once(&mut self, node: usize, parents: &mut [usize]) {
        let mut current = Some(node);
        while let Some(node) = current {
            let parent = parents[node];
            let did_rebalance = self.rebalance_node(node, parents);
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

    fn rebalance_node(&mut self, node: usize, parents: &mut [usize]) -> bool {
        let left_height = self.left_height(node);
        let right_height = self.right_height(node);
        debug_assert!(left_height <= right_height + 2);
        debug_assert!(right_height <= left_height + 2);
        if left_height > right_height + 1 {
            // rebalance right
            let left = self.lefts[node];
            if self.right_height(left) > self.left_height(left) {
                self.rotate_left(left, parents);
            }
            self.rotate_right(node, parents);
            true
        } else if right_height > left_height + 1 {
            // rebalance left
            let right = self.rights[node];
            if self.left_height(right) > self.right_height(right) {
                self.rotate_right(right, parents);
            }
            self.rotate_left(node, parents);
            true
        } else {
            self.update_height(node);
            false
        }
    }

    fn push(&mut self, parents: &mut Vec<usize>) -> usize {
        let id = self.heights.len();
        debug_assert_eq!(self.heights.len(), parents.len());
        self.heights.push(0);
        self.lefts.push(usize::MAX);
        self.rights.push(usize::MAX);
        parents.push(usize::MAX);
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

            let right = self.right(current);
            let left = self.left(current);

            {
                let (index, choice) = self.events[current];
                if index != usize::MAX {
                    o.emit(index, choice);
                }
            }

            let value = byte & 0b1 == 1;
            if value {
                idx = right;
            } else {
                idx = left;
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

    pub fn bytes(&self) -> usize {
        (self.height() + 7) / 8
    }

    fn insert_right(&mut self, stack: &mut Vec<usize>, parents: &mut [usize], node: usize) {
        let mut parent = usize::MAX;

        if let Some(p) = stack.last().copied() {
            parent = p;
        } else {
            if self.root == usize::MAX {
                self.root = node;
                return;
            } else {
                parent = self.root;
            }
        }

        while let Some(next) = self.right(parent) {
            parent = next;
        }
        self.rights[parent] = node;
        parents[node] = parent;

        self.rebalance_once(node, parents);
    }

    fn insert_left(&mut self, stack: &mut Vec<usize>, parents: &mut [usize], node: usize) {
        let mut parent = usize::MAX;

        if let Some(p) = stack.last().copied() {
            parent = p;
        } else {
            if self.root == usize::MAX {
                self.root = node;
                return;
            } else {
                parent = self.root;
            }
        }

        while let Some(next) = self.left(parent) {
            parent = next;
        }
        self.lefts[parent] = node;
        parents[node] = parent;

        self.rebalance_once(node, parents);
    }
}

#[derive(Clone, Debug, Default)]
pub struct Builder {
    tree: Tree,
    index: usize,
    stack: Vec<usize>,
    parents: Vec<usize>,
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

        let last = choices - 1;
        for choice in 0..choices {
            if choice == last {
                let id = self.tree.push(&mut self.parents);
                self.tree
                    .insert_right(&mut self.stack, &mut self.parents, id);
                self.stack.push(id);

                eprintln!("{}, {}", prev_index, choice);
                self.tree.events[id] = (prev_index, choice);
            } else {
                let decision = self.tree.push(&mut self.parents);
                self.tree
                    .insert_right(&mut self.stack, &mut self.parents, decision);
                self.stack.push(decision);

                let id = self.tree.push(&mut self.parents);
                self.tree
                    .insert_left(&mut self.stack, &mut self.parents, id);

                eprintln!("{}, {}", prev_index, choice);
                self.tree.events[id] = (prev_index, choice);
            }

            f(self, choice);
            self.stack.pop();
        }

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
        dbg!(tree);
        panic!();
    }

    #[test]
    fn wide_test() {
        let mut builder = Builder::default();

        builder.insert(8, |_builder, _choice| {});

        let tree = builder.finish();
        dbg!(tree);
        //panic!();
    }
}
