use super::selection::{Output, Selection};
use crate::Driver;
use alloc::vec::Vec;
use core::fmt;

pub mod builder;
pub use builder::Builder;

#[cfg(test)]
mod tests;

#[derive(Clone, Debug)]
pub struct Tree {
    bytes: usize,
    leaves: usize,
    nodes: Vec<Node>,
}

impl Default for Tree {
    #[inline]
    fn default() -> Self {
        Self {
            bytes: 0,
            leaves: 0,
            nodes: vec![],
        }
    }
}

impl Tree {
    #[inline]
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.leaves
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.leaves == 0
    }

    #[inline]
    pub fn select<D: Driver, O: Output>(&self, driver: &mut D, out: &mut O) {
        let index = driver.gen_variant(self.leaves, 0).unwrap_or(usize::MAX);
        self.select_with_index(index, out)
    }

    #[inline]
    fn select_with_index<O: Output>(&self, index: usize, out: &mut O) {
        select(index, &self.nodes, out)
    }

    #[inline]
    pub fn iter(&self) -> Iter {
        Iter {
            tree: self,
            nodes: self.nodes[..self.leaves].iter(),
        }
    }
}

pub struct Iter<'a> {
    tree: &'a Tree,
    nodes: core::slice::Iter<'a, Node>,
}

impl<'a> Iterator for Iter<'a> {
    type Item = IterNode<'a>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let node = self.nodes.next()?;
        Some(IterNode {
            tree: self.tree,
            node,
        })
    }
}

pub struct IterNode<'a> {
    tree: &'a Tree,
    node: &'a Node,
}

impl<'a> IterNode<'a> {
    #[inline]
    pub fn select<O: Output>(&self, out: &mut O) {
        let Node { choice, parent } = *self.node;
        out.push_front(choice);
        select(parent as _, &self.tree.nodes, out);
    }

    #[inline]
    pub fn selection(&self) -> Selection {
        let mut selection = Selection::default();
        self.select(&mut selection);
        selection
    }
}

impl<'a> fmt::Debug for IterNode<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.selection().fmt(f)
    }
}

#[inline(always)]
fn select(mut index: usize, nodes: &[Node], out: &mut impl Output) {
    while let Some(node) = nodes.get(index) {
        out.push_front(node.choice);
        index = node.parent().unwrap_or(usize::MAX);
    }

    out.finish();
}

impl crate::ValueGenerator for Tree {
    type Output = Selection;

    #[inline]
    fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
        let mut output = driver.cache_get().unwrap_or_else(Selection::default);
        match self.mutate(driver, &mut output) {
            Some(()) => Some(output),
            None => {
                driver.cache_put(output);
                None
            }
        }
    }

    #[inline]
    fn mutate<D: Driver>(&self, driver: &mut D, value: &mut Self::Output) -> Option<()> {
        value.clear();
        self.select(driver, value);
        if value.is_empty() {
            None
        } else {
            Some(())
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Node {
    choice: u32,
    parent: u32,
}

impl Node {
    #[inline(always)]
    pub fn parent(&self) -> Option<usize> {
        if self.parent == u32::MAX {
            None
        } else {
            Some(self.parent as _)
        }
    }
}

impl fmt::Debug for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("Node");

        s.field("choice", &self.choice);
        if let Some(parent) = self.parent() {
            s.field("parent", &parent);
        }
        s.finish()
    }
}
