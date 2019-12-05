// WIP

use arrayvec::ArrayVec;
use bolero::{fuzz, generator::*};
use std::collections::LinkedList;

#[derive(Debug, TypeGenerator)]
enum Operation {
    Push(u8),
    Pop,
    Clear,
}

#[derive(Default)]
struct Model {
    subject: ArrayVec<[u8; 32]>,
    oracle: LinkedList<u8>,
}

#[model(Operation)]
impl Model {
    #[new]
    fn new() -> Self {
        Self::default()
    }

    fn push(&mut self, value: u8) {
        self.subject.push(value);
        self.oracle.push_front(value);
    }

    fn pop(&mut self) {
        let actual = self.subject.pop();
        let expected = self.oracle.pop_front();
        assert_eq!(actual, expected);
    }

    fn clear(&mut self) {
        self.subject.clear();
        self.oracle.clear();
    }
}

trait Model {
    type Arguments;
    type Operation;

    fn init(arguments: Self::Arguments);
    fn dispatch(&mut self, operation: Self::Operation);
}

fn main() {
    fuzz!().with_model::<Model>();
}
