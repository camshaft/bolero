use arrayvec::ArrayVec;
use basic::should_panic;
use bolero::{check, generator::*};
use std::collections::LinkedList;

#[derive(Debug, TypeGenerator)]
enum Operation {
    Push(u8),
    Pop,
    Clear,
}

fn main() {
    let len = if should_panic() { 16 } else { 4 };

    check!()
        .with_generator(produce::<Vec<Operation>>().with().len(0usize..=len))
        .for_each(|operations| {
            let mut subject: ArrayVec<[_; 4]> = ArrayVec::new();
            let mut oracle = LinkedList::new();

            for operation in operations.iter() {
                match operation {
                    Operation::Push(value) => {
                        subject.push(value);
                        oracle.push_front(value);
                    }
                    Operation::Pop => {
                        let actual = subject.pop();
                        let expected = oracle.pop_front();
                        assert_eq!(actual, expected);
                    }
                    Operation::Clear => {
                        subject.clear();
                        oracle.clear();
                    }
                }
            }
        });
}
