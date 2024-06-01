use super::*;
use bolero::{check, generator::*};
use core::fmt;

#[derive(Clone, Copy, Debug, TypeGenerator)]
enum Operation<T> {
    Push { count: u8, value: T },
    Pop { count: u8 },
    Clear,
}

#[derive(Default)]
struct Model<T: Copy + fmt::Debug + Eq> {
    oracle: Vec<T>,
    subject: RleStack<T>,
}

impl<T: Copy + fmt::Debug + Eq> Model<T> {
    pub fn push(&mut self, value: T) {
        self.oracle.push(value);
        self.subject.push(value);
        self.invariants();
    }

    pub fn pop(&mut self) -> Option<T> {
        let expected = self.oracle.pop();
        let actual = self.subject.pop();
        assert_eq!(expected, actual);
        self.invariants();
        actual
    }

    pub fn clear(&mut self) {
        self.oracle.clear();
        self.subject.clear();
        self.invariants();
    }

    pub fn apply(&mut self, operation: Operation<T>) {
        match operation {
            Operation::Push { count, value } => {
                for _ in 0..count {
                    self.push(value);
                }
            }
            Operation::Pop { count } => {
                for _ in 0..count {
                    self.pop();
                }
            }
            Operation::Clear => {
                self.clear();
            }
        }
    }

    pub fn finish(&self) {
        self.invariants();
        let actual: Vec<_> = self.subject.iter().copied().collect();
        assert_eq!(
            self.oracle, actual,
            "\n\nSubject state: {:#?}",
            self.subject
        );
    }

    fn invariants(&self) {
        assert_eq!(
            self.oracle.len(),
            self.subject.len(),
            "lengths do not match"
        );
        assert_eq!(
            self.oracle.is_empty(),
            self.subject.is_empty(),
            "is_empty does not match"
        );
    }
}

impl<T: Copy + fmt::Debug + Eq> Drop for Model<T> {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            self.finish();
        }
    }
}

#[test]
fn model_test() {
    check!().with_type::<Vec<Operation<u8>>>().for_each(|ops| {
        let mut model = Model::default();
        for op in ops {
            model.apply(*op);
        }
    })
}

#[test]
fn unit_test() {
    let mut model = <Model<u8>>::default();

    assert!(model.pop().is_none());
    model.clear();
    assert!(model.pop().is_none());

    model.push(123);
    assert_eq!(model.pop(), Some(123));
}
