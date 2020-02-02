use bolero_generator::*;
use core::ops::{Range, RangeInclusive};

include!("../src/testing.rs");

fn gen_foo() -> impl ValueGenerator<Output = u32> {
    4..6
}

#[derive(TypeGenerator)]
pub struct Unit;

#[derive(Debug, Clone, TypeGenerator, PartialEq)]
pub struct NewType(#[generator(4..10)] u64);

#[derive(Debug, Clone, TypeGenerator, PartialEq)]
pub struct Struct {
    #[generator(gen_foo())]
    field_a: u32,

    #[generator(_code = "gen()")]
    field_b: NewType,

    #[generator(_code = "gen::<u8>().with()")]
    field_c: u8,
}

#[derive(Debug, Clone, TypeGenerator, PartialEq)]
pub enum Enum {
    Insert {
        #[generator(1..3)]
        index: usize,
        value: u32,
    },
    Remove {
        #[generator(4..6)]
        index: usize,
    },
    Struct(Struct, Struct),
    CustomGenerator(#[generator(42..53)] usize),
    Clear,
}

#[derive(TypeGenerator)]
pub union Union {
    a: u32,
    b: u64,
    c: u8,
}

pub type RangeBound = u8;

#[derive(TypeGenerator)]
pub enum RangeValue {
    Range(Range<RangeBound>),
    RangeInclusive(RangeInclusive<RangeBound>),
}

#[derive(TypeGenerator)]
pub enum RangeOperation {
    Insert { range: RangeValue },
    Remove { range: RangeValue },
}

#[test]
fn derive_struct_test() {
    let _ = generator_mutate_test!(Struct::gen());
}

#[test]
fn derive_enum_test() {
    let _ = generator_mutate_test!(Enum::gen());
}

#[test]
fn derive_union_test() {
    let _ = generator_test!(Union::gen());
}
