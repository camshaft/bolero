use super::*;
use bolero::check;

#[test]
fn model_test() {
    check!()
        .with_type::<Expr>()
        .with_max_depth(3)
        .for_each(|ops| {
            let _value = ops.eval();
        })
}
