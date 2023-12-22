use super::*;
use bolero::check;
use std::collections::BTreeMap;

#[test]
fn model_test() {
    use bolero::generator::bolero_generator::grammar;
    let max_depth = 4;

    let g = bolero::gen::<Expr>();

    let grammar = grammar::Grammar::from_generator(&g);
    let options = grammar::Options {
        max_depth: Some(max_depth),
        ..Default::default()
    };
    dbg!(grammar.estimate_state_space(&options));
    dbg!(grammar.estimate_topology(&options));
    let topology = grammar.topology(&options);
    dbg!(topology.len());
    for selection in topology.iter() {
        //println!("{selection:?}");
    }
    let g = grammar::topology::Generator::new(g, topology);

    let mut hist = BTreeMap::default();

    check!()
        .with_generator(g)
        .with_max_depth(max_depth)
        .with_test_time(core::time::Duration::from_secs(10))
        .for_each(|ops| {
            *hist.entry(format!("{:?}", ops.shape())).or_insert(0u64) += 1;
            let _value = ops.eval();
        });

    let mut min_value = u64::MAX;
    let mut max_value = u64::MIN;
    for value in hist.values().copied() {
        min_value = min_value.min(value);
        max_value = max_value.max(value);
    }

    dbg!(hist.len());
    dbg!(min_value, max_value, max_value - min_value);
}
