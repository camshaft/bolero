use super::*;
use crate::{
    driver::Driver as _,
    grammar::{Driver, Options},
};

fn t<O: IntoIterator<Item = S>, S: AsRef<[u32]>>(tree: Tree, outcomes: O) {
    let mut is_ok = true;
    let mut outcomes = outcomes.into_iter();
    let mut out = vec![];

    dbg!(tree.len());
    for idx in 0..tree.len() {
        tree.select_with_index(idx, &mut out);
        let outcome = outcomes.next();
        let idx_is_ok = outcome.as_ref().map_or(false, |o| o.as_ref().eq(&*out));
        if idx_is_ok {
            eprintln!("&{:?},", &out[..]);
        } else {
            eprintln!(
                "&{:?}, // expected {:?}",
                &out[..],
                outcome.as_ref().map(|v| v.as_ref())
            );
        }
        is_ok &= idx_is_ok;
        out.clear();
    }

    for (idx, extra) in outcomes.enumerate() {
        if idx == 0 {
            eprintln!("// === UNEXPECTED ===");
        }
        eprintln!("&{:?},", extra.as_ref());
        is_ok = false;
    }

    assert!(is_ok);
}

fn driver(options: Options, f: impl FnOnce(&mut Driver)) -> Tree {
    let mut driver = Driver::default();
    f(&mut driver);
    let grammar = driver.finish();
    let estimate = dbg!(grammar.estimate_topology(&options));
    let tree = grammar.topology(&options);
    //assert_eq!(tree.len() as f64, estimate, "{tree:#?}");
    tree
}

#[test]
fn binary_tree_test() {
    t(
        driver(
            Options {
                max_depth: Some(2),
                ..Default::default()
            },
            |driver| {
                struct A {}
                struct B {}
                struct C {}

                driver.enter_sum::<A, _, _>(None, 2, 0, |driver, _idx| {
                    driver.enter_sum::<B, _, _>(None, 2, 0, |driver, _idx| {
                        driver.enter_sum::<C, _, _>(None, 2, 0, |_driver, _idx| Some(()))
                    })
                });
            },
        ),
        [
            &[0, 0, 0][..],
            &[0, 0, 1],
            &[0, 1, 0],
            &[0, 1, 1],
            &[1, 0, 0],
            &[1, 0, 1],
            &[1, 1, 0],
            &[1, 1, 1],
        ],
    )
}

#[test]
fn binary_tree_unbalanced_test() {
    t(
        driver(
            Options {
                max_depth: Some(3),
                ..Default::default()
            },
            |driver| {
                struct Node {}

                driver.enter_sum::<Node, _, _>(None, 2, 0, |driver, idx| {
                    if idx > 0 {
                        driver.enter_sum::<Node, _, _>(None, 2, 0, |_driver, _idx| Some(()))
                    } else {
                        Some(())
                    }
                });
            },
        ),
        [
            // comment so rustfmt doesn't put this on 1 line
            &[0][..],
            &[1, 0],
            &[1, 1, 0],
            &[1, 1, 1, 0],
            &[1, 1, 1, 1, 0],
        ],
    )
}

#[test]
fn expr_unbalanced_test() {
    t(
        driver(
            Options {
                max_depth: Some(1),
                ..Default::default()
            },
            |driver| {
                struct Expr {}

                driver.enter_sum::<Expr, _, _>(None, 2, 0, |driver, idx| {
                    if idx > 0 {
                        for _ in 0..2 {
                            driver.enter_sum::<Expr, _, _>(None, 2, 0, |_driver, _idx| Some(()))?;
                        }
                    }
                    Some(())
                });
            },
        ),
        [
            &[0][..],
            &[1, 0, 0],
            &[1, 1, 0, 0, 0],
            &[1, 0, 1, 0, 0],
            &[1, 1, 0, 0, 1, 0, 0],
        ],
    )
}

#[test]
fn list_test() {
    t(
        driver(
            Options {
                max_depth: Some(2),
                ..Default::default()
            },
            |driver| {
                struct Enum {}
                struct List {}

                driver.enter_list::<List, _, _, _>(&(0usize..=3), |driver, len| {
                    for _ in 0..len {
                        driver.enter_sum::<Enum, _, _>(None, 2, 0, |_driver, _idx| Some(()))?;
                    }
                    Some(())
                });
            },
        ),
        [
            &[0][..],
            &[1, 0],
            &[1, 1],
            &[2, 0, 0],
            &[2, 1, 0],
            &[2, 0, 1],
            &[2, 1, 1],
            &[3, 0, 0, 0],
            &[3, 1, 0, 0],
            &[3, 0, 1, 0],
            &[3, 1, 1, 0],
            &[3, 0, 0, 1],
            &[3, 1, 0, 1],
            &[3, 0, 1, 1],
            &[3, 1, 1, 1],
        ],
    )
}

#[test]
fn list_nonzero_test() {
    t(
        driver(
            Options {
                max_depth: Some(2),
                ..Default::default()
            },
            |driver| {
                struct Enum {}
                struct List {}

                driver.enter_list::<List, _, _, _>(&(2usize..4), |driver, len| {
                    for _ in 0..len {
                        driver.enter_sum::<Enum, _, _>(None, 2, 0, |_driver, _idx| Some(()))?;
                    }
                    Some(())
                });
            },
        ),
        [
            &[2, 0, 0][..],
            &[2, 1, 0],
            &[2, 0, 1],
            &[2, 1, 1],
            &[3, 0, 0, 0],
            &[3, 1, 0, 0],
            &[3, 0, 1, 0],
            &[3, 1, 1, 0],
            &[3, 0, 0, 1],
            &[3, 1, 0, 1],
            &[3, 0, 1, 1],
            &[3, 1, 1, 1],
        ],
    )
}
