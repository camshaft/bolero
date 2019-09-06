use basic::add;
use bolero::fuzz;

fuzz!(|input| {
    if input.len() < 2 {
        return;
    }

    let a = input[0];
    let b = input[1];
    assert!(add(a, b) >= a);
});
