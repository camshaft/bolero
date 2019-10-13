use basic::add;
use bolero::fuzz;

fuzz!(for (a, b) in all(gen()) {
    assert!(add(a, b) >= a);
});
