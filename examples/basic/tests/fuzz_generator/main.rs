use basic::add;
use bolero::{fuzz, generator::*};

fuzz!(for (a, b) in all(gen()) {
    assert!(add(a, b) >= a);
});
