use basic::add;
use bolero::fuzz;

fn main() {
    fuzz!(for (a, b) in all(gen()) {
        assert!(add(a, b) >= a);
    });
}
