use bolero::fuzz;
use crate_b::run;

fn main() {
    fuzz!().with_type().cloned().for_each(|(a, b)| {
        run(a, b);
    });
}
