use bolero::fuzz;
use crate_a::run;

fn main() {
    fuzz!().with_type().for_each(|(a, b)| {
        run(a, b);
    });
}
