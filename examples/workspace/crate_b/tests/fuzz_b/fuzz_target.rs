use bolero::check;
use crate_b::run;

fn main() {
    check!().with_type().cloned().for_each(|(a, b)| {
        run(a, b);
    });
}
