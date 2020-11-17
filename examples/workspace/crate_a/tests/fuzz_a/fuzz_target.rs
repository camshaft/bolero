use bolero::check;
use crate_a::run;

fn main() {
    check!().with_type().cloned().for_each(|(a, b)| {
        run(a, b);
    });
}
