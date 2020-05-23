use bolero::fuzz;

fn main() {
    fuzz!().with_type().for_each(|value: &u64| {
        // TODO implement checks
        let _ = value;
    });
}
