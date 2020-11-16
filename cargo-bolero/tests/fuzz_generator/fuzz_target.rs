use bolero::check;

fn main() {
    check!().with_type().for_each(|value: &u64| {
        // TODO implement checks
        let _ = value;
    });
}
