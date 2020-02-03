use bolero::fuzz;

fn main() {
    fuzz!().for_each(|input: &[u8]| {
        // TODO implement checks
        let _ = input;
    });
}
