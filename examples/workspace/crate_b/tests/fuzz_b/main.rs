use bolero::fuzz;

fn main() {
    fuzz!(|input| {
        if input.len() < 3 {
            return;
        }

        if input[0] == 0 && input[1] == 1 && input[2] == 2 {
            panic!("you found me!");
        }
    });
}
