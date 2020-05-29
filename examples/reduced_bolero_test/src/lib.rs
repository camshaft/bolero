use bolero::generator::*;
use std::collections::HashSet;

#[derive(Debug, TypeGenerator)]
pub(crate) struct Datum {
    #[generator(HashSet::gen().with().len(0usize..10))]
    channels: HashSet<u64>,
}

//  ▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄    ▄▄▄▄    ▄▄▄▄▄▄▄▄    ▄▄▄▄
//  ▀▀▀██▀▀▀  ██▀▀▀▀▀▀  ▄█▀▀▀▀█   ▀▀▀██▀▀▀  ▄█▀▀▀▀█
//     ██     ██        ██▄          ██     ██▄
//     ██     ███████    ▀████▄      ██      ▀████▄
//     ██     ██             ▀██     ██          ▀██
//     ██     ██▄▄▄▄▄▄  █▄▄▄▄▄█▀     ██     █▄▄▄▄▄█▀
//     ▀▀     ▀▀▀▀▀▀▀▀   ▀▀▀▀▀       ▀▀      ▀▀▀▀▀
//
//

#[cfg(test)]
mod tests {
    use super::*;
    use bolero::fuzz;

    #[test]
    fn bolero_test() {
        fuzz!().with_type::<Datum>().for_each(|_dut| {
            // Does absolutely nothing.  This is on purpose to test bolero.
        });
    }
}
