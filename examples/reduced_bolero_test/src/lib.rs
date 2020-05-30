#[cfg(test)]
pub(crate) mod tests {
    use bolero::fuzz;

    // Cheesy crash test.
    #[test]
    fn new() {
        assert!(true);

        // The following block causes the issues.  Change 'true' to 'false' and
        // the issues go away.  See the README.md for more info.
        if true {
            fuzz!().with_type::<u64>().for_each(|dut| {
                let bytes = dut.to_be_bytes();
                let dut2 = u64::from_be_bytes(bytes);
                assert_eq!(dut, &dut2);
            });
        }
    }
}
