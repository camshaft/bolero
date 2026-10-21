pub fn branches(x: u64) -> u64 {
    if x % 3 == 0 {
        0
    } else if x % 5 == 0 {
        1
    } else if x % 7 == 0 {
        2
    } else {
        x
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_branches() {
        bolero::check!()
            .with_type::<u64>()
            .cloned()
            .for_each(|x: u64| {
                let result = branches(x);
                if x % 3 == 0 {
                    assert_eq!(result, 0);
                } else if x % 5 == 0 {
                    assert_eq!(result, 1);
                } else if x % 7 == 0 {
                    assert_eq!(result, 2);
                } else {
                    assert_eq!(result, x);
                }
            });
    }
}
