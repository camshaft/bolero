use bolero::{generator::*, Driver};

#[derive(Debug)]
pub struct Dummy();

impl TypeGenerator for Dummy {
    fn generate<R>(_driver: &mut R) -> Option<Self>
    where
        R: Driver,
    {
        assert!(
            false,
            "{:?}: {:?}: I should see something here!",
            file!(),
            line!()
        );
        Some(Dummy())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bolero::fuzz;

    #[test]
    fn serialize() {
        fuzz!().with_type::<Dummy>().for_each(|_| {
            // Deliberately empty, testing bolero
        });
    }
}
