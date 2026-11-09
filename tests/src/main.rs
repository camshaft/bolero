pub type Result<T = ()> = anyhow::Result<T>;

mod bolero;
mod cargo_bolero;
mod downstream;
mod engines;
mod env;
mod examples;
mod reduce;

fn main() -> Result {
    downstream::test()?;
    bolero::test()?;
    cargo_bolero::test()?;
    examples::test()?;
    engines::test()?;
    reduce::test()?;

    Ok(())
}
