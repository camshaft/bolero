use bolero_generator::TypeGenerator;

thread_local! {
    static SHOULD_PANIC: bool = {
        #[cfg(bolero_should_panic)]
        return true;

        #[cfg(not(bolero_should_panic))]
        return std::env::var("SHOULD_PANIC").is_ok();
    };
}

#[cfg(test)]
mod tests;

#[derive(Clone, Debug, TypeGenerator)]
pub enum Expr {
    Value(bool),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Xor(Box<Expr>, Box<Expr>),
    Nand(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
}

impl Expr {
    pub fn eval(&self) -> bool {
        match self {
            Expr::Value(value) => *value,
            Expr::And(a, b) => a.eval() && b.eval(),
            Expr::Or(a, b) => a.eval() || b.eval(),
            Expr::Xor(a, b) => a.eval() ^ b.eval(),
            Expr::Nand(a, b) => !(a.eval() && b.eval()),
            Expr::Not(_) if SHOULD_PANIC.with(|v| *v) => unreachable!(),
            Expr::Not(a) => !a.eval(),
        }
    }
}
