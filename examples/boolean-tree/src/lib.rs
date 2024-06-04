use bolero_generator::TypeGenerator;
use core::fmt;

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

#[derive(Copy, Clone)]
pub struct Shape<'a>(&'a Expr);

impl<'a> fmt::Debug for Shape<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Expr::Value(_) => write!(f, "Value"),
            Expr::And(a, b) => f
                .debug_tuple("And")
                .field(&Shape(a))
                .field(&Shape(b))
                .finish(),
            Expr::Or(a, b) => f
                .debug_tuple("Or")
                .field(&Shape(a))
                .field(&Shape(b))
                .finish(),
            Expr::Xor(a, b) => f
                .debug_tuple("Xor")
                .field(&Shape(a))
                .field(&Shape(b))
                .finish(),
            Expr::Not(a) => f.debug_tuple("Not").field(&Shape(a)).finish(),
        }
    }
}

#[derive(Clone, Debug, TypeGenerator)]
pub enum Expr {
    Value(bool),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Xor(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
}

impl Expr {
    #[inline]
    pub fn shape(&self) -> Shape {
        Shape(self)
    }

    #[inline]
    pub fn eval(&self) -> bool {
        match self {
            Expr::Value(value) => *value,
            Expr::And(a, b) => a.eval() && b.eval(),
            Expr::Or(a, b) => a.eval() || b.eval(),
            Expr::Xor(a, b) => a.eval() ^ b.eval(),
            Expr::Not(_) if SHOULD_PANIC.with(|v| *v) => unreachable!(),
            Expr::Not(a) => !a.eval(),
        }
    }
}
