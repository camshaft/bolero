type Type = crate::kani::Driver;

pub use core::convert::Infallible as Error;

/// Kani doesn't support thread_locals so use a static global instead
static mut CURRENT: Type = Type {
    depth: 0,
    max_depth: crate::driver::Options::DEFAULT_MAX_DEPTH,
};

fn get() -> Type {
    unsafe {
        let depth = CURRENT.depth;
        let max_depth = CURRENT.max_depth;

        Type { depth, max_depth }
    }
}

fn set(value: Type) -> Type {
    let prev = get();

    unsafe {
        CURRENT.depth = value.depth;
        CURRENT.max_depth = value.max_depth;
    }

    prev
}

pub fn with<F, R>(driver: Type, f: F) -> (Type, R)
where
    F: FnOnce() -> R,
{
    let prev = set(driver);
    let res = f();
    let driver = set(prev);
    (driver, res)
}

fn borrow_with<F: FnOnce(&mut Type) -> R, R>(f: F) -> R {
    let mut driver = unsafe {
        let depth = CURRENT.depth;
        let max_depth = CURRENT.max_depth;

        Type { depth, max_depth }
    };
    let result = f(&mut driver);
    set(driver);
    result
}

pub fn any<G: crate::ValueGenerator>(g: &G) -> G::Output {
    borrow_with(|driver| {
        let v = g.generate(driver);
        assume(v.is_some(), "generator should return at least one value");
        v.unwrap()
    })
}

pub fn fill_bytes(bytes: &mut [u8]) {
    for dst in bytes {
        #[cfg(kani)]
        let src = ::kani::any();

        #[cfg(not(kani))]
        let src = 0;

        *dst = src;
    }
}

#[inline]
pub fn assume(condition: bool, message: &'static str) {
    #[cfg(kani)]
    ::kani::assume(condition);

    let _ = condition;
    let _ = message;
}
