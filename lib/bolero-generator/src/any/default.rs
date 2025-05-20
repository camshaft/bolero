use crate::driver::object::{self, DynDriver, Object};
use core::fmt;
use std::cell::RefCell;

pub trait Scope: 'static + DynDriver + core::any::Any {
    fn borrowed(&mut self) -> object::Borrowed;
}

impl<T> Scope for T
where
    T: 'static + DynDriver + core::any::Any,
{
    fn borrowed(&mut self) -> object::Borrowed {
        object::Borrowed(self)
    }
}

type Type = Box<dyn Scope>;

thread_local! {
    static SCOPE: RefCell<Type> = RefCell::new(Box::new(Object(default())));
}

fn default() -> impl crate::Driver {
    use rand_core::SeedableRng;
    use rand_xoshiro::Xoshiro128PlusPlus;

    let mut seed = [42; 16];
    // make a best effort to get random seeds
    let _ = getrandom::fill(&mut seed);
    let rng = Xoshiro128PlusPlus::from_seed(seed);
    // we don't want to limit the output of this by default for when it hasn't been configured by a fuzzer
    let config = crate::driver::Options::default()
        .with_max_len(usize::MAX)
        .with_max_depth(10);
    crate::driver::Rng::new(rng, &config)
}

fn set(value: Type) -> Type {
    SCOPE.with(|r| core::mem::replace(&mut *r.borrow_mut(), value))
}

// protect against panics in the `with` function
struct Prev(Option<Type>);

impl Prev {
    fn reset(mut self) -> Type {
        set(self.0.take().unwrap())
    }
}

impl Drop for Prev {
    fn drop(&mut self) {
        if let Some(prev) = self.0.take() {
            let _ = set(prev);
        }
    }
}

pub fn with<D, F, R>(driver: Box<D>, f: F) -> (Box<D>, R)
where
    D: Scope,
    F: FnOnce() -> R,
{
    let prev = Prev(Some(set(driver)));
    let res = f();
    let driver = prev.reset();
    let driver = if driver.type_id() == core::any::TypeId::of::<D>() {
        unsafe {
            let raw = Box::into_raw(driver);
            Box::from_raw(raw as *mut D)
        }
    } else {
        panic!(
            "invalid scope state; expected {}",
            core::any::type_name::<D>()
        )
    };
    (driver, res)
}

fn borrow_with<F: FnOnce(&mut object::Borrowed) -> R, R>(f: F) -> R {
    SCOPE.with(|r| {
        let mut driver = r.borrow_mut();
        let mut driver = driver.borrowed();
        f(&mut driver)
    })
}

#[track_caller]
pub fn any<G: crate::ValueGenerator>(g: &G) -> G::Output {
    borrow_with(|driver| {
        g.generate(driver).unwrap_or_else(|| {
            std::panic::panic_any(Error {
                location: core::panic::Location::caller(),
                generator: core::any::type_name::<G>(),
                output: core::any::type_name::<G::Output>(),
            })
        })
    })
}

#[track_caller]
pub fn assume(condition: bool, message: &'static str) {
    if !condition {
        std::panic::panic_any(Error {
            location: core::panic::Location::caller(),
            generator: "<assume>",
            output: message,
        });
    }
}

#[track_caller]
pub fn fill_bytes(bytes: &mut [u8]) {
    borrow_with(|driver| {
        let len = bytes.len();
        let mut hint = || (len, Some(len));
        driver
            .0
            .gen_from_bytes(&mut hint, &mut |src: &[u8]| {
                if src.len() == len {
                    bytes.copy_from_slice(src);
                    Some(len)
                } else {
                    None
                }
            })
            .unwrap_or_else(|| {
                std::panic::panic_any(Error {
                    location: core::panic::Location::caller(),
                    generator: "<fill_bytes>",
                    output: "could not generate enough bytes",
                });
            })
    })
}

#[derive(Clone)]
pub struct Error {
    location: &'static core::panic::Location<'static>,
    generator: &'static str,
    output: &'static str,
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Error")
            .field("location", &self.location)
            .field("generator", &self.generator)
            .field("output", &self.output)
            .finish()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Could not generate value of type {} at {}",
            self.output, self.location,
        )
    }
}

impl std::error::Error for Error {}
