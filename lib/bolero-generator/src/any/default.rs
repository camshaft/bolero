use crate::driver::object::{self, DynDriver, Object};
use core::{cell::Cell, fmt};
use std::{cell::RefCell, sync::Once};

pub trait Scope: 'static + DynDriver + core::any::Any {
    fn borrowed(&mut self) -> object::Borrowed<'_>;
}

impl<T> Scope for T
where
    T: 'static + DynDriver + core::any::Any,
{
    fn borrowed(&mut self) -> object::Borrowed<'_> {
        object::Borrowed(self)
    }
}

type Type = Box<dyn Scope>;

/// The seed of a default scope, in the type and the decimal form of `BOLERO_RANDOM_SEED`
type Seed = u128;

thread_local! {
    static SCOPE: RefCell<Type> = RefCell::new(Box::new(Object(default())));
    // the seed this thread's default scope was created with
    static SEED: Cell<Option<Seed>> = const { Cell::new(None) };
    // whether this thread drew a value from its default scope
    static DRAWN: Cell<bool> = const { Cell::new(false) };
    // how many drivers `with` sets in place of the default scope
    static DEPTH: Cell<usize> = const { Cell::new(0) };
    // how many harnesses run on this thread, each of which reports the seed of its own inputs
    static HARNESS: Cell<usize> = const { Cell::new(0) };
}

fn default() -> impl crate::Driver {
    use rand_core::SeedableRng;
    use rand_xoshiro::Xoshiro128PlusPlus;

    let seed = seed();
    SEED.with(|cell| cell.set(Some(seed)));
    let rng = Xoshiro128PlusPlus::from_seed(seed.to_le_bytes());
    // we don't want to limit the output of this by default for when it hasn't been configured by a fuzzer
    let config = crate::driver::Options::default()
        .with_max_len(usize::MAX)
        .with_max_depth(10);
    crate::driver::Rng::new(rng, &config)
}

/// Reads the seed from `BOLERO_RANDOM_SEED` as a bolero test does, so that setting it replays
/// the values drawn, and otherwise chooses a random seed
fn seed() -> Seed {
    let var = std::env::var("BOLERO_RANDOM_SEED").ok();
    if let Some(seed) = var.and_then(|value| value.parse().ok()) {
        return seed;
    }

    let mut seed = [42; 16];
    // make a best effort to get random seeds
    let _ = getrandom::fill(&mut seed);
    Seed::from_le_bytes(seed)
}

fn set(value: Type) -> Type {
    SCOPE.with(|r| core::mem::replace(&mut *r.borrow_mut(), value))
}

// protect against panics in the `with` function
struct Prev(Option<Type>);

impl Prev {
    fn new(value: Type) -> Self {
        let prev = Self(Some(set(value)));
        DEPTH.with(|depth| depth.set(depth.get() + 1));
        prev
    }

    fn reset(mut self) -> Type {
        set(self.0.take().unwrap())
    }
}

impl Drop for Prev {
    fn drop(&mut self) {
        if let Some(prev) = self.0.take() {
            let _ = set(prev);
        }
        DEPTH.with(|depth| depth.set(depth.get() - 1));
    }
}

pub fn with<D, F, R>(driver: Box<D>, f: F) -> (Box<D>, R)
where
    D: Scope,
    F: FnOnce() -> R,
{
    let prev = Prev::new(driver);
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
        if DEPTH.with(Cell::get) == 0 {
            on_default_draw();
        }
        let mut driver = driver.borrowed();
        f(&mut driver)
    })
}

/// Marks this thread as one that drew from its default scope, and installs the panic hook that
/// reports the scope's seed
fn on_default_draw() {
    DRAWN.with(|drawn| drawn.set(true));
    install_hook();
}

/// Installs the panic hook that reports the seed of a thread's default scope, once a process
///
/// The hook calls the hook it replaced, then reports the seed. An install takes the current hook
/// and sets a new one in two steps, so two installs at the same time can both take one hook, and
/// the second set drops the first install's hook. A crate that installs a hook of its own calls
/// this function before it takes the current hook: the call returns once this hook is installed,
/// so the crate's hook wraps this one, and neither install drops the other's hook.
#[doc(hidden)]
pub fn install_hook() {
    static HOOK: Once = Once::new();

    // the panic hook can't change while this thread panics
    if std::thread::panicking() {
        return;
    }

    HOOK.call_once(|| {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            prev(info);
            report();
        }));
    });
}

/// Prints the seed of this thread's default scope where the thread drew from it and no harness
/// runs on it, so that setting `BOLERO_RANDOM_SEED` to the seed replays the values drawn
fn report() {
    // a harness reports the seed of its own failing input
    if HARNESS.try_with(Cell::get).unwrap_or(0) > 0 {
        return;
    }

    if !DRAWN.try_with(Cell::get).unwrap_or(false) {
        return;
    }

    if let Ok(Some(seed)) = SEED.try_with(Cell::get) {
        eprintln!("BOLERO_RANDOM_SEED={seed}");
    }
}

/// Marks this thread as running a harness until the returned guard drops
///
/// A harness reports the seed of its own failing input, so the default scope doesn't report
/// its seed while one runs.
#[doc(hidden)]
pub fn enter_harness() -> HarnessGuard {
    HARNESS.with(|harness| harness.set(harness.get() + 1));
    HarnessGuard(())
}

/// Marks this thread as running a harness until it drops
///
/// Obtained by calling [`enter_harness`].
#[doc(hidden)]
pub struct HarnessGuard(());

impl Drop for HarnessGuard {
    fn drop(&mut self) {
        let _ = HARNESS.try_with(|harness| {
            let count = harness.get();
            harness.set(count.saturating_sub(1));
        });
    }
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
