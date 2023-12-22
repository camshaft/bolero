use crate::{driver, ValueGenerator};
use core::{
    any::{type_name, TypeId},
    ops::Bound,
};
use std::collections::{BTreeMap, HashMap};

pub const DEFAULT_MAX_BYTES: usize = 4096;
pub const DEFAULT_MAX_DEPTH: usize = 2;

pub mod state_space;
pub mod topology;

#[derive(Clone, Debug)]
pub struct Options {
    pub max_depth: Option<usize>,
    pub max_bytes: Option<usize>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            max_depth: Some(DEFAULT_MAX_DEPTH),
            max_bytes: Some(DEFAULT_MAX_BYTES),
        }
    }
}

impl Options {
    #[inline]
    fn check_depth(&self, current_depth: usize) -> bool {
        if let Some(max_depth) = self.max_depth {
            max_depth >= current_depth.saturating_sub(1)
        } else {
            true
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Grammar {
    pub root: usize,
    pub terms: Vec<Term>,
    pub products: Vec<Product<usize>>,
    pub sums: Vec<Sum<usize>>,
    pub lists: Vec<List<usize>>,
}

impl Grammar {
    #[inline]
    pub fn root(&self) -> &Term {
        &self.terms[self.root]
    }

    pub fn estimate_state_space(&self, options: &Options) -> state_space::Estimate {
        state_space::estimate(self, state_space::Kind::StateSpace, options)
    }

    pub fn estimate_topology(&self, options: &Options) -> state_space::Estimate {
        state_space::estimate(self, state_space::Kind::Topology, options)
    }

    pub fn topology(&self, options: &Options) -> topology::Tree {
        topology::calculate(self, options)
    }

    pub fn from_generator<G: ValueGenerator>(g: &G) -> Self {
        let mut driver = Driver::default();
        let _ = g.generate(&mut driver);
        driver.finish()
    }
}

struct Builder<'a> {
    grammar: &'a mut Grammar,
    driver: &'a Driver,
    terms: HashMap<Term<usize>, usize>,
    products: BTreeMap<TypeId, usize>,
    sums: BTreeMap<TypeId, usize>,
    lists: BTreeMap<TypeId, usize>,
}

impl<'a> Builder<'a> {
    fn push(&mut self, term: Term) -> usize {
        if let Some(idx) = self.terms.get(&term) {
            return *idx;
        }

        let id = self.grammar.terms.len();
        self.grammar.terms.push(term);
        self.terms.insert(term, id);
        id
    }

    fn push_sum(&mut self, tid: TypeId) -> usize {
        if let Some(idx) = self.sums.get(&tid) {
            return *idx;
        }
        let source = self.driver.sums.get(&tid).unwrap();
        let name = source.name;

        let idx = self.sums.len();
        self.grammar.sums.push(Sum {
            id: tid,
            name,
            elements: vec![],
        });

        let id = self.push(Term::Sum { id: idx });
        self.sums.insert(tid, id);

        let mut elements = vec![];
        for product in &source.elements {
            let mut p = vec![];
            for term in &product.elements {
                p.push(term.finish(self));
            }
            elements.push(Product {
                id: tid,
                name: product.name,
                elements: p,
            });
        }

        self.grammar.sums[idx] = Sum {
            id: tid,
            name,
            elements,
        };

        id
    }

    fn push_product(&mut self, tid: TypeId) -> usize {
        if let Some(idx) = self.products.get(&tid) {
            return *idx;
        }
        let source = self.driver.products.get(&tid).unwrap();
        let name = source.name;

        let idx = self.products.len();
        self.grammar.products.push(Product {
            id: tid,
            name,
            elements: vec![],
        });

        let id = self.push(Term::Product { id: idx });
        self.products.insert(tid, id);

        let mut elements = vec![];
        for term in &source.elements {
            elements.push(term.finish(self));
        }

        self.grammar.products[idx] = Product {
            id: tid,
            name,
            elements,
        };

        id
    }

    fn push_list(&mut self, tid: TypeId) -> usize {
        if let Some(idx) = self.lists.get(&tid) {
            return *idx;
        }
        let source = self.driver.lists.get(&tid).unwrap();
        let name = source.name;

        let idx = self.lists.len();
        self.grammar.lists.push(List {
            id: tid,
            name,
            len: 0,
            value: 0,
        });

        let id = self.push(Term::List { id: idx });
        self.lists.insert(tid, id);

        let len = source.len.finish(self);
        let value = source.value.finish(self);
        self.grammar.lists[idx] = List {
            id: tid,
            name,
            len,
            value,
        };

        id
    }
}

#[derive(Clone, Default, Debug)]
pub struct Driver {
    scope: Scope,
    depth: usize,
    products: BTreeMap<TypeId, Product<Term<TypeId>>>,
    sums: BTreeMap<TypeId, Sum<Term<TypeId>>>,
    lists: BTreeMap<TypeId, List<Term<TypeId>>>,
    options: driver::Options,
}

#[derive(Clone, Debug)]
pub struct Product<Term> {
    pub id: TypeId,
    pub name: &'static str,
    pub elements: Vec<Term>,
}

#[derive(Clone, Debug)]
pub struct Sum<Term> {
    pub id: TypeId,
    pub name: &'static str,
    pub elements: Vec<Product<Term>>,
}

#[derive(Clone, Debug)]
pub struct List<Term> {
    pub id: TypeId,
    pub name: &'static str,
    pub len: Term,
    pub value: Term,
}

impl Driver {
    pub fn finish(mut self) -> Grammar {
        let mut grammar = Grammar::default();
        let terms = core::mem::take(&mut self.scope.terms);

        if terms.is_empty() {
            return grammar;
        }

        if terms.len() > 1 {
            todo!("make the root element a product");
        }

        let mut builder = Builder {
            grammar: &mut grammar,
            driver: &self,
            terms: Default::default(),
            products: Default::default(),
            sums: Default::default(),
            lists: Default::default(),
        };

        let root = terms[0].finish(&mut builder);

        grammar.root = root;

        grammar
    }

    fn enter<F: FnOnce(&mut Self, &mut Scope) -> R, R>(&mut self, f: F) -> R {
        let mut current = self.take();
        let result = f(self, &mut current);
        self.scope = current;
        result
    }

    fn term<F: FnOnce(&mut Self)>(&mut self, f: F) -> Term<TypeId> {
        self.enter(|driver, _parent| {
            f(driver);
            driver.take_term()
        })
    }

    fn take(&mut self) -> Scope {
        core::mem::take(&mut self.scope)
    }

    fn take_term(&mut self) -> Term<TypeId> {
        assert!(self.scope.terms.len() <= 1, "{:?}", self.scope);
        self.scope.terms.pop().unwrap_or(Term::Constant)
    }
}

#[derive(Clone, Copy, Default, Debug, PartialEq, Eq, Hash)]
pub struct IntegerRange<T> {
    min: T,
    max: T,
    empty: bool,
}

impl IntegerRange<u128> {
    #[inline]
    pub fn as_element_count(&self) -> usize {
        if self.empty {
            return 0;
        }

        (self.max - self.min + 1)
            .try_into()
            .expect("element count too large")
    }
}

#[derive(Clone, Copy, Default, Debug)]
pub struct FloatRange<T> {
    min: T,
    max: T,
}

macro_rules! impl_float_range {
    ($ty:ident, $int:ident) => {
        impl PartialEq for FloatRange<$ty> {
            fn eq(&self, other: &Self) -> bool {
                self.cmp(other) == core::cmp::Ordering::Equal
            }
        }

        impl Eq for FloatRange<$ty> {}

        impl PartialOrd for FloatRange<$ty> {
            fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
                Some(self.cmp(other))
            }
        }

        impl Ord for FloatRange<$ty> {
            fn cmp(&self, other: &Self) -> core::cmp::Ordering {
                let l_min = self.min as $int;
                let l_max = self.max as $int;
                let r_min = other.min as $int;
                let r_max = other.max as $int;
                l_min.cmp(&r_min).then(l_max.cmp(&r_max))
            }
        }

        impl core::hash::Hash for FloatRange<$ty> {
            fn hash<H: core::hash::Hasher>(&self, h: &mut H) {
                (self.min as $int).hash(h);
                (self.max as $int).hash(h);
            }
        }
    };
}

impl_float_range!(f32, u32);
impl_float_range!(f64, u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Term<CompoundId = usize> {
    Constant,
    Bool,
    SignedInteger { range: IntegerRange<i128> },
    UnsignedInteger { range: IntegerRange<u128> },
    Float32 { range: FloatRange<f32> },
    Float64 { range: FloatRange<f64> },
    Char { range: IntegerRange<u32> },
    Sum { id: CompoundId },
    Product { id: CompoundId },
    List { id: CompoundId },
    Bytes { min: usize, max: Option<usize> },
}

impl Term<TypeId> {
    fn finish(self, grammar: &mut Builder) -> usize {
        match self {
            Self::Constant => grammar.push(Term::Constant),
            Self::Bool => grammar.push(Term::Bool),
            Self::SignedInteger { range } => grammar.push(Term::SignedInteger { range }),
            Self::UnsignedInteger { range } => grammar.push(Term::UnsignedInteger { range }),
            Self::Float32 { range } => grammar.push(Term::Float32 { range }),
            Self::Float64 { range } => grammar.push(Term::Float64 { range }),
            Self::Char { range } => grammar.push(Term::Char { range }),
            Self::Sum { id } => grammar.push_sum(id),
            Self::Product { id } => grammar.push_product(id),
            Self::List { id } => grammar.push_list(id),
            Self::Bytes { min, max } => grammar.push(Term::Bytes { min, max }),
        }
    }
}

#[derive(Clone, Default, Debug)]
struct Scope {
    terms: Vec<Term<TypeId>>,
}

macro_rules! gen_integer {
    ($name:ident, $constant:ident, $ty:ty, $integer:ty, $term:ident, $min:expr, $convert:expr) => {
        fn $constant(&mut self, value: $ty) -> Option<$ty> {
            self.$name(Bound::Included(&value), Bound::Included(&value))
        }

        fn $name(&mut self, min: Bound<&$ty>, max: Bound<&$ty>) -> Option<$ty> {
            use Bound::*;

            let mut range = IntegerRange {
                min: 0,
                max: 0,
                empty: true,
            };

            match (min, max) {
                (Unbounded, Unbounded) => {
                    range.min = $min as _;
                    range.max = <$ty>::MAX as _;
                    range.empty = false;
                }
                (Unbounded, Included(max)) => {
                    range.min = $min as _;
                    range.max = *max as _;
                    range.empty = range.min > range.max;
                }
                (Unbounded, Excluded(max)) => {
                    range.min = $min as _;
                    range.max = *max as $integer - 1;
                    range.empty = range.min >= range.max;
                }
                (Included(min), Unbounded) => {
                    range.min = *min as _;
                    range.max = <$ty>::MAX as _;
                    range.empty = range.min > range.max;
                }
                (Included(min), Included(max)) => {
                    range.min = *min as _;
                    range.max = *max as _;
                    range.empty = range.min > range.max;
                }
                (Included(min), Excluded(max)) => {
                    range.min = *min as _;
                    range.max = *max as $integer - 1;
                    range.empty = range.min > range.max;
                }
                (Excluded(min), Unbounded) => {
                    range.min = *min as $integer + 1;
                    range.max = <$ty>::MAX as _;
                    range.empty = range.min >= range.max;
                }
                (Excluded(min), Included(max)) => {
                    range.min = *min as $integer + 1;
                    range.max = *max as _;
                    range.empty = range.min >= range.max;
                }
                (Excluded(min), Excluded(max)) => {
                    range.min = *min as $integer + 1;
                    range.max = *max as $integer - 1;
                    range.empty = range.min >= range.max;
                }
            }

            let min = ($convert)(range.min);

            self.scope.terms.push(Term::$term { range });

            min
        }
    };
}

macro_rules! gen_signed {
    ($name:ident, $constant:ident, $ty:ty) => {
        gen_integer!(
            $name,
            $constant,
            $ty,
            i128,
            SignedInteger,
            <$ty>::MIN,
            |v| Some(v as $ty)
        );
    };
}

macro_rules! gen_unsigned {
    ($name:ident, $constant:ident, $ty:ty) => {
        gen_integer!(
            $name,
            $constant,
            $ty,
            u128,
            UnsignedInteger,
            <$ty>::MIN,
            |v| Some(v as $ty)
        );
    };
}

macro_rules! gen_method {
    ($name:ident, $constant:ident, $ty:ty) => {
        fn $name(&mut self, _min: Bound<&$ty>, _max: Bound<&$ty>) -> Option<$ty> {
            todo!()
        }
    };
}

impl driver::Driver for Driver {
    fn depth(&self) -> usize {
        self.depth
    }

    fn set_depth(&mut self, depth: usize) {
        self.depth = depth;
    }

    fn max_depth(&self) -> usize {
        self.options.max_depth_or_default()
    }

    #[inline]
    fn enter_product<Output, F, R>(&mut self, mut f: F) -> Option<R>
    where
        Output: 'static,
        F: FnMut(&mut Self) -> Option<R>,
    {
        let id = TypeId::of::<Output>();
        let name = type_name::<Output>();
        if self.products.contains_key(&id) {
            return self.enter(|driver, parent| {
                let result = f(driver);
                parent.terms.push(Term::Product { id });
                result
            });
        }

        // insert a placeholder
        self.products.insert(
            id,
            Product {
                id,
                name,
                elements: Default::default(),
            },
        );

        self.enter(|driver, parent| {
            let result = f(driver);
            let scope = driver.take();
            let ty = Product {
                id,
                name,
                elements: scope.terms,
            };
            driver.products.insert(id, ty);
            parent.terms.push(Term::Product { id });
            result
        })
    }

    #[inline]
    fn enter_sum<Output, F, R>(
        &mut self,
        element_names: Option<&'static [&'static str]>,
        num_elements: usize,
        base_case: usize,
        mut f: F,
    ) -> Option<R>
    where
        Output: 'static,
        F: FnMut(&mut Self, usize) -> Option<R>,
    {
        let id = TypeId::of::<Output>();
        let name = type_name::<Output>();
        if self.sums.contains_key(&id) {
            return self.enter(|driver, parent| {
                let result = f(driver, base_case);
                parent.terms.push(Term::Sum { id });
                result
            });
        }

        // insert a placeholder
        self.sums.insert(
            id,
            Sum {
                id,
                name,
                elements: Default::default(),
            },
        );

        self.enter(|driver, parent| {
            let names = element_names.unwrap_or(&[]);
            let mut elements = vec![];
            for idx in 0..num_elements {
                let _ = f(driver, idx);
                let scope = driver.take();
                elements.push(Product {
                    id,
                    name: names.get(idx).copied().unwrap_or(""),
                    elements: scope.terms,
                });
            }

            let ty = Sum { id, name, elements };

            driver.sums.insert(id, ty);
            parent.terms.push(Term::Sum { id });

            f(driver, base_case)
        })
    }

    #[inline]
    fn enter_list<Output, F, L, R>(&mut self, lens: &L, mut f: F) -> Option<R>
    where
        Output: 'static,
        F: FnMut(&mut Self, usize) -> Option<R>,
        L: ValueGenerator<Output = usize>,
    {
        let id = TypeId::of::<Output>();
        let name = type_name::<Output>();
        if self.lists.contains_key(&id) {
            return self.enter(|driver, parent| {
                let result = f(driver, 1);
                parent.terms.push(Term::List { id });
                result
            });
        }

        // insert a placeholder
        self.lists.insert(
            id,
            List {
                id,
                name,
                len: Term::Constant,
                value: Term::Constant,
            },
        );

        self.enter(|driver, parent| {
            let len = driver.term(|driver| {
                let _ = lens.generate(driver);
            });

            let mut result = None;
            let value = driver.term(|driver| {
                // pass a single list item just to get the generator grammar
                result = f(driver, 1);
            });

            let _scope = driver.take();
            let ty = List {
                id,
                name,
                len,
                value,
            };
            driver.lists.insert(id, ty);
            parent.terms.push(Term::List { id });
            result
        })
    }

    fn gen_variant(&mut self, variants: usize, base_case: usize) -> Option<usize> {
        // TODO do we need to do anything special here?
        let _ = variants;
        Some(base_case)
    }

    gen_unsigned!(gen_u8, gen_u8_constant, u8);
    gen_signed!(gen_i8, gen_i8_constant, i8);
    gen_unsigned!(gen_u16, gen_u16_constant, u16);
    gen_signed!(gen_i16, gen_i16_constant, i16);
    gen_unsigned!(gen_u32, gen_u32_constant, u32);
    gen_signed!(gen_i32, gen_i32_constant, i32);
    gen_unsigned!(gen_u64, gen_u64_constant, u64);
    gen_signed!(gen_i64, gen_i64_constant, i64);
    gen_unsigned!(gen_u128, gen_u128_constant, u128);
    gen_signed!(gen_i128, gen_i128_constant, i128);
    gen_unsigned!(gen_usize, gen_usize_constant, usize);
    gen_signed!(gen_isize, gen_isize_constant, isize);
    gen_method!(gen_f32, gen_f32_constant, f32);
    gen_method!(gen_f64, gen_f64_constant, f64);
    gen_integer!(
        gen_char,
        gen_char_constant,
        char,
        u32,
        Char,
        char::from_u32(0).unwrap(),
        char::from_u32
    );

    fn gen_bool(&mut self, _probability: Option<f32>) -> Option<bool> {
        self.scope.terms.push(Term::Bool);
        Some(false)
    }

    fn gen_from_bytes<Hint, Gen, T>(&mut self, hint: Hint, mut gen: Gen) -> Option<T>
    where
        Hint: FnOnce() -> (usize, Option<usize>),
        Gen: FnMut(&[u8]) -> Option<(usize, T)>,
    {
        let (min, max) = hint();
        self.scope.terms.push(Term::Bytes { min, max });
        let bytes = vec![0u8; min];
        let (_, value) = gen(&bytes)?;
        Some(value)
    }
}
