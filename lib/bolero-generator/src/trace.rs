#![cfg_attr(kani, allow(dead_code))]

use super::ValueGenerator;
use core::{any::type_name, ops::Bound};

pub struct Trace<G: ValueGenerator>(G);

impl<G: ValueGenerator> Trace<G> {
    #[inline]
    pub fn new(g: G) -> Self {
        Self(g)
    }
}

#[cfg(not(kani))]
impl<G: ValueGenerator> ValueGenerator for Trace<G> {
    type Output = G::Output;

    #[inline]
    fn generate<D: crate::Driver>(&self, driver: &mut D) -> Option<Self::Output> {
        let mut driver = Driver {
            inner: driver,
            formatter: Default::default(),
        };
        self.0.generate(&mut driver)
    }

    #[inline]
    fn mutate<D: crate::Driver>(&self, driver: &mut D, value: &mut Self::Output) -> Option<()> {
        let mut driver = Driver {
            inner: driver,
            formatter: Default::default(),
        };
        self.0.mutate(&mut driver, value)
    }

    #[inline]
    fn driver_cache<D: crate::Driver>(&self, driver: &mut D, value: Self::Output) {
        let mut driver = Driver {
            inner: driver,
            formatter: Default::default(),
        };
        self.0.driver_cache(&mut driver, value)
    }
}

#[cfg(kani)]
impl<G: ValueGenerator> ValueGenerator for Trace<G> {
    type Output = G::Output;

    #[inline]
    fn generate<D: crate::Driver>(&self, driver: &mut D) -> Option<Self::Output> {
        self.0.generate(driver)
    }

    #[inline]
    fn mutate<D: crate::Driver>(&self, driver: &mut D, value: &mut Self::Output) -> Option<()> {
        self.0.mutate(driver, value)
    }

    #[inline]
    fn driver_cache<D: crate::Driver>(&self, driver: &mut D, value: Self::Output) {
        self.0.driver_cache(driver, value)
    }
}

struct Formatter<O: std::io::Write> {
    indent: usize,
    needs_newline: bool,
    output: O,
}

impl Default for Formatter<std::io::Stderr> {
    fn default() -> Self {
        Self::new(std::io::stderr())
    }
}

impl<O: std::io::Write> Formatter<O> {
    fn new(output: O) -> Self {
        Self {
            indent: 0,
            needs_newline: false,
            output,
        }
    }

    #[inline]
    fn emit_prim<T: core::fmt::Debug>(&mut self, name: &str, result: &Option<T>) {
        match result {
            Some(v) => self.writeln(format_args!("{name} -> {v:?}")),
            None => self.writeln(format_args!("{name} -> <None>")),
        }
    }

    fn writeln(&mut self, f: impl core::fmt::Display) {
        self.write(format_args!("{f}\n"))
    }

    fn write(&mut self, f: impl core::fmt::Display) {
        if core::mem::take(&mut self.needs_newline) {
            let _ = writeln!(self.output);
        }
        for _ in 0..self.indent {
            let _ = write!(self.output, "    ");
        }
        let _ = write!(self.output, "{f}");
    }
}

struct Driver<'a, D: crate::Driver, O: std::io::Write> {
    inner: &'a mut D,
    formatter: Formatter<O>,
}

impl<'a, D: crate::Driver, O: std::io::Write> Driver<'a, D, O> {
    #[inline]
    fn emit_block<F: FnOnce(&mut Self) -> Option<Ret>, Ret>(
        &mut self,
        name: impl core::fmt::Display,
        f: F,
    ) -> Option<Ret> {
        self.formatter.write(format_args!("{name} {{"));
        self.formatter.indent += 1;
        self.formatter.needs_newline = true;
        let res = f(self);
        self.formatter.indent -= 1;
        let close = match &res {
            Some(_) => "}",
            None => "} -> <None>",
        };
        if core::mem::take(&mut self.formatter.needs_newline) {
            let indent = core::mem::take(&mut self.formatter.indent);
            self.formatter.writeln(close);
            self.formatter.indent = indent;
        } else {
            self.formatter.writeln(close);
        }
        res
    }

    fn emit_sum_variant<F, Ret>(
        &mut self,
        name: &str,
        idx: Option<usize>,
        element_names: Option<&'static [&'static str]>,
        mut f: F,
    ) -> Option<Ret>
    where
        F: FnMut(&mut Self, usize) -> Option<Ret>,
    {
        match (idx, element_names) {
            (None, _) => {
                self.formatter
                    .writeln(format_args!("{name} {{}} -> <None>"));
                None
            }
            (Some(idx), Some(names)) => self
                .emit_block(format_args!("{name} {}", names[idx]), |driver| {
                    f(driver, idx)
                }),
            (Some(idx), None) => {
                self.emit_block(format_args!("{name} {idx:?}"), |driver| f(driver, idx))
            }
        }
    }
}

macro_rules! gen_prim {
    ($name:ident, $ty:ident) => {
        #[inline]
        fn $name(&mut self, min: Bound<&$ty>, max: Bound<&$ty>) -> Option<$ty> {
            let res = self.inner.$name(min, max);
            self.formatter.emit_prim(stringify!($ty), &res);
            res
        }
    };
}

impl<'a, D: crate::Driver, O: std::io::Write> crate::Driver for Driver<'a, D, O> {
    #[inline]
    fn depth(&self) -> usize {
        self.inner.depth()
    }

    #[inline]
    fn set_depth(&mut self, depth: usize) {
        self.inner.set_depth(depth)
    }

    #[inline]
    fn max_depth(&self) -> usize {
        self.inner.max_depth()
    }

    #[inline]
    fn gen_variant(&mut self, variants: usize, base_case: usize) -> Option<usize> {
        let res = self.inner.gen_variant(variants, base_case);
        self.formatter.emit_prim("variant", &res);
        res
    }

    gen_prim!(gen_u8, u8);
    gen_prim!(gen_i8, i8);
    gen_prim!(gen_u16, u16);
    gen_prim!(gen_i16, i16);
    gen_prim!(gen_u32, u32);
    gen_prim!(gen_i32, i32);
    gen_prim!(gen_u64, u64);
    gen_prim!(gen_i64, i64);
    gen_prim!(gen_u128, u128);
    gen_prim!(gen_i128, i128);
    gen_prim!(gen_usize, usize);
    gen_prim!(gen_isize, isize);
    gen_prim!(gen_f32, f32);
    gen_prim!(gen_f64, f64);
    gen_prim!(gen_char, char);

    #[inline]
    fn gen_bool(&mut self, probability: Option<f32>) -> Option<bool> {
        let res = self.inner.gen_bool(probability);
        self.formatter.emit_prim("bool", &res);
        res
    }

    #[inline]
    fn gen_from_bytes<Hint, Gen, T>(&mut self, hint: Hint, mut gen: Gen) -> Option<T>
    where
        Hint: FnOnce() -> (usize, Option<usize>),
        Gen: FnMut(&[u8]) -> Option<(usize, T)>,
    {
        self.inner.gen_from_bytes(hint, |bytes| {
            let res = gen(bytes);
            self.formatter
                .emit_prim("bytes", &res.as_ref().map(|(len, _value)| *len));
            res
        })
    }

    #[inline]
    fn enter_product<Output, F, Ret>(&mut self, mut f: F) -> Option<Ret>
    where
        Output: 'static,
        F: FnMut(&mut Self) -> Option<Ret>,
    {
        self.emit_block(
            format_args!("product {}", type_name::<Output>()),
            |driver| f(driver),
        )
    }

    #[inline]
    fn enter_sum<Output, F, Ret>(
        &mut self,
        element_names: Option<&'static [&'static str]>,
        elements: usize,
        base_case: usize,
        f: F,
    ) -> Option<Ret>
    where
        Output: 'static,
        F: FnMut(&mut Self, usize) -> Option<Ret>,
    {
        self.emit_block(format_args!("sum {}", type_name::<Output>()), |driver| {
            // don't emit information for this generator
            let idx = driver.inner.gen_variant(elements, base_case);
            driver.emit_sum_variant("variant", idx, element_names, f)
        })
    }

    #[inline]
    fn enter_list<Output, F, Len, Ret>(&mut self, lens: &Len, f: F) -> Option<Ret>
    where
        Output: 'static,
        F: FnMut(&mut Self, usize) -> Option<Ret>,
        Len: ValueGenerator<Output = usize>,
    {
        self.emit_block(format_args!("list {}", type_name::<Output>()), |driver| {
            driver.depth_guard(|driver| {
                // don't emit information for this generator
                let len = lens.generate(driver.inner);
                driver.emit_sum_variant("len", len, None, f)
            })
        })
    }

    #[inline]
    fn enter_combinator<Output, F, Ret>(&mut self, mut f: F) -> Option<Ret>
    where
        Output: 'static,
        F: FnMut(&mut Self) -> Option<Ret>,
    {
        f(self)
    }

    #[inline]
    fn cache_put<T: 'static>(&mut self, value: T) {
        self.inner.cache_put(value)
    }

    #[inline]
    fn cache_get<T: 'static>(&mut self) -> Option<T> {
        self.inner.cache_get()
    }
}

#[cfg(test)]
mod tests {
    use crate::{Driver, TypeGenerator, ValueGenerator};
    use std::cell::RefCell;

    pub struct Trace<G: ValueGenerator> {
        g: G,
        out: RefCell<Vec<u8>>,
    }

    impl<G: ValueGenerator> Trace<G> {
        #[inline]
        pub fn new(g: G) -> Self {
            Self {
                g,
                out: RefCell::new(vec![]),
            }
        }
    }

    impl<G: ValueGenerator> ValueGenerator for Trace<G> {
        type Output = G::Output;

        #[inline]
        fn generate<D: crate::Driver>(&self, driver: &mut D) -> Option<Self::Output> {
            let mut out = self.out.borrow_mut();
            out.clear();
            let out = std::io::Cursor::new(&mut *out);
            let mut driver = super::Driver {
                inner: driver,
                formatter: super::Formatter::new(out),
            };
            self.g.generate(&mut driver)
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq, TypeGenerator)]
    struct Empty {}

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Even {
        pub value: u8,
    }

    impl TypeGenerator for Even {
        #[inline]
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            driver.enter_product::<Self, _, _>(|driver| {
                let value = driver.gen()?;
                // return `None` on odds. This can be used to test what happens when generators fail.
                if value % 2 == 0 {
                    Some(Self { value })
                } else {
                    None
                }
            })
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq, TypeGenerator)]
    enum EvenTree {
        Leaf(Even),
        Pair(Box<EvenTree>, Box<EvenTree>),
    }

    fn run<G: ValueGenerator>(slice: &[u8], g: G, expected: &str) {
        let mut driver = crate::driver::ByteSliceDriver::new(slice, &Default::default());
        let g = Trace::new(g);
        let _ = g.generate(&mut driver);
        let out = g.out.borrow();
        let out = core::str::from_utf8(&out).unwrap();
        assert_eq!(out, expected.trim_start())
    }

    #[test]
    fn empty_test() {
        run(
            &[],
            Empty::gen(),
            r#"
product bolero_generator::trace::tests::Empty {}
"#,
        )
    }

    #[test]
    fn even_test() {
        run(
            &[],
            Even::gen(),
            r#"
product bolero_generator::trace::tests::Even {
    u8 -> 0
}
"#,
        );
    }

    #[test]
    fn odd_test() {
        run(
            &[1],
            Even::gen(),
            r#"
product bolero_generator::trace::tests::Even {
    u8 -> 1
} -> <None>
"#,
        );
    }

    #[test]
    fn tree_even_test() {
        run(
            &[],
            EvenTree::gen(),
            r#"
sum bolero_generator::trace::tests::EvenTree {
    variant Leaf {
        product bolero_generator::trace::tests::Even {
            u8 -> 0
        }
    }
}
"#,
        );
    }

    #[test]
    fn nested_tree_test() {
        run(
            &[255],
            EvenTree::gen(),
            r#"
sum bolero_generator::trace::tests::EvenTree {
    variant Pair {
        sum bolero_generator::trace::tests::EvenTree {
            variant Leaf {
                product bolero_generator::trace::tests::Even {
                    u8 -> 0
                }
            }
        }
        sum bolero_generator::trace::tests::EvenTree {
            variant Leaf {
                product bolero_generator::trace::tests::Even {
                    u8 -> 0
                }
            }
        }
    }
}
"#,
        );
    }

    #[test]
    fn nested_tree_left_odd_test() {
        run(
            &[255, 0, 1],
            EvenTree::gen(),
            r#"
sum bolero_generator::trace::tests::EvenTree {
    variant Pair {
        sum bolero_generator::trace::tests::EvenTree {
            variant Leaf {
                product bolero_generator::trace::tests::Even {
                    u8 -> 1
                } -> <None>
            } -> <None>
        } -> <None>
    } -> <None>
} -> <None>
"#,
        );
    }

    #[test]
    fn nested_tree_right_odd_test() {
        run(
            &[255, 0, 0, 0, 1],
            EvenTree::gen(),
            r#"
sum bolero_generator::trace::tests::EvenTree {
    variant Pair {
        sum bolero_generator::trace::tests::EvenTree {
            variant Leaf {
                product bolero_generator::trace::tests::Even {
                    u8 -> 0
                }
            }
        }
        sum bolero_generator::trace::tests::EvenTree {
            variant Leaf {
                product bolero_generator::trace::tests::Even {
                    u8 -> 1
                } -> <None>
            } -> <None>
        } -> <None>
    } -> <None>
} -> <None>
"#,
        );
    }
}
