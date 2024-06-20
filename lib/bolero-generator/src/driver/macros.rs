macro_rules! gen_int {
    ($name:ident, $ty:ident) => {
        #[inline(always)]
        fn $name(&mut self, min: Bound<&$ty>, max: Bound<&$ty>) -> Option<$ty> {
            Uniform::sample(self, min, max)
        }
    };
}

macro_rules! gen_float {
    ($name:ident, $ty:ident) => {
        #[inline]
        fn $name(&mut self, min: Bound<&$ty>, max: Bound<&$ty>) -> Option<$ty> {
            use core::ops::RangeBounds;

            if let (Bound::Unbounded, Bound::Unbounded) = (min, max) {
                let mut bytes = [0u8; core::mem::size_of::<$ty>()];
                self.fill_bytes(&mut bytes)?;
                return Some(<$ty>::from_le_bytes(bytes));
            }

            // TODO make this all less biased
            if let Some(value) = self
                .$name(Bound::Unbounded, Bound::Unbounded)
                .filter(|value| (min, max).contains(value))
            {
                return Some(value);
            }

            match min {
                Bound::Included(&v) => Some(v),
                Bound::Excluded(&v) => Some(v + $ty::EPSILON),
                Bound::Unbounded => Some($ty::MIN),
            }
        }
    };
}

macro_rules! gen_from_bytes {
    () => {
        gen_int!(gen_u8, u8);

        gen_int!(gen_i8, i8);

        gen_int!(gen_u16, u16);

        gen_int!(gen_i16, i16);

        gen_int!(gen_u32, u32);

        gen_int!(gen_i32, i32);

        gen_int!(gen_u64, u64);

        gen_int!(gen_i64, i64);

        gen_int!(gen_u128, u128);

        gen_int!(gen_i128, i128);

        gen_int!(gen_usize, usize);

        gen_int!(gen_isize, isize);

        gen_float!(gen_f32, f32);

        gen_float!(gen_f64, f64);

        #[inline(always)]
        fn gen_char(&mut self, min: Bound<&char>, max: Bound<&char>) -> Option<char> {
            char::sample(self, min, max)
        }

        #[inline(always)]
        fn gen_bool(&mut self, probability: Option<f32>) -> Option<bool> {
            if let Some(probability) = probability {
                let value = self.sample_u32()? as f32 / u32::MAX as f32;
                Some(value < probability)
            } else {
                self.sample_bool()
            }
        }

        #[inline(always)]
        fn gen_variant(&mut self, variants: usize, base_case: usize) -> Option<usize> {
            if self.depth == self.max_depth {
                return Some(base_case);
            }

            Uniform::sample(self, Bound::Unbounded, Bound::Excluded(&variants))
        }
    };
}
