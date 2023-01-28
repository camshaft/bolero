macro_rules! gen_int {
    ($name:ident, $ty:ident) => {
        #[inline]
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

            // if we're in direct mode, just sample a value and check if it's within the provided range
            if self.mode() == DriverMode::Direct {
                return self
                    .$name(Bound::Unbounded, Bound::Unbounded)
                    .filter(|value| (min, max).contains(value));
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

        #[inline]
        fn gen_char(&mut self, min: Bound<&char>, max: Bound<&char>) -> Option<char> {
            char::sample(self, min, max)
        }

        #[inline]
        fn gen_bool(&mut self, probability: Option<f32>) -> Option<bool> {
            if let Some(probability) = probability {
                let value = self.gen_u32(Bound::Unbounded, Bound::Unbounded)? as f32
                    / core::u32::MAX as f32;
                Some(value < probability)
            } else {
                let value: u8 = self.gen_u8(Bound::Unbounded, Bound::Unbounded)?;
                Some(value < (u8::MAX / 2))
            }
        }

        fn gen_from_bytes<Gen, T>(&mut self, len: RangeInclusive<usize>, mut gen: Gen) -> Option<T>
        where
            Gen: FnMut(&[u8]) -> Option<(usize, T)>,
        {
            const ABUSIVE_SIZE: usize = 1024;
            const MIN_INCREASE: usize = 32;

            match self.mode() {
                DriverMode::Direct => {
                    let len = match (len.start(), len.end()) {
                        (s, e) if s == e => *s,
                        (s, e) => self.gen_usize(Bound::Included(s), Bound::Included(e))?,
                    };
                    let mut data = vec![0; len];
                    self.peek_bytes(0, &mut data)?;
                    match gen(&data) {
                        None => None,
                        Some((consumed, res)) => {
                            self.consume_bytes(consumed);
                            Some(res)
                        }
                    }
                }
                DriverMode::Forced => {
                    let init_len = len.start()
                        + self.gen_usize(
                            Bound::Included(&0),
                            Bound::Included(&std::cmp::min(ABUSIVE_SIZE, len.end() - len.start())),
                        )?;
                    let mut data = vec![0; init_len];
                    self.peek_bytes(0, &mut data)?;
                    loop {
                        match gen(&data) {
                            Some((consumed, res)) => {
                                self.consume_bytes(consumed);
                                return Some(res);
                            }
                            None => {
                                let max_additional_size = std::cmp::min(
                                    ABUSIVE_SIZE,
                                    len.end().saturating_sub(data.len()),
                                );
                                if max_additional_size == 0 {
                                    self.consume_bytes(data.len());
                                    return None; // we actually tried feeding the max amount of data already
                                }
                                let additional_size = self.gen_usize(
                                    Bound::Included(&std::cmp::min(
                                        MIN_INCREASE,
                                        max_additional_size,
                                    )),
                                    Bound::Included(&max_additional_size),
                                )?;
                                let previous_len = data.len();
                                data.resize(data.len() + additional_size, 0);
                                self.peek_bytes(previous_len, &mut data[previous_len..]);
                            }
                        }
                    }
                }
            }
        }
    };
}
