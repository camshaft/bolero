use core::time::Duration;

#[derive(Clone, Debug, Default)]
pub struct Options {
    shrink_time: Option<Duration>,
    max_depth: Option<usize>,
    max_len: Option<usize>,
    exhaustive: bool,
}

impl Options {
    pub const DEFAULT_MAX_DEPTH: usize = 5;
    pub const DEFAULT_MAX_LEN: usize = 4096;
    pub const DEFAULT_SHRINK_TIME: Duration = Duration::from_secs(1);

    pub fn with_shrink_time(mut self, shrink_time: Duration) -> Self {
        self.shrink_time = Some(shrink_time);
        self
    }

    pub fn with_max_depth(mut self, max_depth: usize) -> Self {
        self.max_depth = Some(max_depth);
        self
    }

    pub fn with_max_len(mut self, max_len: usize) -> Self {
        self.max_len = Some(max_len);
        self
    }

    pub fn with_exhaustive(mut self, exhaustive: bool) -> Self {
        self.exhaustive = exhaustive;
        self
    }

    pub fn set_exhaustive(&mut self, exhaustive: bool) -> &mut Self {
        self.exhaustive = exhaustive;
        self
    }

    pub fn set_shrink_time(&mut self, shrink_time: Duration) -> &mut Self {
        self.shrink_time = Some(shrink_time);
        self
    }

    pub fn set_max_depth(&mut self, max_depth: usize) -> &mut Self {
        self.max_depth = Some(max_depth);
        self
    }

    pub fn set_max_len(&mut self, max_len: usize) -> &mut Self {
        self.max_len = Some(max_len);
        self
    }

    #[inline]
    pub fn exhaustive(&self) -> bool {
        self.exhaustive
    }

    #[inline]
    pub fn max_depth(&self) -> Option<usize> {
        self.max_depth
    }

    #[inline]
    pub fn max_len(&self) -> Option<usize> {
        self.max_len
    }

    #[inline]
    pub fn shrink_time(&self) -> Option<Duration> {
        self.shrink_time
    }

    #[inline]
    pub fn max_depth_or_default(&self) -> usize {
        self.max_depth.unwrap_or(Self::DEFAULT_MAX_DEPTH)
    }

    #[inline]
    pub fn max_len_or_default(&self) -> usize {
        self.max_len.unwrap_or(Self::DEFAULT_MAX_LEN)
    }

    #[inline]
    pub fn shrink_time_or_default(&self) -> Duration {
        self.shrink_time.unwrap_or(Self::DEFAULT_SHRINK_TIME)
    }

    #[inline]
    pub fn merge_from(&mut self, other: &Self) {
        macro_rules! merge {
            ($name:ident) => {
                if let Some($name) = other.$name {
                    self.$name = Some($name);
                }
            };
        }

        merge!(max_depth);
        merge!(max_len);
        merge!(shrink_time);
    }
}
