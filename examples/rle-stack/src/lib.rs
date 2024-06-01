use core::fmt;

thread_local! {
    static SHOULD_PANIC: bool = {
        #[cfg(bolero_should_panic)]
        return true;

        #[cfg(not(bolero_should_panic))]
        return std::env::var("SHOULD_PANIC").is_ok();
    };
}

type Counter = u16;

//= https://en.wikipedia.org/wiki/Run-length_encoding
//# Run-length encoding (RLE) is a form of lossless data compression in which
//# runs of data (sequences in which the same data value occurs in many consecutive
//# data elements) are stored as a single data value and count, rather than as
//# the original run.

pub struct RleStack<T> {
    stack: Vec<Entry<T>>,
    len: usize,
}

impl<T> Default for RleStack<T> {
    fn default() -> Self {
        Self {
            stack: vec![],
            len: 0,
        }
    }
}

impl<T: fmt::Debug> fmt::Debug for RleStack<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RleStack")
            .field("stack", &self.stack)
            .field("len", &self.len)
            .finish()
    }
}

impl<T: Clone + Eq> RleStack<T> {
    pub fn push(&mut self, value: T) {
        self.len += 1;

        if let Some(prev) = self.stack.last_mut() {
            if prev.merge(&value) {
                return;
            }
        }

        self.stack.push(Entry::new(value));
    }

    pub fn pop(&mut self) -> Option<T> {
        let entry = self.stack.last_mut()?;

        self.len -= 1;

        if entry.additional == 0 {
            return self.stack.pop().map(|entry| entry.value);
        }
        entry.additional -= 1;
        Some(entry.value.clone())
    }

    pub fn clear(&mut self) {
        // inject faults into the model if configured
        if SHOULD_PANIC.with(|v| *v) {
            return;
        }

        self.len = 0;
        self.stack.clear();
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn iter(&self) -> Iter<T> {
        Iter {
            entry: 0,
            count: 0,
            stack: self,
        }
    }
}

pub struct Iter<'a, T> {
    entry: usize,
    count: Counter,
    stack: &'a RleStack<T>,
}

impl<'a, T> Iterator for Iter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        let entry = self.stack.stack.get(self.entry)?;

        if entry.additional <= self.count {
            self.entry += 1;
            self.count = 0;
        } else {
            self.count += 1;
        }

        Some(&entry.value)
    }
}

struct Entry<T> {
    value: T,
    additional: Counter,
}

impl<T: fmt::Debug> fmt::Debug for Entry<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Entry")
            .field("value", &self.value)
            .field("additional", &self.additional)
            .finish()
    }
}

impl<T> Entry<T> {
    pub fn new(value: T) -> Self {
        Self {
            value,
            additional: 0,
        }
    }
}

impl<T: Eq> Entry<T> {
    pub fn merge(&mut self, other: &T) -> bool {
        if &self.value == other {
            self.additional += 1;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests;
