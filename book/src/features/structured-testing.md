# Structured Testing

In addition to generating random byte slices, `bolero` supports generating well-formed types, with the [`bolero-generator`](https://docs.rs/bolero-generator/) crate.

## Operation Example

Let's supposes we've implemented a `MySet` data structure. It has 3 operations:

* `insert(value)` - inserts an value into the set
* `remove(value)` - removes an value from the set
* `clear()` - removes all values from the set

The operations can easily be modeled as an `enum`:

```rust
use bolero::generator::TypeGenerator;

#[derive(Debug, TypeGenerator)]
enum Operation {
    Insert(u64),
    Remove(u64),
    Clear,
}
```

Note that we've added `TypeGenerator` to the list of derives. This enables `bolero` to generate random values for `Operation`. We can combine that with a `Vec<Operation>` and get a list of operations to perform on our `MySet` data structure.

```rust
use bolero::{check, generator::*};
use my_set::MySet;

#[derive(Debug, TypeGenerator)]
enum Operation {
    Insert(u64),
    Remove(u64),
    Clear,
}

fn main() {
    check!()
        .with_type::<Vec<Operation>>()
        .for_each(|operations| {
            let mut set = MySet::new();

            for operation in operations.iter() {
                match operation {
                    Operation::Insert(value) => {
                        set.insert(value);
                    }
                    Operation::Remove(value) => {
                        set.remove(value);
                    }
                    Operation::Clear => {
                        set.clear();
                    }
                }
            }
        })
}
```

## Controlling The Number Of Operations Generated

Using `check!().with_type::<Vec<T>>()` will generate vectors with lengths in the range `0..=64`. If you need more control over the number of elements being generated you can instead use `.with_generator` and provide a customized generator:

```rust
# use bolero::{check, generator::*};
use bolero::gen;
# use my_set::MySet;

# #[derive(Debug, TypeGenerator)]
# enum Operation {
#     Insert(u64),
#     Remove(u64),
#     Clear,
# }
#
fn main() {
    check!()
        // Generate 0 to 200 operations
        .with_generator(gen::<Vec<Operation>>().with().len(0..=200))
        .for_each(|operations| {
#             let mut set = MySet::new();
#
#             for operation in operations.iter() {
#                 match operation {
#                     Operation::Insert(value) => {
#                         set.insert(value);
#                     }
#                     Operation::Remove(value) => {
#                         set.remove(value);
#                     }
#                     Operation::Clear => {
#                         set.clear();
#                     }
#                 }
#             }
#         })
# }
```

## Using Test Oracles

The basic test we constructed above will make sure we don't panic on any of the list of operations. We can take it to the next step by using a test oracle to make sure the behavior of `MySet` is actually correct. Here we'll use `HashSet` from the `std` library:

```rust
use bolero::{check, generator::*};
use my_set::MySet;
use std::collections::HashSet;

#[derive(Debug, TypeGenerator)]
enum Operation {
    Insert(u64),
    Remove(u64),
    Clear,
}

fn main() {
    check!()
        .with_type::<Vec<Operation>>()
        .for_each(|operations| {
            let mut set = MySet::new();
            let mut oracle = HashSet::new();

            for operation in operations.iter() {
                match operation {
                    Operation::Insert(value) => {
                        set.insert(value);
                        oracle.insert(value);
                    }
                    Operation::Remove(value) => {
                        set.remove(value);
                        oracle.remove(value);
                    }
                    Operation::Clear => {
                        set.clear();
                        oracle.clear();
                    }
                }
            }

            assert!(set.iter().eq(oracle.iter()));
        })
}
```
