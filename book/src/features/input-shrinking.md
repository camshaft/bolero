# Input Shrinking

`bolero` supports input shrinking for all of the provided testing engines.

## What is it?

From [PropEr Testing](https://propertesting.com/book_shrinking.html):

> Shrinking is the mechanism by which a property-based testing framework can be told how to simplify failure cases enough to let it figure out exactly what the minimal reproducible case is.
>
> Sometimes the input required to find a failure can be fairly large or complex. Finding the initial failing case may have required hundreds of attempts, and it may contain vast amounts of irrelevant information. The framework will then attempt to reduce that data set through shrinking. It generally does so by transforming all the generators used and trying to bring them back towards their own zero point.

## Example

Let's suppose we're testing a `MySet` data structure:

```rust
use bolero::{fuzz, generator::*};
use my_set::MySet;

#[derive(Debug, TypeGenerator)]
enum Operation {
    Insert(u64),
    Remove(u64),
    Clear,
}

fn main() {
    fuzz!()
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

Assume there's hypothetical scenario in which adding 16 elements to `MySet` causes a panic. Without shrinking, the randomly-generated inputs can be difficult to interpret:

```
======================== Test Failure ========================

Input:
[
    Insert(9693583160302274182),
    Insert(15890536247564076678),
    Clear,
    Insert(15914819332679195868),
    Insert(9717884937115065564),
    Insert(15914645609842007260),
    Insert(18446738425238052060),
    Remove(15912577393975689024),
    Insert(15338377272073444572),
    Insert(15914838024242123988),
    Insert(11228695243045262548),
    Insert(11212726789901900955),
    Insert(11212726789901884315),
    Insert(11212726789901884316),
    Insert(11212726789901884317),
    Insert(11212726789901884318),
    Insert(11212726789901884319),
    Insert(11212726789901884311),
    Insert(11212726789901884312),
    Insert(11212726789901884313),
    Insert(11212726789901884314),
    Insert(9727500806739001343),
    Insert(9693583160302274182),
    Insert(9693583160302274182),
    Insert(5714873654208093419),
    Remove(5714873654208057167),
    Remove(16717362667219255119),
    Insert(9726366166670698728),
    Insert(9727642152175306374),
    Remove(18446181099529437184),
    Insert(18446744073709551615),
    Insert(15336116641675083775),
    Remove(11212726789901884372),
    Insert(11212726789901884315),
    Insert(11212666079612935067)
]

Error:
panicked at 'internal assertion', src/lib.rs:16:17
```

After shrinking the input, it becomes more obvious how to trigger the bug:

```
======================== Test Failure ========================

Input:
[
    Insert(0),
    Insert(1),
    Insert(2),
    Insert(3),
    Insert(4),
    Insert(5),
    Insert(6),
    Insert(7),
    Insert(8),
    Insert(9),
    Insert(10),
    Insert(11),
    Insert(12),
    Insert(13),
    Insert(14),
    Insert(15),
]

Error:
panicked at 'internal assertion', src/lib.rs:16:17
```
