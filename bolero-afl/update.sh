#!/bin/bash -e

version=${1:-master}
project_dir="$(pwd)"
tmp_dir="$(mktemp -d)"

git clone https://github.com/google/AFL.git "$tmp_dir"
cd "$tmp_dir"
git checkout $version --force
rm -rf "$project_dir/afl/"
mkdir -p "$project_dir/afl/llvm_mode"
mv "$tmp_dir/llvm_mode/afl-llvm-rt.o.c" "$project_dir/afl/llvm_mode/"
mv $tmp_dir/*.c "$project_dir/afl"
mv $tmp_dir/*.h "$project_dir/afl"
mv $tmp_dir/LICENSE "$project_dir/afl"

function replace() {
    sed -i.bak -e "$1" "$2"
    rm "$2.bak"
}

SRC=$project_dir/afl/*.c
for f in $SRC
do
    name=$(basename "$f" .c | sed 's/-/_/g')
    replace "s/int main/int ${name}_main/" $f
done

# make cycle count configurable
replace \
    's/ cycles_wo_finds > 100/ cycles_wo_finds > bolero_afl_max_cycles()/' \
    "$project_dir/afl/afl-fuzz.c"

# insert the utility header
replace \
    's/#include "hash.h"/#include "hash.h"\'$'\n#include "..\/src\/bolero-afl-util.h"/' \
    "$project_dir/afl/afl-fuzz.c"
