#!/bin/bash -e

version=${1:-master}
project_dir="$(pwd)"
tmp_dir="$(mktemp -d)"
honggfuzz_dir="$project_dir/honggfuzz/"

git clone https://github.com/google/honggfuzz.git "$tmp_dir"
cd "$tmp_dir"
git checkout $version --force
rm -rf "$honggfuzz_dir"
mv "$tmp_dir/android/" "$honggfuzz_dir"
mv "$tmp_dir/includes/" "$honggfuzz_dir"
mv "$tmp_dir/libhfcommon/" "$honggfuzz_dir"
mv "$tmp_dir/libhfuzz/" "$honggfuzz_dir"
mv "$tmp_dir/libhfnetdriver/" "$honggfuzz_dir"
mv "$tmp_dir/linux/" "$honggfuzz_dir"
mv "$tmp_dir/mac/" "$honggfuzz_dir"
mv "$tmp_dir/netbsd/" "$honggfuzz_dir"
mv "$tmp_dir/posix/" "$honggfuzz_dir"
mv "$tmp_dir/third_party/" "$honggfuzz_dir"
mv "$tmp_dir/COPYING" "$honggfuzz_dir"
mv "$tmp_dir/Makefile" "$honggfuzz_dir"
mv "$tmp_dir"/*.c "$honggfuzz_dir"
mv "$tmp_dir"/*.h "$honggfuzz_dir"

function replace() {
    sed -i.bak -e "$1" "$2"
    rm "$2.bak"
}

SRC=$project_dir/honggfuzz/*.c
for f in $SRC
do
    name=$(basename "$f" .c | sed 's/-/_/g')
    replace "s/int main/int ${name}_main/" $f
done

echo -e "libhonggfuzz.a: \$(OBJS) \$(LCOMMON_ARCH) \$(CRASH_REPORT)\n\t\$(AR) rcs libhonggfuzz.a \$(OBJS) \$(CRASH_REPORT)" >> "$project_dir/honggfuzz/Makefile"
