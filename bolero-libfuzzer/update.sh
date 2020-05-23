#!/bin/bash -ex

version=${1:-master}
project_dir="$(pwd)"
tmp_dir="$(mktemp -d)"

git clone --depth 1 --single-branch --branch $version https://github.com/llvm/llvm-project.git "$tmp_dir"
rm -rf "$project_dir/libfuzzer/"
mv "$tmp_dir/compiler-rt/lib/fuzzer/" "$project_dir/libfuzzer/"
mv "$tmp_dir/compiler-rt/LICENSE.txt" "$project_dir/libfuzzer/"
