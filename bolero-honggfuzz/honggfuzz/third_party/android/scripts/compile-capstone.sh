#!/bin/bash
#
#   honggfuzz capstone build help script
#   -----------------------------------------
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

#set -x # debug

abort() {
  cd - &>/dev/null
  exit "$1"
}

trap "abort 1" SIGINT SIGTERM

if [ $# -ne 2 ]; then
  echo "[-] Invalid arguments"
  echo "[!] $0 <CAPSTONE_DIR> <ARCH>"
  echo "    ARCH: arm arm64 x86 x86_64"
  exit 1
fi

readonly CAPSTONE_DIR="$1"

if [ ! -d "$CAPSTONE_DIR/.git" ]; then
  git submodule update --init third_party/android/capstone || {
    echo "[-] git submodules init failed"
    exit 1
  }
fi

# register client hooks
hooksDir="$(git -C "$CAPSTONE_DIR" rev-parse --git-dir)/hooks"
mkdir -p "$hooksDir"

if [ ! -f "$hooksDir/post-checkout" ]; then
  cat > "$hooksDir/post-checkout" <<'endmsg'
#!/usr/bin/env bash

endmsg
  chmod +x "$hooksDir/post-checkout"
fi

# Change workspace
cd "$CAPSTONE_DIR" &>/dev/null

if [ -z "$NDK" ]; then
  # Search in $PATH
  if [[ $(which ndk-build) != "" ]]; then
    NDK=$(dirname $(which ndk-build))
  else
    echo "[-] Could not detect Android NDK dir"
    abort 1
  fi
fi

ARCH="$2"

case "$ARCH" in
  arm)
    CS_ARCH="arm"
    CS_BUILD_BIN="make"
    ;;
  arm64)
    CS_ARCH="arm aarch64"
    CS_BUILD_BIN="make"
    ;;
  x86)
    CS_ARCH="x86"
    CS_BUILD_BIN="make"
    ;;
  x86_64)
    CS_ARCH="x86"
    CS_BUILD_BIN="make"
    ;;
esac

# Capstone ARM/ARM64 cross-compile automation is broken,
# we need to prepare the Android NDK toolchains manually
if [ -z "$NDK" ]; then
  # Search in $PATH
  if [[ $(which ndk-build) != "" ]]; then
    $NDK=$(dirname $(which ndk-build))
  else
    echo "[-] Could not detect Android NDK dir"
    abort 1
  fi
fi

if [ -z "$ANDROID_API" ]; then
  ANDROID_API="android-26"
fi
if ! echo "$ANDROID_API" | grep -qoE 'android-[0-9]{1,2}'; then
  echo "[-] Invalid ANDROID_API '$ANDROID_API'"
  abort 1
fi
ANDROID_API_V=$(echo "$ANDROID_API" | grep -oE '[0-9]{1,2}$')

# Support both Linux & Darwin
HOST_OS=$(uname -s | tr '[:upper:]' '[:lower:]')
HOST_ARCH=$(uname -m)

export CC="$NDK"/toolchains/llvm/prebuilt/linux-x86_64/bin/"$ANDROID_NDK_COMPILER_PREFIX""$ANDROID_API_V"-clang
export CXX="$NDK"/toolchains/llvm/prebuilt/linux-x86_64/bin/"$ANDROID_NDK_COMPILER_PREFIX""$ANDROID_API_V"-clang++

# Build it
make clean

NDK=$NDK CAPSTONE_BUILD_CORE_ONLY=yes CAPSTONE_ARCHS=$CS_ARCH \
CAPSTONE_SHARED=no CAPSTONE_STATIC=yes \
eval $CS_BUILD_BIN
if [ $? -ne 0 ]; then
    echo "[-] Compilation failed"
    abort 1
else
    echo "[*] '$ARCH' libcapstone available at '$CAPSTONE_DIR/$ARCH'"
fi

abort 0
