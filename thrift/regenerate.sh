#!/usr/bin/env bash
# Copyright 2023 Meta Platforms, Inc. and affiliates.
#
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


# Regenerates the Rust crates in thrift/rust/ from thrift/*.thrift. Each crate
# directory holds only its hand-written Cargo.toml and the generated src/.
#
# The generated code targets the fbthrift runtime at commit FBTHRIFT_COMMIT,
# which crates.io carries as `fbthrift-git` (its version has the commit as
# build metadata). The code generator, thrift1, is built from the same commit,
# so the generated code always matches its runtime. To move to another fbthrift
# snapshot, change FBTHRIFT_COMMIT and the `fbthrift-git` requirement in the
# Cargo.toml files together, set the BOOST_* and FMT_* pins to the versions
# and checksums that build/fbcode_builder/manifests pins at the new commit,
# run `cargo update -p fbthrift-git`, check that the files of the new
# fbthrift-git crate equal thrift/lib/rust at the new commit, apart from the
# package metadata, then rerun this script.
#
# Usage:
#   thrift/regenerate.sh          rewrite thrift/rust/*/src
#   thrift/regenerate.sh --check  fail if thrift/rust/*/src is out of date
#
# Requirements: bash 4.4+, GNU coreutils, git, curl, tar, diff, find, cmake,
# make, a C++17 compiler and the OpenSSL headers. The first run builds thrift1
# from source, which needs 1.5 GB of scratch space, and caches it in
# $UEFISETTINGS_THRIFT_CACHE (default:
# ${XDG_CACHE_HOME:-$HOME/.cache}/uefisettings/thrift; a relative path is
# taken from the repository root). The build runs up to
# $UEFISETTINGS_THRIFT_JOBS compiler processes at a time (default: 1). A build
# killed by SIGKILL leaves its scratch directory, <key>.XXXXXX, in the cache;
# delete it.

set -euo pipefail
shopt -s inherit_errexit

readonly FBTHRIFT_REPO=https://github.com/facebook/fbthrift.git
readonly FBTHRIFT_COMMIT=c383b5e113b0b74cb768d21bd54d51d8e1a5e964

# The versions build/fbcode_builder/manifests pins at FBTHRIFT_COMMIT.
readonly BOOST_VERSION=1.83.0
readonly BOOST_SHA256=c0685b68dd44cc46574cce86c4e17c0f611b15e195be9848dfd0769a0a207628
# GitHub generates the fmt tarball on request and may change its compressed
# bytes, though not the files in it; FMT_SHA256 would then fail. Should that
# happen, fetch fmt with git at commit a33701196adfad74917046096bf5a2aa0ab0bb50
# (tag 9.1.0), as fbthrift is fetched. Make that switch at the latest with the
# next change of these pins, which needs a fresh build anyway.
readonly FMT_VERSION=9.1.0
readonly FMT_SHA256=5dea48d1fcddc3ec571ce2058e13910a0d4a6bab4cc09a809d8b1dd1c88ae6f2

readonly USAGE="usage: $0 [--check]"

die() {
    echo "regenerate.sh: $*" >&2
    exit 1
}

# fetch URL SHA256 DEST downloads URL to DEST and verifies its checksum.
fetch() {
    local url=$1 sha256=$2 dest=$3
    curl --fail --silent --show-error --location --output "$dest" "$url"
    echo "$sha256  $dest" | sha256sum --check --quiet --strict -
}

# build_toolchain DIR JOBS builds thrift1 and its static dependencies in
# DIR/build, running up to JOBS compiler processes at a time, then installs
# thrift1 to DIR/bin and the Thrift standard library to DIR/include.
build_toolchain() {
    local dir=$1 jobs=$2
    local build=$dir/build
    local prefix=$build/deps
    local boost=boost_${BOOST_VERSION//./_}
    mkdir "$build"

    fetch "https://archives.boost.io/release/$BOOST_VERSION/source/$boost.tar.gz" \
        "$BOOST_SHA256" "$build/boost.tar.gz"
    tar --extract --gzip --file "$build/boost.tar.gz" --directory "$build"
    (
        cd "$build/$boost"
        # bootstrap.sh compiles b2 with a single compiler command.
        ./bootstrap.sh --prefix="$prefix" --with-libraries=filesystem
        ./b2 -j"$jobs" link=static variant=release threading=multi install
    )

    fetch "https://github.com/fmtlib/fmt/archive/refs/tags/$FMT_VERSION.tar.gz" \
        "$FMT_SHA256" "$build/fmt.tar.gz"
    tar --extract --gzip --file "$build/fmt.tar.gz" --directory "$build"
    cmake -S "$build/fmt-$FMT_VERSION" -B "$build/fmt-build" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX="$prefix" \
        -DFMT_DOC=OFF \
        -DFMT_TEST=OFF
    cmake --build "$build/fmt-build" --parallel "$jobs" --target install

    git init --quiet "$build/fbthrift"
    git -C "$build/fbthrift" fetch --quiet --depth 1 "$FBTHRIFT_REPO" "$FBTHRIFT_COMMIT"
    git -C "$build/fbthrift" checkout --quiet "$FBTHRIFT_COMMIT"
    # fbthrift asks for CMake 3.1.3, which CMake 4 rejects without
    # CMAKE_POLICY_VERSION_MINIMUM. Older CMake ignores the variable.
    cmake -S "$build/fbthrift" -B "$build/fbthrift-build" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_PREFIX_PATH="$prefix" \
        -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
        -DBoost_USE_STATIC_LIBS=ON \
        -DTHRIFT_COMPILER_ONLY=ON
    cmake --build "$build/fbthrift-build" --parallel "$jobs" --target thrift1

    install -D "$build/fbthrift-build/bin/thrift1" "$dir/bin/thrift1"
    # thrift1 looks up its standard library in the include path, and IDL
    # files may include the annotations.
    local lib
    for lib in thrift/annotation thrift/lib/thrift; do
        mkdir -p "$dir/include/$lib"
        cp "$build/fbthrift/$lib"/*.thrift "$dir/include/$lib/"
    done
    rm -rf "$build"
}

# toolchain prints the directory that has bin/thrift1 and the Thrift standard
# library in include/, building them on the first use.
toolchain() (
    local cache=${UEFISETTINGS_THRIFT_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/uefisettings/thrift}
    # The key covers the pinned sources and the recipe that builds them, not
    # the host's compiler, CMake or libraries.
    local key
    key=$({
        printf '%s\n' "$FBTHRIFT_COMMIT" "$BOOST_VERSION" "$BOOST_SHA256" "$FMT_VERSION" "$FMT_SHA256"
        declare -f fetch build_toolchain
    } | sha256sum | cut -c1-16)
    local dir=$cache/$key
    local jobs=${UEFISETTINGS_THRIFT_JOBS:-1}
    [[ $jobs =~ ^[1-9][0-9]*$ ]] ||
        die "UEFISETTINGS_THRIFT_JOBS must be a positive integer, not '$jobs'"
    if [[ ! -e $dir ]]; then
        mkdir -p "$cache"
        local tmp
        tmp=$(mktemp -d "$dir.XXXXXX")
        trap 'rm -rf "$tmp"' EXIT
        build_toolchain "$tmp" "$jobs" >&2
        # A concurrent run may have installed the toolchain first.
        mv --no-target-directory "$tmp" "$dir" 2>/dev/null || [[ -d $dir ]] ||
            die "cannot move $tmp to $dir"
    fi
    # thrift1 links OpenSSL and libstdc++ dynamically, so a system upgrade can
    # break a cached build.
    "$dir/bin/thrift1" -I "$dir/include" --skip-gen "$dir/include/thrift/annotation/thrift.thrift" >&2 ||
        die "$dir/bin/thrift1 does not work; remove $dir and rerun"
    echo "$dir"
)

# check_runtime fails unless Cargo.lock resolves fbthrift-git to the snapshot
# of FBTHRIFT_COMMIT.
check_runtime() {
    local version
    version=$(sed -n '/^name = "fbthrift-git"$/{n;s/^version = "\(.*\)"$/\1/p}' Cargo.lock)
    [[ $version == *"+${FBTHRIFT_COMMIT:0:7}" ]] ||
        die "Cargo.lock has fbthrift-git '$version', expected the snapshot of fbthrift ${FBTHRIFT_COMMIT:0:7}"
}

# check_crates fails unless every IDL file has a crate in thrift/rust/ and
# thrift/rust/ holds nothing but those crate directories and rustfmt.toml. A
# crate directory may hold only its Cargo.toml file and src/ directory, besides
# the Cargo.lock file and target/ directory that Cargo creates when it runs
# there. Hidden entries and symbolic links in these directories count as
# unmanaged. The check does not look inside Cargo.lock or target/.
check_crates() {
    local idl name dir stray
    for idl in thrift/*.thrift; do
        name=$(basename "$idl" .thrift)
        [[ -f thrift/rust/${name}_thrift/Cargo.toml ]] ||
            die "thrift/rust/${name}_thrift/Cargo.toml is missing"
    done
    # Unlike a glob, find lists hidden entries, and its * matches a leading
    # dot, hence the [!.]. With -H, find follows thrift/rust itself when it
    # is a symbolic link.
    stray=$(find -H thrift/rust -mindepth 1 -maxdepth 1 ! \( -name rustfmt.toml -type f \) \
        ! \( -name '[!.]*_thrift' -type d \))
    [[ -z $stray ]] || die "thrift/rust has files that regenerate.sh does not manage: ${stray//$'\n'/, }"
    for dir in thrift/rust/*/; do
        dir=${dir%/}
        name=$(basename "$dir" _thrift)
        [[ -f thrift/$name.thrift ]] || die "$dir has no IDL file thrift/$name.thrift"
        stray=$(find "$dir" -mindepth 1 -maxdepth 1 ! \( -name Cargo.toml -type f \) \
            ! \( -name src -type d \) ! \( -name Cargo.lock -type f \) ! \( -name target -type d \))
        [[ -z $stray ]] || die "$dir has files that regenerate.sh does not manage: ${stray//$'\n'/, }"
    done
}

# generate TOOLCHAIN OUT writes the src/ directory of every thrift crate to
# OUT/<crate>/src.
generate() {
    local toolchain=$1 out=$2
    local idl name crate gen mods mod
    for idl in thrift/*.thrift; do
        name=$(basename "$idl" .thrift)
        crate=${name}_thrift
        gen=$out/$crate/gen
        mkdir -p "$gen" "$out/$crate/src"
        # The input path goes into the @generated header, so it must be
        # relative to the repository root.
        "$toolchain/bin/thrift1" -I "$toolchain/include" --gen mstch_rust --out "$gen" "$idl"
        # Only the types part is needed: types.rs becomes the crate root and
        # brings the modules it declares.
        cp "$gen/types.rs" "$out/$crate/src/lib.rs"
        mods=$(sed -n 's/^pub mod \([a-z_]*\);$/\1/p' "$gen/types.rs")
        for mod in $mods; do
            cp "$gen/$mod.rs" "$out/$crate/src/"
        done
        rm -r "$gen"
    done
}

# main runs in a subshell, as toolchain does, so that its EXIT trap runs while
# the locals the trap uses are still in scope.
main() (
    local check=false
    case $# in
    0) ;;
    1) [[ $1 == --check ]] || die "$USAGE"; check=true ;;
    *) die "$USAGE" ;;
    esac

    cd "$(dirname "${BASH_SOURCE[0]}")/.."
    check_runtime
    check_crates
    local toolchain
    toolchain=$(toolchain)

    local out
    out=$(mktemp -d)
    trap 'rm -rf "$out"' EXIT
    generate "$toolchain" "$out"

    local crate
    for crate in "$out"/*; do
        crate=$(basename "$crate")
        if $check; then
            diff -r "thrift/rust/$crate/src" "$out/$crate/src" >&2 ||
                die "thrift/rust/$crate/src is out of date; run $0"
        else
            rm -rf "thrift/rust/$crate/src"
            mv "$out/$crate/src" "thrift/rust/$crate/src"
        fi
    done
)

main "$@"
