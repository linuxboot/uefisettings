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

# Checks that the Rust toolchain of the checks is there, and installs nothing. With a
# toolchain name, the cargo on PATH must be the one of rustup, and rustup must have that
# toolchain, a release toolchain for its default host, with clippy, rustfmt and every target
# of the list; with an empty name, PATH must have a cargo. Each missing piece has its own
# message.
#
# Usage: scripts/check-toolchain.sh <toolchain name, or empty> <target>[,<target>...]

set -euo pipefail

# Otherwise a rustup command that names a missing toolchain installs it.
export RUSTUP_AUTO_INSTALL=0
# Otherwise RUSTUP_TERM_COLOR=always colours what rustup show prints.
export RUSTUP_TERM_COLOR=never

toolchain=$1
targets=$2

if [[ -z $toolchain ]]; then
    if ! command -v cargo >/dev/null; then
        echo "make RUST_TOOLCHAIN= runs the checks on the cargo on PATH," \
            "and PATH has no cargo" >&2
        exit 1
    fi
    exit 0
fi

# rustup also takes the path of a toolchain, but make setup cannot install one, and the
# rustup commands below take only names.
if [[ $toolchain == */* ]]; then
    echo "the checks take the name of a rustup toolchain, and paths such as $toolchain" \
        "are not supported; make RUST_TOOLCHAIN= runs them on the cargo on PATH" >&2
    exit 1
fi

if ! command -v rustup >/dev/null; then
    echo "the checks run Rust $toolchain through rustup, and PATH has no rustup;" \
        "make RUST_TOOLCHAIN= runs them on the cargo on PATH" >&2
    exit 1
fi

# The cargo of rustup is a link to rustup itself, which runs the cargo of the toolchain;
# another cargo would ignore the toolchain.
cargo=$(command -v cargo || true)
if [[ -z $cargo ]]; then
    echo "the checks run Rust $toolchain through the cargo of rustup," \
        "and PATH has no cargo" >&2
    exit 1
fi
if [[ ! $cargo -ef $(command -v rustup) ]]; then
    echo "the checks run Rust $toolchain through the cargo of rustup, and the cargo on" \
        "PATH, $cargo, is another one; make RUST_TOOLCHAIN= runs them on that cargo" >&2
    exit 1
fi

# rustup show prints the default host first, and then fails when RUSTUP_TOOLCHAIN names a
# missing toolchain.
show=$(rustup show 2>&1 || true)
host=$(sed -n 's/^Default host: //p' <<<"$show")
if [[ -z $host ]]; then
    echo "rustup show names no default host; it prints:" >&2
    printf '%s\n' "$show" >&2
    exit 1
fi

# rustup resolves the toolchain name itself, inferring what a partial host such as the gnu
# of stable-gnu leaves out, and lists the targets of an installed release toolchain only.
# A toolchain that rustup toolchain list names, maybe followed by a note such as
# (default), but whose targets rustup cannot list is a custom one. --toolchain= hands rustup
# a name that starts with - as the toolchain, not as an option.
if ! listed_targets=$(rustup target list --installed --toolchain="$toolchain" 2>&1); then
    toolchains=$(rustup toolchain list || true)
    if awk -v t="$toolchain" '
        $0 == "no installed toolchains" { next }
        $1 == t { found = 1 }
        END { exit !found }' <<<"$toolchains"; then
        echo "rustup cannot list the targets of Rust toolchain $toolchain, as for a" \
            "custom toolchain, so the checks do not support it; make RUST_TOOLCHAIN=" \
            "runs them on the cargo on PATH. rustup target list prints:" >&2
    else
        echo "rustup has no Rust toolchain $toolchain; for a release toolchain, make" \
            "RUST_TOOLCHAIN=$toolchain setup installs it. rustup target list prints:" >&2
    fi
    printf '%s\n' "$listed_targets" >&2
    exit 1
fi

# rustup lists the rustc, clippy and rustfmt of a toolchain as rustc-<host>, clippy-<host>
# and rustfmt-<host>, with the host that the toolchain runs on.
listed_components=$(rustup component list --installed --toolchain="$toolchain")
if ! grep --quiet --line-regexp --fixed-strings "rustc-$host" <<<"$listed_components"; then
    echo "Rust toolchain $toolchain has no rustc for $host, the default host of rustup," \
        "and the checks take a toolchain for that host; make RUST_TOOLCHAIN= runs them" \
        "on the cargo on PATH" >&2
    exit 1
fi

missing=()
IFS=, read -ra wanted <<<"$targets"
for target in "${wanted[@]}"; do
    if ! grep --quiet --line-regexp --fixed-strings "$target" <<<"$listed_targets"; then
        missing+=("$target")
    fi
done
if ((${#missing[@]} > 0)); then
    echo "Rust toolchain $toolchain lacks the targets ${missing[*]};" \
        "make RUST_TOOLCHAIN=$toolchain setup adds them" >&2
    exit 1
fi

missing=()
for component in clippy rustfmt; do
    if ! grep --quiet --line-regexp --fixed-strings "$component-$host" \
        <<<"$listed_components"; then
        missing+=("$component")
    fi
done
if ((${#missing[@]} > 0)); then
    echo "Rust toolchain $toolchain lacks the components ${missing[*]} for $host;" \
        "make RUST_TOOLCHAIN=$toolchain setup adds them" >&2
    exit 1
fi
