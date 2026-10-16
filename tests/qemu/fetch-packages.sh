#!/bin/bash
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

# Downloads the packages that LIST names into CACHE, checks them against their sha256 and
# unpacks them, .rpm and .deb alike, into the new directory ROOT. Each line of LIST that is
# neither empty nor a # comment holds the sha256 of a package and then its HTTPS URLs,
# mirrors of one another that end in the same file name, with a permanent archive last, as
# distributions drop superseded packages from their pools. The whole list is checked before
# any download. A package already in CACHE with the right sha256 is not downloaded again;
# otherwise its URLs are tried in order, the next one after a failed download or a sha256
# mismatch, each for at most 1220 s. ROOT appears only once every package is right and
# unpacked.
#
# Usage: tests/qemu/fetch-packages.sh LIST CACHE ROOT

set -euo pipefail

if (($# != 3)); then
    echo "usage: $0 LIST CACHE ROOT" >&2
    exit 2
fi
list=$(realpath "$1")
cache=$2
root=$(realpath -m "$3")
if [[ -e $root ]]; then
    echo "$root exists" >&2
    exit 1
fi

sums=()
files=()
mirrors=()
# read fails on a last line without a newline, which still counts.
while read -r sum urls || [[ -n $sum ]]; do
    [[ -z $sum || $sum == \#* ]] && continue
    if [[ ! $sum =~ ^[0-9a-f]{64}$ ]]; then
        echo "$list: $sum is not a sha256" >&2
        exit 1
    fi
    read -r -a urls <<<"$urls"
    if ((${#urls[@]} == 0)); then
        echo "$list: no URL for $sum" >&2
        exit 1
    fi
    file=${urls[0]##*/}
    case $file in
    *.rpm | *.deb) ;;
    *)
        echo "$list: $file is neither an .rpm nor a .deb" >&2
        exit 1
        ;;
    esac
    for url in "${urls[@]}"; do
        if [[ $url != https://* ]]; then
            echo "$list: $url is not an HTTPS URL" >&2
            exit 1
        fi
        if [[ ${url##*/} != "$file" ]]; then
            echo "$list: the URLs of $file name other files: ${urls[*]}" >&2
            exit 1
        fi
    done
    sums+=("$sum")
    files+=("$file")
    mirrors+=("${urls[*]}")
done <"$list"
if ((${#files[@]} == 0)); then
    echo "$list: no package" >&2
    exit 1
fi

mkdir -p "$cache"
cd "$cache"
for i in "${!files[@]}"; do
    sum=${sums[i]}
    file=${files[i]}
    read -r -a urls <<<"${mirrors[i]}"
    # The -f test keeps the sha256sum of uutils (Ubuntu 26.04) from printing "FAILED open
    # or read" for a missing file, which it does even with --status.
    if ! { [[ -f $file ]] && sha256sum --check --status <<<"$sum  $file"; } 2>/dev/null; then
        # --max-time ends a try that stalls: kernel-core, the biggest package at about
        # 21 MB, takes 300 s only below 70 kB/s. curl makes up to 4 tries with waits of 1,
        # 2 and 4 s between them, 1207 s in all, but waits longer when the server sends a
        # Retry-After header, so timeout stops curl after 1210 s and kills it 10 s later.
        # Without --foreground, timeout would move curl into a process group of its own,
        # which a timeout around make does not reach.
        for url in "${urls[@]}"; do
            timeout --foreground -k 10 1210 curl --fail --silent --show-error --location \
                --proto =https --proto-redir =https --retry 3 --max-time 300 \
                --output "$file" "$url" &&
                sha256sum --check --status <<<"$sum  $file" && break
        done
    fi
    sha256sum --check --strict <<<"$sum  $file"
done

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
# Unpacked next to ROOT and renamed to it at the end, so that a failure leaves no ROOT.
staging=$(mktemp -d "$root.XXXXXX")
trap 'rm -rf "$work" "$staging"' EXIT
# mkdir's mode, not mktemp's 0700.
chmod "$(umask -S)" "$staging"
unpack_failed() {
    echo "fetch-packages.sh: cannot unpack $1" >&2
    exit 1
}
for file in "${files[@]}"; do
    echo "fetch-packages.sh: unpacking $file"
    case $file in
    *.rpm)
        rpm2cpio "$file" |
            (cd "$staging" && cpio --extract --make-directories --preserve-modification-time \
                --no-absolute-filenames --quiet) ||
            unpack_failed "$file"
        ;;
    *.deb)
        # An ar archive whose member data.tar, compressed or not, holds the files.
        data=$(ar t "$file" | grep -E --line-regexp 'data\.tar(\.[a-z0-9]+)?') ||
            unpack_failed "$file"
        ar p "$file" "$data" >"$work/$data" || unpack_failed "$file"
        tar --extract --file "$work/$data" --directory "$staging" || unpack_failed "$file"
        ;;
    esac
done
mv -T "$staging" "$root"
