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

# Downloads the guest kernel's RPMs that tests/qemu/kernel.sha256 lists into CACHE, checks
# them against their sha256 and unpacks them into the new directory ROOT. RPMs already in
# CACHE with the right sha256 are not downloaded again. Each mirror gets at most 1220 s for
# an RPM, so the download of an RPM from both mirrors stops within about 41 minutes.
#
# Usage: tests/qemu/fetch-kernel.sh CACHE ROOT

set -euo pipefail

if (($# != 2)); then
    echo "usage: $0 CACHE ROOT" >&2
    exit 2
fi
cache=$1
root=$2
list=$(realpath "$(dirname "$0")/kernel.sha256")
# Fedora 43 packages; the archive keeps them once the release reaches its end of life.
mirrors=(
    https://dl.fedoraproject.org/pub/fedora/linux/releases/43/Everything/x86_64/os/Packages/k
    https://archives.fedoraproject.org/pub/archive/fedora/linux/releases/43/Everything/x86_64/os/Packages/k
)

mkdir -p "$cache"
cd "$cache"
while read -r sum rpm; do
    if ! sha256sum --check --status <<<"$sum  $rpm" 2>/dev/null; then
        # --max-time ends a try that stalls: kernel-core, about 21 MB, takes 300 s only
        # below 70 kB/s. curl makes up to 4 tries with waits of 1, 2 and 4 s between
        # them, 1207 s in all, but waits longer when the server sends a Retry-After
        # header, so timeout stops curl after 1210 s and kills it 10 s later. Without
        # --foreground, timeout would move curl into a process group of its own, which a
        # timeout around make does not reach.
        for mirror in "${mirrors[@]}"; do
            timeout --foreground -k 10 1210 curl --fail --silent --show-error --location \
                --retry 3 --max-time 300 --output "$rpm" "$mirror/$rpm" && break
        done
    fi
done <"$list"
sha256sum --check --strict "$list"

mkdir "$root"
while read -r _ rpm; do
    rpm2cpio "$rpm" | (cd "$root" && cpio --extract --make-directories --preserve-modification-time --quiet)
done <"$list"
