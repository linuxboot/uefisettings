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

# The test of how fetch-packages.sh unpacks, which run.sh runs before any boot: each case
# unpacks one package that the cache already holds, so nothing is downloaded, and checks
# either the file that ROOT then holds or the message that fetch-packages.sh fails with,
# leaving no ROOT. An .rpm is a cpio archive that the case's rpm2cpio prints. Prints each
# case that does not hold and fails if one does not.
#
# Usage: tests/qemu/fetch-packages-test.sh

set -euo pipefail
here=$(realpath "$(dirname "$0")")

dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
errors=$dir/errors
cases=0
failed=0

mkdir "$dir/files" "$dir/bin"
echo "unpacked by fetch-packages-test.sh" >"$dir/files/file"
(cd "$dir/files" && echo file | cpio --create --format=newc --quiet) >"$dir/archive.cpio"
tar --create --file "$dir/files/data.tar" --directory "$dir/files" file
echo "not a tar archive" >"$dir/files/garbage"

# Checks fetch-packages.sh on the package $1, which is the file $2, with an rpm2cpio that
# runs the commands $3 on it: $4 is "unpacked" when ROOT must hold the archive's file, or
# else the last line that fetch-packages.sh must print, failing, with no ROOT left behind.
check() {
    local name=$1 file=$2 rpm2cpio=$3 want=$4 status=0 root sum last
    cases=$((cases + 1))
    root=$dir/root-$cases
    mkdir "$dir/cache-$cases"
    cp "$file" "$dir/cache-$cases/$name"
    sum=$(sha256sum <"$file" | cut -d ' ' -f 1)
    echo "$sum https://example.invalid/$name" >"$dir/list-$cases"
    printf '#!/bin/bash\n%s\n' "$rpm2cpio" >"$dir/bin/rpm2cpio"
    chmod +x "$dir/bin/rpm2cpio"
    PATH=$dir/bin:$PATH "$here/fetch-packages.sh" "$dir/list-$cases" "$dir/cache-$cases" \
        "$root" >/dev/null 2>"$errors" || status=$?
    last=$(tail -n 1 "$errors")
    if [[ $want == unpacked ]]; then
        if ((status == 0)) && [[ ! -s $errors ]] &&
            cmp --quiet "$root/file" "$dir/files/file"; then
            return
        fi
    elif ((status == 1)) && [[ $last == "$want" ]] && ! compgen -G "$root*" >/dev/null; then
        return
    fi
    echo "fetch-packages-test: $name from ${file##*/}: expected [$want]," \
        "got status $status, [$last], ROOT and staging [$(compgen -G "$root*" || true)]"
    failed=$((failed + 1))
}

check fixture-1.0.noarch.rpm "$dir/archive.cpio" 'cat "$1"' unpacked
# cpio stops reading at the archive's trailer, while rpm2cpio may still be writing padding
# after it: 4 MiB of it, more than a pipe holds, outlasts cpio on every run.
check fixture-1.0.noarch.rpm "$dir/archive.cpio" 'cat "$1" && head -c 4194304 /dev/zero' unpacked
check fixture-1.0.noarch.rpm "$dir/archive.cpio" 'cat "$1"; exit 3' \
    'fetch-packages.sh: cannot unpack fixture-1.0.noarch.rpm (exit statuses: rpm2cpio 3, cpio 0)'

check fixture-1.0.noarch.rpm "$dir/files/garbage" 'cat "$1"' \
    'fetch-packages.sh: cannot unpack fixture-1.0.noarch.rpm (exit statuses: rpm2cpio 0, cpio 2)'

(cd "$dir/files" && ar rc "$dir/data.deb" data.tar)
check fixture_1.0_all.deb "$dir/data.deb" exit unpacked
head -c 1024 "$dir/data.deb" >"$dir/cut-data.deb"
check fixture_1.0_all.deb "$dir/cut-data.deb" exit \
    'fetch-packages.sh: cannot unpack fixture_1.0_all.deb (exit statuses: ar p 1)'
check fixture_1.0_all.deb "$dir/files/garbage" exit \
    'fetch-packages.sh: cannot unpack fixture_1.0_all.deb (exit statuses: ar t | grep 1)'
(cd "$dir/files" && ar rc "$dir/no-data.deb" garbage)
check fixture_1.0_all.deb "$dir/no-data.deb" exit \
    'fetch-packages.sh: cannot unpack fixture_1.0_all.deb (exit statuses: ar t | grep 1)'
cp "$dir/files/garbage" "$dir/files/data.tar"
(cd "$dir/files" && ar rc "$dir/garbage-data.deb" data.tar)
check fixture_1.0_all.deb "$dir/garbage-data.deb" exit \
    'fetch-packages.sh: cannot unpack fixture_1.0_all.deb (exit statuses: tar 2)'

if ((failed > 0)); then
    echo "fetch-packages-test: $failed of $cases cases failed"
    exit 1
fi
echo "fetch-packages-test: $cases cases passed"
