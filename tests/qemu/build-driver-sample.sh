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

# Builds DriverSample.efi, EDK2's sample HII driver
# (MdeModulePkg/Universal/DriverSampleDxe), which the QEMU tests load into OVMF
# for its HII forms. The source is the edk2-stable202508 tag, checked against
# its commit. DriverSample is BSD-2-Clause-Patent, so EDK2's License.txt is
# copied next to it as DriverSample-License.txt.
# Needs gcc, g++, make, nasm, python3, git and the libuuid headers; on Ubuntu
# 24.04: apt-get install build-essential git nasm python3 uuid-dev.
# JOBS sets the make and build job count (default: nproc).
#
# Usage: [JOBS=<n>] tests/qemu/build-driver-sample.sh <output directory>

set -euo pipefail

if (($# != 1)); then
    echo "usage: $0 <output directory>" >&2
    exit 2
fi
out=$(realpath -m -- "$1")
tag=edk2-stable202508
commit=d46aa46c8361194521391aa581593e556c707c6e
jobs=${JOBS:-$(nproc)}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
git clone --quiet --depth 1 --branch "$tag" https://github.com/tianocore/edk2.git "$work/edk2"
cd "$work/edk2"
head=$(git rev-parse HEAD)
if [[ $head != "$commit" ]]; then
    echo "$tag is at $head, expected $commit" >&2
    exit 1
fi
# MdePkg.dec and MdeModulePkg.dec name include directories inside the last two;
# BaseTools builds BrotliCompress from the first.
git submodule update --quiet --init --depth 1 \
    BaseTools/Source/C/BrotliCompress/brotli \
    MdePkg/Library/MipiSysTLib/mipisyst \
    MdeModulePkg/Library/BrotliCustomDecompressLib/brotli
make -C BaseTools/Source/C -j "$jobs"
# edksetup.sh reads the script's arguments and tests unset variables.
set -- && set +u
# shellcheck source=/dev/null
. ./edksetup.sh
set -u
build -a X64 -t GCC -b RELEASE -n "$jobs" -p MdeModulePkg/MdeModulePkg.dsc \
    -m MdeModulePkg/Universal/DriverSampleDxe/DriverSampleDxe.inf
mkdir -p -- "$out"
cp Build/MdeModule/RELEASE_GCC/X64/DriverSample.efi "$out/"
cp License.txt "$out/DriverSample-License.txt"
