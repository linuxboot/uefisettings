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


# Builds the firmware of the Secure Boot scenarios on i686 and aarch64 from the
# edk2-stable202508 tag, checked against its commit:
# - IA32: OvmfPkg/OvmfPkgIa32.dsc with SECURE_BOOT_ENABLE and SMM_REQUIRE, as the pinned
#   ovmf-ia32 deb's OVMF32_CODE_4M.secboot.fd page-faults before its first console line under
#   QEMU 10.1. The tag is the last release with OvmfPkgIa32.dsc, which edk2 commit 1fb88ffe2847
#   ("OvmfPkg: Remove OVMF IA32") removed; the later tag edk2-stable202508.01 only adds a
#   TerminalDxe fix.
# - AARCH64: ArmVirtPkg/ArmVirtQemu.dsc with the flags of Ubuntu's AAVMF_CODE.secboot.fd
#   (AAVMF_SECBOOT_FLAGS of edk2 2024.02-2ubuntu0.10's debian/rules) but CC_MEASUREMENT_ENABLE,
#   which only OvmfPkg reads, the two that build in measured boot, and the PCDs that name the
#   Ubuntu package. That image refuses every authenticated write: without SMM, AuthVariableLib
#   verifies with RuntimeCryptLib, whose 600 KiB heap OpenSSL 3's PKCS7_verify() exhausts; edk2
#   commit ccbe6f5030bb raised it to 1100 KiB, which the tag has.
# Neither image holds the UEFI Shell (BUILD_SHELL=FALSE), as Debian's secboot images do not, so
# the scenarios put the Shell on the ESP.
# WORK keeps the clone, which both architectures share, its build tools and its builds, so a
# later run resumes there. OUTPUT, which a successful build replaces, gets OVMF_CODE.fd and
# OVMF_VARS.fd, or AAVMF_CODE.fd and AAVMF_VARS.fd padded to the 64 MiB of a flash device of
# QEMU's virt machine, as Ubuntu pads them, and edk2's License.txt.
# Needs what build-driver-sample.sh needs, and the iasl of the acpica-tools deb that
# host-packages pins, which fetch-packages.sh downloads and unpacks, with curl and zstd.
# JOBS sets the make and build job count (default: nproc).
#
# Usage: [JOBS=<n>] tests/qemu/build-secboot-firmware.sh <IA32|AARCH64> <work directory> \
#            <output directory>

set -euo pipefail

arch=${1-}
case $arch in
IA32 | AARCH64) ;;
*) arch= ;;
esac
if (($# != 3)) || [[ -z $arch ]]; then
    echo "usage: $0 <IA32|AARCH64> <work directory> <output directory>" >&2
    exit 2
fi
here=$(realpath "$(dirname "$0")")
work=$(realpath -m -- "$2")
out=$(realpath -m -- "$3")
# EDK2's tools_def.txt reads the prefix of the AARCH64 gcc from it.
export GCC_AARCH64_PREFIX=${GCC_AARCH64_PREFIX-aarch64-linux-gnu-}
tag=edk2-stable202508
commit=d46aa46c8361194521391aa581593e556c707c6e
jobs=${JOBS:-$(nproc)}
# MdePkg.dec and MdeModulePkg.dec name include directories in mipisyst and the second brotli,
# CryptoPkg.dec and SecurityPkg.dec in the next three; BaseTools builds BrotliCompress from the
# first brotli.
submodules=(
    BaseTools/Source/C/BrotliCompress/brotli
    MdePkg/Library/MipiSysTLib/mipisyst
    MdeModulePkg/Library/BrotliCustomDecompressLib/brotli
    CryptoPkg/Library/OpensslLib/openssl
    CryptoPkg/Library/MbedTlsLib/mbedtls
    SecurityPkg/DeviceSecurity/SpdmLib/libspdm
)
case $arch in
IA32)
    platform=OvmfPkg/OvmfPkgIa32.dsc
    fv=Build/OvmfIa32/RELEASE_GCC/FV
    flags=(-D SECURE_BOOT_ENABLE=TRUE -D SMM_REQUIRE=TRUE -D BUILD_SHELL=FALSE)
    # the images of the build and their names in OUTPUT
    images=(OVMF_CODE.fd OVMF_CODE.fd OVMF_VARS.fd OVMF_VARS.fd)
    pad=
    ;;
AARCH64)
    platform=ArmVirtPkg/ArmVirtQemu.dsc
    fv=Build/ArmVirtQemu-AARCH64/RELEASE_GCC/FV
    flags=(-D NETWORK_HTTP_BOOT_ENABLE=TRUE -D NETWORK_IP6_ENABLE=TRUE -D NETWORK_TLS_ENABLE
        -D CAVIUM_ERRATUM_27456=TRUE -D BUILD_SHELL=FALSE -D SECURE_BOOT_ENABLE=TRUE)
    images=(QEMU_EFI.fd AAVMF_CODE.fd QEMU_VARS.fd AAVMF_VARS.fd)
    pad=64M
    # ArmVirtQemu's FdtLib builds from it.
    submodules+=(MdePkg/Library/BaseFdtLib/libfdt)
    ;;
esac

mkdir -p -- "$work"
# One build at a time in WORK, such as those of make -j's i686 and aarch64 runs.
exec {lock}>"$work/lock"
flock "$lock"
src=$work/$commit
staging=
trap 'rm -rf "$staging"' EXIT
# Cloned next to its place and renamed to it at the end, so that a failure leaves no clone.
if [[ ! -e $src ]]; then
    staging=$(mktemp -d "$src.XXXXXX")
    git clone --quiet --depth 1 --branch "$tag" https://github.com/tianocore/edk2.git "$staging"
    mv -T "$staging" "$src"
fi
head=$(git -C "$src" rev-parse HEAD)
if [[ $head != "$commit" ]]; then
    echo "$src is at $head, expected $tag's $commit: delete it" >&2
    exit 1
fi
git -C "$src" submodule update --quiet --init --depth 1 "${submodules[@]}"
make -C "$src/BaseTools/Source/C" -j "$jobs"
rm -rf -- "$work/host"
"$here/fetch-packages.sh" "$here/host-packages" "$work/packages" "$work/host"
# EDK2's tools_def.txt runs the iasl of this prefix.
export IASL_PREFIX=$work/host/usr/bin/
(
    cd "$src"
    # edksetup.sh reads the script's arguments and tests unset variables.
    set -- && set +u
    # shellcheck source=/dev/null
    . ./edksetup.sh
    set -u
    build -a "$arch" -t GCC -b RELEASE -n "$jobs" -p "$platform" "${flags[@]}"
)

# Staged next to OUTPUT and renamed to it at the end, so that a failure leaves no partial
# OUTPUT, which run.sh would take for a build.
staging=$(mktemp -d "$out.XXXXXX")
# mkdir's mode, not mktemp's 0700.
chmod "$(umask -S)" "$staging"
for ((i = 0; i < ${#images[@]}; i += 2)); do
    cp "$src/$fv/${images[i]}" "$staging/${images[i + 1]}"
    [[ -z $pad ]] || truncate --size="$pad" "$staging/${images[i + 1]}"
done
cp "$src/License.txt" "$staging/"
rm -rf -- "$out"
mv -T "$staging" "$out"
