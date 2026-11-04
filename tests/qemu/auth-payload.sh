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


# Writes the data of authenticated variable writes, from keys that run.sh generates per run:
# - sign: an EFI_VARIABLE_AUTHENTICATION_2 descriptor followed by DATA, the new variable content
#   (UEFI 2.11 §8.2.6): EFI_TIME, then WIN_CERTIFICATE_UEFI_GUID holding a PKCS#7 SignedData of
#   CertType EFI_CERT_TYPE_PKCS7_GUID (§32.2.4). The signature covers §8.2.6's digest input,
#   VariableName (UCS-2, no terminator) || VendorGuid || Attributes || TimeStamp || DATA, with no
#   signed attributes and without the content, as edk2's AuthVariableLib verifies it. ATTRIBUTES
#   are those of the SetVariable() call, EFI_VARIABLE_APPEND_WRITE included. TimeStamp is the
#   current UTC second.
# - x509-esl: the EFI_SIGNATURE_LIST of one X.509 certificate (§32.4.1), the data of a db append.
#
# Usage: tests/qemu/auth-payload.sh sign NAME GUID ATTRIBUTES DATA SIGNER_CERT SIGNER_KEY OUT
#        tests/qemu/auth-payload.sh x509-esl OWNER CERT OUT
# NAME is printable ASCII; GUID and OWNER are in registry format; ATTRIBUTES is a hexadecimal
# number such as 0x67; SIGNER_CERT and SIGNER_KEY are PEM files; CERT is a PEM certificate.

set -euo pipefail
# The bracket ranges and printf's bytes below need the C locale.
export LC_ALL=C

usage() {
    echo "usage: $0 sign NAME GUID ATTRIBUTES DATA SIGNER_CERT SIGNER_KEY OUT" >&2
    echo "       $0 x509-esl OWNER CERT OUT" >&2
    exit 2
}

check_guid() {
    if [[ ! $1 =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
        echo "$0: not a GUID in registry format: $1" >&2
        exit 2
    fi
}

# Writes the bytes of the hexadecimal string $1.
hex() {
    local escaped
    escaped=$(sed 's/../\\x&/g' <<<"$1")
    printf '%b' "$escaped"
}

# Writes the number $1 as a little-endian integer of $2 bytes.
le() {
    local i digits=
    for ((i = 0; i < $2; i++)); do
        digits+=$(printf '%02x' $((($1 >> (8 * i)) & 0xff)))
    done
    hex "$digits"
}

# Writes the registry-format GUID $1 as an EFI_GUID: Data1, Data2 and Data3 little-endian, Data4
# as written.
efi_guid() {
    local digits=${1//-/}
    le $((16#${digits:0:8})) 4
    le $((16#${digits:8:4})) 2
    le $((16#${digits:12:4})) 2
    hex "${digits:16:16}"
}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

case ${1-} in
x509-esl)
    (($# == 4)) || usage
    check_guid "$2"
    openssl x509 -in "$3" -outform DER -out "$work/cert"
    size=$(stat --format=%s "$work/cert")
    {
        # SignatureType EFI_CERT_X509_GUID, then SignatureListSize, SignatureHeaderSize 0 and
        # SignatureSize; then the one EFI_SIGNATURE_DATA: SignatureOwner and the certificate
        efi_guid a5c059a1-94e4-4aa7-87b5-ab155c2bf072
        le $((28 + 16 + size)) 4
        le 0 4
        le $((16 + size)) 4
        efi_guid "$2"
        cat "$work/cert"
    } >"$4"
    exit 0
    ;;
sign) (($# == 8)) || usage ;;
*) usage ;;
esac

name=$2 guid=$3 attributes=$4 data=$5 cert=$6 key=$7 out=$8
if [[ ! $name =~ ^[\ -~]+$ ]]; then
    echo "$0: not printable ASCII: $name" >&2
    exit 2
fi
check_guid "$guid"
if [[ ! $attributes =~ ^0x[0-9a-fA-F]{1,8}$ ]]; then
    echo "$0: not a 32-bit hexadecimal number: $attributes" >&2
    exit 2
fi

read -r year month day hour minute second < <(date -u +'%Y %m %d %H %M %S')
# EFI_TIME, whose Pad1, Nanosecond, TimeZone, Daylight and Pad2 are 0 (§8.2.6)
{
    le "$year" 2
    le $((10#$month)) 1
    le $((10#$day)) 1
    le $((10#$hour)) 1
    le $((10#$minute)) 1
    le $((10#$second)) 1
    le 0 1
    le 0 4
    le 0 2
    le 0 1
    le 0 1
} >"$work/time"
{
    for ((i = 0; i < ${#name}; i++)); do
        printf '%s' "${name:i:1}"
        hex 00
    done
    efi_guid "$guid"
    le $((attributes)) 4
    cat "$work/time" "$data"
} >"$work/digest-input"
openssl cms -sign -binary -noattr -outform DER -md sha256 -signer "$cert" -inkey "$key" \
    -in "$work/digest-input" -out "$work/signature"
size=$(stat --format=%s "$work/signature")
{
    cat "$work/time"
    # WIN_CERTIFICATE: dwLength, of the header, CertType and CertData; wRevision 0x0200;
    # wCertificateType WIN_CERT_TYPE_EFI_GUID. Then CertType EFI_CERT_TYPE_PKCS7_GUID.
    le $((8 + 16 + size)) 4
    le 0x0200 2
    le 0x0EF1 2
    efi_guid 4aafd29d-68df-49ee-8aa9-347d375665a7
    cat "$work/signature" "$data"
} >"$out"
