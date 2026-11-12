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

# Fails unless a GitHub Actions workflow runs each named check of the Makefile and no other:
# the workflow runs a check where one of its lines is "run: make -k <check>", or
# "check: <check>", a matrix entry's check, which its job runs as make -k "$CHECK". Each
# missing or unknown check has its own message.
# It does not check which systems run a check, nor that a job runs its entries' checks.
#
# Usage: scripts/check-ci-jobs.sh <workflow> <check>...

set -euo pipefail

workflow=$1
shift
# Words, not an array: macOS's bash 3.2 has no mapfile.
workflow_checks=$(sed -nE 's/^ *(- )?(run: make -k|check:) ([a-z0-9_-]+)$/\3/p' "$workflow" | sort -u | tr '\n' ' ')
failed=0
for check in "$@"; do
    if [[ " $workflow_checks " != *" $check "* ]]; then
        echo "$workflow has no line \"run: make -k $check\" or \"check: $check\"" >&2
        failed=1
    fi
done
for check in $workflow_checks; do
    if [[ " $* " != *" $check "* ]]; then
        echo "$workflow names $check, which is not one of the checks: $*" >&2
        failed=1
    fi
done
exit "$failed"
