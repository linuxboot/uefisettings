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


# The table test of scenario-options.sh, which run.sh runs before any boot: each case below is
# an options column and what scenario_options makes of it, either the variables that it sets or
# the message that it fails with, or an architecture and whether scenario_runs_on boots the
# scenario there. Prints each case that does not hold and fails if one does not.
#
# Usage: tests/qemu/scenario-options-test.sh

set -euo pipefail
source "$(dirname "$0")/scenario-options.sh"

errors=$(mktemp)
trap 'rm -f "$errors"' EXIT
cases=0
failed=0

# Prints the variables that scenario_options set, in the form of the accepts cases.
parsed() {
    local IFS=,
    echo "kernel=$option_kernel firmware=$option_firmware arch=${option_arches[*]}" \
        "devices=${option_devices[*]}"
}

# Checks that scenario_options parses the column $1 into $2, quietly.
accepts() {
    local status=0 got
    cases=$((cases + 1))
    scenario_options test "$1" 2>"$errors" || status=$?
    got=$(parsed)
    if ((status != 0)) || [[ -s $errors || $got != "$2" ]]; then
        echo "scenario-options-test: [$1]: expected [$2], got status $status, [$got], [$(<"$errors")]"
        failed=$((failed + 1))
    fi
}

# Checks that scenario_options refuses the column $1 with the message $2 alone.
refuses() {
    local status=0
    cases=$((cases + 1))
    scenario_options test "$1" 2>"$errors" || status=$?
    if ((status == 0)) || [[ $(<"$errors") != "$2" ]]; then
        echo "scenario-options-test: [$1]: expected the refusal [$2], got status $status, [$(<"$errors")]"
        failed=$((failed + 1))
    fi
}

# Checks that scenario_runs_on tells, after the column $1, that architecture $2 boots the
# scenario ($3 yes) or skips it ($3 no).
runs_on() {
    local got=no
    cases=$((cases + 1))
    scenario_options test "$1"
    if scenario_runs_on "$2"; then
        got=yes
    fi
    if [[ $got != "$3" ]]; then
        echo "scenario-options-test: [$1] on $2: expected $3, got $got"
        failed=$((failed + 1))
    fi
}

all='firmware=default arch=x86_64,i686,aarch64'
accepts - "kernel= $all devices="
accepts kernel=vamap "kernel=vamap $all devices="
accepts kernel=lockdown "kernel=lockdown $all devices="
accepts kernel=lockdown-conf "kernel=lockdown-conf $all devices="
accepts firmware=default "kernel= $all devices="
accepts firmware=secboot-setup \
    'kernel= firmware=secboot-setup arch=x86_64,i686,aarch64 devices='
accepts firmware=secboot-user 'kernel= firmware=secboot-user arch=x86_64,i686,aarch64 devices='
accepts arch=i686 'kernel= firmware=default arch=i686 devices='
accepts arch=aarch64,x86_64 'kernel= firmware=default arch=aarch64,x86_64 devices='
accepts devices=virtio-rng "kernel= $all devices=virtio-rng"
accepts 'devices=virtio-rng firmware=secboot-user kernel=lockdown arch=x86_64,i686' \
    'kernel=lockdown firmware=secboot-user arch=x86_64,i686 devices=virtio-rng'
# Each case starts from the defaults, not from the case before.
accepts - "kernel= $all devices="

refuses '' 'scenarios.tsv: test: the options column is empty'
refuses ' kernel=vamap' 'scenarios.tsv: test: an empty option: a space at the start or end, or two in a row'
refuses 'kernel=vamap ' 'scenarios.tsv: test: an empty option: a space at the start or end, or two in a row'
refuses 'kernel=vamap  arch=i686' \
    'scenarios.tsv: test: an empty option: a space at the start or end, or two in a row'
refuses vamap "scenarios.tsv: test: option vamap has no '='"
# A value with a space is two tokens, the second without "=".
refuses 'kernel=lockdown conf' "scenarios.tsv: test: option conf has no '='"
refuses 'kernel=vamap kernel=lockdown' 'scenarios.tsv: test: repeated key kernel'
refuses 'arch=i686 kernel=vamap arch=i686' 'scenarios.tsv: test: repeated key arch'
refuses smbios=type=4 'scenarios.tsv: test: unknown key smbios'
refuses =vamap 'scenarios.tsv: test: unknown key '
refuses kernel= 'scenarios.tsv: test: unknown value kernel=; the values are vamap lockdown lockdown-conf'
refuses kernel=integrity \
    'scenarios.tsv: test: unknown value kernel=integrity; the values are vamap lockdown lockdown-conf'
refuses kernel=vamap=1 \
    'scenarios.tsv: test: unknown value kernel=vamap=1; the values are vamap lockdown lockdown-conf'
refuses firmware=secboot \
    'scenarios.tsv: test: unknown value firmware=secboot; the values are default secboot-setup secboot-user'
refuses 'firmware=secboot-user firmware=secboot-setup' 'scenarios.tsv: test: repeated key firmware'
refuses arch= 'scenarios.tsv: test: an empty element in arch='
refuses arch=x86_64, 'scenarios.tsv: test: an empty element in arch=x86_64,'
refuses arch=,x86_64 'scenarios.tsv: test: an empty element in arch=,x86_64'
refuses arch=x86_64,,i686 'scenarios.tsv: test: an empty element in arch=x86_64,,i686'
refuses arch=x86_64,i686,x86_64 'scenarios.tsv: test: repeated element x86_64 in arch=x86_64,i686,x86_64'
refuses arch=riscv64 \
    'scenarios.tsv: test: unknown element riscv64 in arch=riscv64; the elements are x86_64 i686 aarch64'
refuses arch=x86 \
    'scenarios.tsv: test: unknown element x86 in arch=x86; the elements are x86_64 i686 aarch64'
refuses devices=fat-disk \
    'scenarios.tsv: test: unknown element fat-disk in devices=fat-disk; the elements are virtio-rng'
refuses devices=virtio \
    'scenarios.tsv: test: unknown element virtio in devices=virtio; the elements are virtio-rng'
refuses devices=virtio-rng,virtio-rng \
    'scenarios.tsv: test: repeated element virtio-rng in devices=virtio-rng,virtio-rng'

runs_on - aarch64 yes
runs_on arch=x86_64,i686 x86_64 yes
runs_on arch=x86_64,i686 i686 yes
runs_on arch=x86_64,i686 aarch64 no
runs_on arch=aarch64 x86_64 no

if ((failed > 0)); then
    echo "scenario-options-test: $failed of $cases cases failed"
    exit 1
fi
echo "scenario-options-test: $cases cases passed"
