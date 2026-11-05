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
        "devices=${option_devices[*]} guest=$option_guest params=${option_params[*]}"
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
accepts - "kernel= $all devices= guest= params="
accepts kernel=vamap "kernel=vamap $all devices= guest= params="
accepts kernel=lockdown "kernel=lockdown $all devices= guest= params="
accepts kernel=lockdown-conf "kernel=lockdown-conf $all devices= guest= params="
accepts firmware=default "kernel= $all devices= guest= params="
accepts firmware=secboot-setup \
    'kernel= firmware=secboot-setup arch=x86_64,i686,aarch64 devices= guest= params='
accepts firmware=secboot-user 'kernel= firmware=secboot-user arch=x86_64,i686,aarch64 devices= guest= params='
accepts arch=i686 'kernel= firmware=default arch=i686 devices= guest= params='
accepts arch=aarch64,x86_64 'kernel= firmware=default arch=aarch64,x86_64 devices= guest= params='
accepts devices=virtio-rng "kernel= $all devices=virtio-rng guest= params="
accepts 'devices=virtio-rng firmware=secboot-user kernel=lockdown arch=x86_64,i686' \
    'kernel=lockdown firmware=secboot-user arch=x86_64,i686 devices=virtio-rng guest= params='
accepts guest=unfixed "kernel= $all devices= guest=unfixed params="
accepts 'guest=unfixed kernel=lockdown-conf arch=x86_64' \
    'kernel=lockdown-conf firmware=default arch=x86_64 devices= guest=unfixed params='
accepts 'arch=x86_64 guest=unfixed-v5.8' \
    'kernel= firmware=default arch=x86_64 devices= guest=unfixed-v5.8 params='
accepts params=uefisettings.efivarfs=ro "kernel= $all devices= guest= params=uefisettings.efivarfs=ro"
# A parameter may have no value, or "=" in its value.
accepts params=nokaslr,uefisettings.allowed_error=a=b \
    "kernel= $all devices= guest= params=nokaslr,uefisettings.allowed_error=a=b"
accepts 'guest=unfixed params=uefisettings.efivarfs=ro,printk.devkmsg=on,uefisettings.flood=6000' \
    "kernel= $all devices= guest=unfixed params=uefisettings.efivarfs=ro,printk.devkmsg=on,uefisettings.flood=6000"
# Each case starts from the defaults, not from the case before.
accepts - "kernel= $all devices= guest= params="

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
refuses guest= 'scenarios.tsv: test: unknown value guest=; the values are unfixed unfixed-v5.8'
refuses guest=fixed 'scenarios.tsv: test: unknown value guest=fixed; the values are unfixed unfixed-v5.8'
refuses 'guest=unfixed guest=unfixed' 'scenarios.tsv: test: repeated key guest'
refuses guest=unfixed-v5.8 \
    'scenarios.tsv: test: guest=unfixed-v5.8 needs arch=x86_64: only guest-packages-x86_64-unfixed-v5.8 pins its kernel'
refuses 'arch=x86_64,i686 guest=unfixed-v5.8' \
    'scenarios.tsv: test: guest=unfixed-v5.8 needs arch=x86_64: only guest-packages-x86_64-unfixed-v5.8 pins its kernel'
refuses params= 'scenarios.tsv: test: an empty element in params='
refuses params=quiet, 'scenarios.tsv: test: run.sh sets quiet itself, not params=quiet,'
refuses params=a=1, 'scenarios.tsv: test: an empty element in params=a=1,'
refuses params=,a=1 'scenarios.tsv: test: an empty element in params=,a=1'
refuses params=a=1,,b=2 'scenarios.tsv: test: an empty element in params=a=1,,b=2'
refuses params=a=1,b,a=2 'scenarios.tsv: test: repeated parameter a in params=a=1,b,a=2'
refuses 'params=a=1 params=b=2' 'scenarios.tsv: test: repeated key params'
refuses params=console=ttyS1 'scenarios.tsv: test: run.sh sets console itself, not params=console=ttyS1'
refuses params=panic=0 'scenarios.tsv: test: run.sh sets panic itself, not params=panic=0'
refuses params=a=1,lockdown=integrity \
    'scenarios.tsv: test: run.sh sets lockdown itself, not params=a=1,lockdown=integrity'
refuses params=uefisettings.tty=ttyS0 \
    'scenarios.tsv: test: run.sh sets uefisettings.tty itself, not params=uefisettings.tty=ttyS0'
refuses params=uefisettings.test=hii \
    'scenarios.tsv: test: run.sh sets uefisettings.test itself, not params=uefisettings.test=hii'
refuses params=uefisettings.filter=x \
    'scenarios.tsv: test: run.sh sets uefisettings.filter itself, not params=uefisettings.filter=x'
refuses params=pti=off 'scenarios.tsv: test: run.sh sets pti itself, not params=pti=off'

runs_on - aarch64 yes
runs_on arch=x86_64,i686 x86_64 yes
runs_on arch=x86_64,i686 i686 yes
runs_on arch=x86_64,i686 aarch64 no
runs_on arch=aarch64 x86_64 no
runs_on 'guest=unfixed arch=x86_64,aarch64' aarch64 yes
runs_on 'guest=unfixed arch=x86_64,aarch64' i686 no

if ((failed > 0)); then
    echo "scenario-options-test: $failed of $cases cases failed"
    exit 1
fi
echo "scenario-options-test: $cases cases passed"
