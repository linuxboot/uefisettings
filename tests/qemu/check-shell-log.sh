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

# Checks the console log of a UEFI Shell boot of run.sh against the expectations of its
# script, and fails unless every check passes.
#
# Usage: tests/qemu/check-shell-log.sh ARCH EXPECTATIONS CONSOLE_LOG
#
# The script, tests/qemu/shell/NAME.nsh, runs with echo -off and echoes
# "uefisettings-shell: start" first, "uefisettings-shell: step STEP %lasterror%" after each
# step and "uefisettings-shell: done" last: the output of a step is the console lines after
# the marker before it. EXPECTATIONS, tests/qemu/shell/NAME.tsv, holds the checks, one per
# line, in tab-separated columns:
#   step       the step that the check reads
#   check      status: the step's %lasterror% is the argument; "aborted" stands for
#                EFI_ABORTED, which the shell shows as 0x15, and as 0x80000015 on i686, and
#                "any" checks none, for a step that runs a command of the shell
#              json: the step's output is one line, whose JSON the jq filter of the argument
#                finds true
#              line: a line of the step's output matches the extended regular expression of
#                the argument
#              none: no line of the step's output matches that expression
#              same: the step's output is that of the step that the argument names
#              variable: the argument is "NAME STEP"; the step's output, that of the shell's
#                set, has the line "NAME = VALUE", and VALUE is the one line of STEP's output
#              parity: the step's output is one line, the JSON of hii list-questions, and
#                the argument names a test log, next to CONSOLE_LOG, with the line
#                "uefisettings-qemu-test: list-questions JSON" of a Linux boot, where the
#                questions are pairs: every question that Linux reads, at least one, has
#                the same value here, every question on a variable that Linux finds missing
#                or not present at OS runtime has a value here unless the firmware has no
#                such variable, and at least one has
#   argument   what the check takes
# Every step of the log needs a status check, and every step that a check names must be in
# the log once.

set -euo pipefail
shopt -s nullglob
source "$(dirname "$0")/control-sequence.sh"

if (($# != 3)); then
    echo "usage: $0 ARCH EXPECTATIONS CONSOLE_LOG" >&2
    exit 2
fi
arch=$1
expectations=$2
console=$3
case $arch in
i686) aborted=0x80000015 ;;
x86_64 | aarch64) aborted=0x15 ;;
*)
    echo "unknown architecture $arch; the architectures are x86_64, i686 and aarch64" >&2
    exit 2
    ;;
esac

logs=$(dirname "$console")
steps=$(mktemp -d)
trap 'rm -r "$steps"' EXIT
# The console has CRLF line ends and control sequences.
if ! tr -d '\r' <"$console" | LC_ALL=C sed "s|$control_sequence||g" | awk -v steps="$steps" '
    $0 == "uefisettings-shell: start" { started = 1; output = ""; next }
    !started { next }
    $0 == "uefisettings-shell: done" { done = 1; exit }
    /^uefisettings-shell: step / {
        if (NF != 4 || $3 !~ /^[a-z0-9-]+$/ || ($3 in seen)) {
            printf "check-shell-log: bad or repeated step marker: %s\n", $0
            bad = 1
            exit
        }
        seen[$3] = 1
        printf "%s", output > (steps "/" $3 ".out")
        close(steps "/" $3 ".out")
        print $4 > (steps "/" $3 ".status")
        close(steps "/" $3 ".status")
        output = ""
        next
    }
    { output = output $0 "\n" }
    END {
        if (!started) print "check-shell-log: the script never started"
        else if (!done && !bad) print "check-shell-log: the script never finished"
        exit bad || !done
    }'; then
    exit 1
fi

# Pairs the questions of $linux and of the input by name and rank among those of that name;
# counts the pairs where Linux reads a value and lists those whose values differ; lists those
# on a variable that Linux finds missing or not present at OS runtime where the input has
# no value either, though the firmware has the variable, and counts those where it has.
parity_filter='
    def by_rank: group_by(.name) | map(to_entries | map({key: "\(.value.name) #\(.key)", value})) | add // [] | from_entries;
    def unavailable: .answer | startswith("<ValueUnavailable");
    def value: .answer | split(" <")[0];
    ($linux | by_rank) as $l | by_rank as $s |
    [$l | to_entries[] | select(.value | unavailable | not)] as $read |
    [$read[] | select($s[.key] == null or ($s[.key] | value) != (.value | value)) | .key] as $differing |
    [$l | to_entries[]
        | select(.value.answer | test("^<ValueUnavailable: (no EFI variable |EFI variable [^ ]* is not present at OS runtime: )"))] as $unread |
    {
        compared: $read | length,
        differing: $differing,
        unreached: [$unread[] | select($s[.key] == null or (($s[.key] | unavailable)
            and ($s[.key].answer | startswith("<ValueUnavailable: no EFI variable ") | not))) | .key],
        reached: [$unread[] | select($s[.key] != null and ($s[.key] | unavailable | not))] | length
    }'

failures=0
# Reports a failed check of STEP and the step's output.
fail() {
    local step=$1 message=$2
    printf 'check-shell-log: FAILED: %s: %s; its output:\n' "$step" "$message"
    [[ ! -f $steps/$step.out ]] || sed 's/^/check-shell-log:   /' "$steps/$step.out"
    failures=$((failures + 1))
}

declare -A status_checked
# read fails on a last line without a newline, which still counts.
while IFS=$'\t' read -r step check argument || [[ -n $step ]]; do
    [[ -z $step || $step == \#* ]] && continue
    if [[ ! -f $steps/$step.out ]]; then
        fail "$step" "not in the log"
        continue
    fi
    out=$steps/$step.out
    case $check in
    status)
        status_checked[$step]=1
        want=$argument
        [[ $want != aborted ]] || want=$aborted
        got=$(<"$steps/$step.status")
        [[ $want == any || $got == "$want" ]] || fail "$step" "status $got, not $want"
        echo "check-shell-log: $step: status $got"
        ;;
    json)
        if (($(wc -l <"$out") != 1)) || ! jq --exit-status "$argument" <"$out" >/dev/null 2>&1; then
            fail "$step" "not one line of JSON for which $argument holds"
        fi
        ;;
    line) grep --quiet --extended-regexp -- "$argument" "$out" || fail "$step" "no line matches $argument" ;;
    none) ! grep --quiet --extended-regexp -- "$argument" "$out" || fail "$step" "a line matches $argument" ;;
    same)
        [[ -f $steps/$argument.out ]] && cmp --quiet "$steps/$argument.out" "$out" ||
            fail "$step" "output differs from that of $argument"
        ;;
    variable)
        read -r name other <<<"$argument"
        if [[ ! -f $steps/$other.out ]] || (($(wc -l <"$steps/$other.out") != 1)) ||
            [[ $(sed -n "s/^ *$name = //p" "$out") != "$(<"$steps/$other.out")" ]]; then
            fail "$step" "variable $name is not the output of $other"
        fi
        ;;
    parity)
        # a file, as the JSON can exceed the length of an argument
        if ! tr -d '\r' <"$logs/$argument" |
            sed -n 's/^uefisettings-qemu-test: list-questions //p' >"$steps/linux.json" ||
            ! parity=$(jq --compact-output --slurpfile linux "$steps/linux.json" \
                "\$linux[0] as \$linux | $parity_filter" <"$out"); then
            fail "$step" "no JSON of list-questions here or in $argument"
            continue
        fi
        echo "check-shell-log: $step: parity with $argument: $parity"
        jq --exit-status '.compared > 0 and .differing == [] and .unreached == [] and .reached > 0' \
            <<<"$parity" >/dev/null || fail "$step" "no parity with $argument"
        ;;
    *)
        echo "check-shell-log: unknown check $check of $step in $expectations" >&2
        exit 2
        ;;
    esac
done <"$expectations"
for out in "$steps"/*.out; do
    step=$(basename "$out" .out)
    [[ -n ${status_checked[$step]:-} ]] || fail "$step" "no status check in $expectations"
done
if ((failures > 0)); then
    echo "check-shell-log: $failures checks FAILED"
    exit 1
fi
echo "check-shell-log: every check passed"
