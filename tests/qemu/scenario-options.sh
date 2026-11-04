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


# Sourced by run.sh and scenario-options-test.sh: scenario_options NAME COLUMN parses COLUMN, the
# options column of the scenario NAME of scenarios.tsv. "-" stands for the defaults; otherwise
# the column holds key=value tokens, separated by single spaces, each key at most once:
#   kernel=vamap|lockdown|lockdown-conf  how the scenario's Linux runs (run.sh); default: neither
#   arch=ARCH[,ARCH]...                  the architectures, of x86_64, i686 and aarch64, that boot
#                                        the scenario; default: all three
#   devices=DEVICE[,DEVICE]...           QEMU devices to add, of virtio-rng; default: none
# It sets option_kernel (empty without its key), option_arches and option_devices, and fails,
# naming the scenario and the key, on an empty column or token, a token without "=", an unknown
# or repeated key, an unknown value, and an empty or repeated element of a comma list.
# scenario_runs_on ARCH then tells whether the scenario boots on ARCH.

# Sets option_kernel, option_arches and option_devices from the options column $2 of scenario
# $1.
scenario_options() {
    local name=$1 column=$2 rest token key value seen=' '
    option_kernel=
    option_arches=(x86_64 i686 aarch64)
    option_devices=()
    if [[ -z $column ]]; then
        echo "scenarios.tsv: $name: the options column is empty" >&2
        return 1
    fi
    [[ $column != - ]] || return 0
    # Splits on each space, unlike read -a, which would merge spaces and hide empty tokens.
    rest=$column
    while true; do
        token=${rest%% *}
        if [[ -z $token ]]; then
            echo "scenarios.tsv: $name: an empty option: a space at the start or end, or two in a row" >&2
            return 1
        fi
        if [[ $token != *=* ]]; then
            echo "scenarios.tsv: $name: option $token has no '='" >&2
            return 1
        fi
        key=${token%%=*}
        value=${token#*=}
        if [[ $seen == *" $key "* ]]; then
            echo "scenarios.tsv: $name: repeated key $key" >&2
            return 1
        fi
        seen+="$key "
        case $key in
        kernel)
            scenario_option_value "$name" "$key" "$value" vamap lockdown lockdown-conf || return 1
            option_kernel=$value
            ;;
        arch) scenario_option_list "$name" "$key" "$value" option_arches x86_64 i686 aarch64 || return 1 ;;
        devices) scenario_option_list "$name" "$key" "$value" option_devices virtio-rng || return 1 ;;
        *)
            echo "scenarios.tsv: $name: unknown key $key" >&2
            return 1
            ;;
        esac
        [[ $rest == *' '* ]] || break
        rest=${rest#* }
    done
}

# Fails unless the value $3 of key $2 of scenario $1 is one of the values that follow.
scenario_option_value() {
    local name=$1 key=$2 value=$3
    shift 3
    if [[ " $* " != *" $value "* ]]; then
        echo "scenarios.tsv: $name: unknown value $key=$value; the values are $*" >&2
        return 1
    fi
}

# Puts the elements of the comma list $3 of key $2 of scenario $1 in the array that $4 names,
# and fails on an empty or repeated element or one that is not among the elements that follow.
scenario_option_list() {
    local name=$1 key=$2 value=$3 rest element
    local -n elements=$4
    shift 4
    elements=()
    rest=$value
    while true; do
        element=${rest%%,*}
        if [[ -z $element ]]; then
            echo "scenarios.tsv: $name: an empty element in $key=$value" >&2
            return 1
        fi
        if [[ " $* " != *" $element "* ]]; then
            echo "scenarios.tsv: $name: unknown element $element in $key=$value; the elements are $*" >&2
            return 1
        fi
        if [[ " ${elements[*]} " == *" $element "* ]]; then
            echo "scenarios.tsv: $name: repeated element $element in $key=$value" >&2
            return 1
        fi
        elements+=("$element")
        [[ $rest == *,* ]] || break
        rest=${rest#*,}
    done
}

# Tells whether the scenario that scenario_options parsed last boots on architecture $1.
scenario_runs_on() {
    [[ " ${option_arches[*]} " == *" $1 "* ]]
}
