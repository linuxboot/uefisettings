#!/bin/bash
# DO NOT MERGE: builds the runners' kvm-amd.ko (Ubuntu's 7.0.0-1017-azure) from its exact source,
# linux-azure 7.0.0-1017.17, twice: as Ubuntu ships it ("stock") and with a proof-of-concept fix
# ("poc"). Under Hyper-V, linux-azure's svm_load_mmu_pgd clears bits 0-11 of the guest CR3 that
# it gives the hardware whenever CR4.PCIDE is clear (https://bugs.launchpad.net/bugs/2106673);
# in 32-bit PAE paging, bits 5-11 address the page directory pointer table (KVM's own
# load_pdptrs reads it at CR3 & GENMASK(11, 5)). The PoC leaves CR3 alone in PAE paging and
# masks it as before elsewhere, the case behind the patch included: an SMM entry from long
# mode, paging off, with PCID bits in CR3 (its RFC:
# https://patchwork.kernel.org/project/kvm/patch/20240319163456.133942-1-vkuznets@redhat.com/).
# Both builds take the make variables of Ubuntu's own kernel build (kmake in
# debian/rules.d/0-common-vars.mk), so that the stock module's code is the shipped one's. The
# script fails unless the two builds differ in svm_load_mmu_pgd alone, and reports how the stock
# one compares with SHIPPED. The sha256 of the packages are those of the signed Sources and
# Packages indexes of resolute-updates.
#
# Usage: tests/qemu/ci-diag-kvm-amd.sh DOWNLOADS OUT [SHIPPED]
# DOWNLOADS: where the source and header packages are, or go if missing. OUT: gets
# stock/kvm-amd.ko, poc/kvm-amd.ko, the build logs and comparison.txt. SHIPPED: a kvm-amd.ko or
# kvm-amd.ko.zst to compare the stock build with. The source tree (1.6 GB) goes to TMPDIR.
set -euo pipefail

downloads=$1
out=$2
shipped=${3:-}
release=7.0.0-1017-azure
pool=https://archive.ubuntu.com/ubuntu/pool/main/l/linux-azure
mkdir -p "$downloads" "$out"
while read -r sum name; do
    if [[ ! -f $downloads/$name ]]; then
        curl -fsS --retry 3 -o "$downloads/$name.part" "$pool/$name"
        mv "$downloads/$name.part" "$downloads/$name"
    fi
    echo "$sum  $downloads/$name" | sha256sum --check --quiet
done <<'EOF'
c6343795c8c7e4feff55f5b309365c8e0eaf49cd6abcb412e32315313f149536 linux-azure_7.0.0.orig.tar.gz
d68babe1489bad6a7aeff52c4b5c914d4cb69594933d85c0ed343b4bd51ce0e8 linux-azure_7.0.0-1017.17.diff.gz
f4a8cd2dbd28633e6bd812790e346bf60fc90cb57d3655648d448bbb7224b855 linux-headers-7.0.0-1017-azure_7.0.0-1017.17_amd64.deb
f615cca8ffad2b52511535286e3a4e1e4d45cb557d9c4ddf762a5009d9cfa651 linux-azure-headers-7.0.0-1017_7.0.0-1017.17_all.deb
EOF

df -h "${TMPDIR:-/tmp}" >"$out/space.txt"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
tar -xzf "$downloads/linux-azure_7.0.0.orig.tar.gz" -C "$work"
zcat "$downloads/linux-azure_7.0.0-1017.17.diff.gz" | patch -d "$work/linux-7.0" -p1 --quiet
for deb in linux-headers-7.0.0-1017-azure_7.0.0-1017.17_amd64.deb linux-azure-headers-7.0.0-1017_7.0.0-1017.17_all.deb; do
    dpkg-deb -x "$downloads/$deb" "$work/sysroot"
done
headers=$work/sysroot/usr/src/linux-headers-$release

for variant in stock poc; do
    cp -a "$work/linux-7.0/arch/x86/kvm" "$work/$variant"
    rm "$work/$variant/Makefile"
    # kvm-amd.ko alone, for the stock kvm.ko: the kvm-amd lines of arch/x86/kvm/Makefile.
    cat >"$work/$variant/Kbuild" <<'EOF'
ccflags-y += -I$(src)
ccflags-$(CONFIG_KVM_WERROR) += -Werror

kvm-amd-y		+= svm/svm.o svm/vmenter.o svm/pmu.o svm/nested.o svm/avic.o

kvm-amd-$(CONFIG_KVM_AMD_SEV)	+= svm/sev.o
kvm-amd-$(CONFIG_KVM_HYPERV)	+= svm/hyperv.o

ifdef CONFIG_HYPERV
kvm-amd-y		+= svm/svm_onhyperv.o
endif

obj-m	+= kvm-amd.o

AFLAGS_svm/vmenter.o    := -iquote $(obj)
$(obj)/svm/vmenter.o: $(obj)/kvm-asm-offsets.h

$(obj)/kvm-asm-offsets.h: $(obj)/kvm-asm-offsets.s FORCE
	$(call filechk,offsets,__KVM_ASM_OFFSETS_H__)

targets += kvm-asm-offsets.s
clean-files += kvm-asm-offsets.h
EOF
done
sed -i 's/^\t\tif (!kvm_is_cr4_bit_set(vcpu, X86_CR4_PCIDE))$/\t\tif (!is_pae_paging(vcpu) \&\& !kvm_is_cr4_bit_set(vcpu, X86_CR4_PCIDE))/' \
    "$work/poc/svm/svm.c"
diff "$work/stock/svm/svm.c" "$work/poc/svm/svm.c" >"$out/poc.diff" || true
poc_line=$(printf '\t\tif (!is_pae_paging(vcpu) && !kvm_is_cr4_bit_set(vcpu, X86_CR4_PCIDE))')
mask_line=$(printf '\t\t\tcr3 &= ~X86_CR3_PCID_MASK;')
if [[ $(grep -c '^[<>]' "$out/poc.diff") != 2 ||
    $(grep -A 1 -F -x -e "$poc_line" "$work/poc/svm/svm.c") != "$poc_line"$'\n'"$mask_line" ]]; then
    echo "ci-diag-kvm-amd.sh: the PoC change does not apply as one line before the PCID mask:" >&2
    cat "$out/poc.diff" >&2
    exit 1
fi

# modinfo_field KO FIELD: FIELD of KO's .modinfo, without kmod.
modinfo_field() {
    objcopy -O binary --only-section=.modinfo "$1" "$work/modinfo"
    tr '\0' '\n' <"$work/modinfo" | sed -n "s/^$2=//p"
}

{
    echo "compiler: $(x86_64-linux-gnu-gcc --version | head -n 1); the kernel's: $(sed -n 's/^CONFIG_CC_VERSION_TEXT=//p' "$headers/.config")"
    echo "binutils: $(ld --version | head -n 1)"
} >"$out/comparison.txt"
for variant in stock poc; do
    if ! make -C "$headers" M="$work/$variant" CC=x86_64-linux-gnu-gcc CONFIG_DEBUG_SECTION_MISMATCH=y \
        CFLAGS_MODULE=-DPKG_ABI=1017 modules >"$out/build-$variant.log" 2>&1; then
        tail -n 30 "$out/build-$variant.log" >&2
        exit 1
    fi
    mkdir -p "$out/$variant"
    cp "$work/$variant/kvm-amd.ko" "$out/$variant/kvm-amd.ko"
    vermagic=$(modinfo_field "$out/$variant/kvm-amd.ko" vermagic)
    if [[ $vermagic != "$release SMP preempt mod_unload modversions " ]]; then
        echo "ci-diag-kvm-amd.sh: $variant/kvm-amd.ko has vermagic '$vermagic'" >&2
        exit 1
    fi
    echo "$variant: $(sha256sum <"$out/$variant/kvm-amd.ko" | cut -d ' ' -f 1) srcversion $(modinfo_field "$out/$variant/kvm-amd.ko" srcversion)" >>"$out/comparison.txt"
done

# code KO: the disassembly of each function of KO, each line after its function's name, by name,
# without what moves with the layout of the rest of the module: the order of the functions;
# addresses and encodings; the targets of instructions that a relocation completes, whose
# unrelocated displacements say nothing (the relocation's line, which follows, names the
# symbol); the addends of section-relative relocations (.text, .rodata, __bug_table, ...:
# .rodata holds the source file names, whose paths differ). The targets that the assembler
# resolved stay, by symbol. Not compared: which offset a section-relative relocation names,
# and the data sections (jump tables, ops tables).
code() {
    objdump -d -r --no-show-raw-insn "$1" | awk '
        # flush: prints the instruction before, its targets as placeholders (<L>) if a
        # relocation completed it, else by symbol.
        function flush() {
            if (insn == "") return
            if (relocated) {
                while (match(insn, /[0-9a-f]+ <[^>]+>/))
                    insn = substr(insn, 1, RSTART - 1) "<L>" substr(insn, RSTART + RLENGTH)
            } else {
                gsub(/[0-9a-f]+ </, "<", insn)
            }
            print f " " insn
            insn = ""
        }
        /^[0-9a-f]+ <[^>]+>:$/ { flush(); f = substr($2, 2, length($2) - 3); next }
        f == "" || /^$/ || /^Disassembly of section/ { flush(); next }
        {
            sub(/^[ \t]*[0-9a-f]+:[ \t]*/, "")
            if (/^R_[A-Z0-9_]+[ \t]/) {
                relocated = 1
                flush()
                gsub(/(\.[a-z_.]+|__bug_table)[+-]0x[0-9a-f]+/, "&@")
                gsub(/[+-]0x[0-9a-f]+@/, "+X")
                print f " " $0
            } else {
                flush()
                insn = $0
                relocated = 0
            }
        }
        END { flush() }' | LC_ALL=C sort -s -k 1,1
}

# differing A B: the functions whose lines differ between the listings of code A and B, or that
# only one has (diff's status 1, "differ", is no failure).
differing() {
    { diff "$1" "$2" || (($? == 1)); } | sed -n -E 's/^[<>] ([^ ]+) .*/\1/p' | sort -u
}

# The listings outside $(...), which set -e does not reach.
code "$out/stock/kvm-amd.ko" >"$work/stock.code"
code "$out/poc/kvm-amd.ko" >"$work/poc.code"
symbols=$(cut -d ' ' -f 1 "$work/stock.code" | sort -u | wc -l)
changed=$(differing "$work/stock.code" "$work/poc.code")
{
    echo "code compared per function: instructions, the symbols of resolved targets and relocations;"
    echo "not compared: offsets named by section-relative relocations, data sections"
    echo "stock vs poc: of $symbols symbols with code, these differ: ${changed:-none}" | tr '\n' ' '
    echo
} >>"$out/comparison.txt"
if [[ -n $shipped ]]; then
    case $shipped in
    *.zst) zstd -q -d -c "$shipped" >"$work/shipped.ko" ;;
    *) cp "$shipped" "$work/shipped.ko" ;;
    esac
    code "$work/shipped.ko" >"$work/shipped.code"
    shipped_changed=$(differing "$work/shipped.code" "$work/stock.code")
    {
        echo "shipped $(sha256sum <"$work/shipped.ko" | cut -d ' ' -f 1) vs stock: these differ: ${shipped_changed:-none}" | tr '\n' ' '
        echo
    } >>"$out/comparison.txt"
fi
cat "$out/comparison.txt"
if [[ $changed != svm_load_mmu_pgd ]]; then
    echo "ci-diag-kvm-amd.sh: the PoC must change svm_load_mmu_pgd alone" >&2
    exit 1
fi
