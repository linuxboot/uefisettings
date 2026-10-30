# QEMU tests

These tests boot x86_64, i686 and aarch64 QEMU guests under EDK2's firmware (OVMF, or
AAVMF on aarch64) and run `uefisettings` inside them, so they
exercise the CLI against real UEFI firmware, efivarfs and `/dev/mem` without touching the
machine that runs them.

## Running

`make test-e2e-qemu` runs every scenario on every architecture, and
`make test-e2e-qemu-<arch>` on one of `x86_64`, `i686` and `aarch64`, on the Rust
toolchain and targets that `make setup` installs (see the Checks section of the
repository's README):

```sh
make setup    # once
make test-e2e-qemu
```

It needs an x86_64 host with `/dev/kvm`, which the x86_64 and i686 guests use; QEMU
emulates the aarch64 guests, and must be 9.0 or newer, which faults unaligned loads from
Device memory as arm64 does. On Ubuntu 26.04 it also needs the packages of
[`ubuntu-packages`](ubuntu-packages):

```sh
xargs --arg-file=tests/qemu/ubuntu-packages sudo apt-get install --yes
```

The guest's kernel, firmware and busybox do not come from the host: they are the packages
that `guest-packages-<arch>` ([x86_64](guest-packages-x86_64), [i686](guest-packages-i686)
or [aarch64](guest-packages-aarch64)) pins, which
[`fetch-packages.sh`](fetch-packages.sh) downloads.

`run.sh` alone runs the scenarios of an architecture on the active toolchain of rustup,
which then needs that architecture's musl and UEFI targets:

```sh
rustup target add x86_64-unknown-linux-musl x86_64-unknown-uefi   # once
tests/qemu/run.sh x86_64              # every scenario
tests/qemu/run.sh x86_64 boot-smoke   # the named scenarios
```

Elsewhere, these tools must be on `PATH`: `qemu-system-x86_64`, `qemu-system-i386`,
`qemu-system-aarch64`, `virt-fw-vars`, `jq` and `cpio` for `run.sh`; `curl`, `rpm2cpio`,
`cpio`, `ar`, `tar`, `xz` and `zstd` for `fetch-packages.sh`; and,
unless DriverSample.efi is already built, `gcc`, `g++`, `make`, `git`, `nasm`, `python3`
and the libuuid headers for [`build-driver-sample.sh`](build-driver-sample.sh).
The aarch64 builds also need `aarch64-linux-gnu-gcc` with the `libdl.a` of an aarch64
glibc, or another linker that `CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER` names, and
the i686 build of `uefisettings` a 32-bit `libdl.a` (Fedora: `glibc-devel.i686`), as the
`libloading` crate links `-ldl`.

The `qemu-system-*` on `PATH` may be a wrapper that `exec`s QEMU: `run.sh`
stops a boot after 120 s by signalling that program, not its children, so a wrapper that
runs QEMU as a child would leave the guest running.

Each run writes to `target/qemu-test/<arch>/<UTC time>/`, with one directory per
scenario. For each boot `N`, `bootN.console.log` has the firmware, kernel and `init`
output, `bootN.test.log` the test output and `bootN.qemu.log` how QEMU saw the guest end
(`run.sh` explains its lines).

[`scenarios.tsv`](scenarios.tsv) lists the scenarios and the boots of each; each file in
[`guest/tests/`](guest/tests/) is one test binary, which a boot names, and its module
documentation says what it checks. The guest tests refuse to run on a machine whose kernel
command line lacks `uefisettings.test=`. They build only with the `test-vm` feature, which
`run.sh` enables, so each file needs a `[[test]]` entry with
`required-features = ["test-vm"]` in [`guest/Cargo.toml`](guest/Cargo.toml).

## HII fixture

EDK2's firmware does not publish its HII database for the OS, so the HII scenarios have it
run two drivers from the ESP before the kernel, through `Driver####` load options:

- `DriverSample.efi`, EDK2's unmodified sample HII driver (BSD-2-Clause-Patent), which
  [`build-driver-sample.sh`](build-driver-sample.sh) builds from a pinned EDK2 commit on
  the first run;
- `publish-hiidb.efi`, from [`publish-hiidb/`](publish-hiidb/), which points the `HiiDB`
  variable at a copy of the HII database, the way the firmware of OCP machines does.
  It also puts the CRC-32 of the database in the `HiiDBCrc32` variable for the tests.

[`vars/my-ifr-nv-data.json`](vars/my-ifr-nv-data.json) creates DriverSample's variable
first, with runtime access, so that efivarfs shows it, and with DriverSample's defaults at
that commit.

`publish-hiidb.efi rt-data-global-variable-forms` publishes, after the firmware's own
package lists, those of
[`publish-hiidb/src/global_variable_forms.rs`](publish-hiidb/src/global_variable_forms.rs):
forms whose questions sit on EFI global variables of the firmware, some of them volatile,
under VarStores that declare every one non-volatile.
