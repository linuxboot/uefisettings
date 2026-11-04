# QEMU tests

These tests boot x86_64, i686 and aarch64 QEMU guests under EDK2's firmware (OVMF, or
AAVMF on aarch64) and run `uefisettings` inside them, so they
exercise the CLI against real UEFI firmware, efivarfs and `/dev/mem` without touching the
machine that runs them. The UEFI Shell scenarios run `uefisettings.efi` in the firmware's
UEFI Shell instead.

## Running

`make test-e2e-qemu` runs every scenario on every architecture,
`make test-e2e-qemu-<arch>` the Linux scenarios on one of `x86_64`, `i686` and `aarch64`,
and `make test-e2e-qemu-shell-<arch>` the UEFI Shell scenarios, on the Rust
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

The guest's kernel, firmware, UEFI Shell and busybox do not come from the host: they are the
packages that `guest-packages-<arch>` ([x86_64](guest-packages-x86_64),
[i686](guest-packages-i686) or [aarch64](guest-packages-aarch64)) pins, which
[`fetch-packages.sh`](fetch-packages.sh) downloads.

`run.sh` alone runs the scenarios of an architecture on the active toolchain of rustup,
which then needs that architecture's musl and UEFI targets:

```sh
rustup target add x86_64-unknown-linux-musl x86_64-unknown-uefi   # once
tests/qemu/run.sh x86_64              # every scenario
tests/qemu/run.sh x86_64 boot-smoke   # the named scenarios
```

Elsewhere, these tools must be on `PATH`: `qemu-system-x86_64`, `qemu-system-i386`,
`qemu-system-aarch64`, `virt-fw-vars`, `jq`, `cpio`, `flock` and `openssl` for `run.sh`;
`curl`, `rpm2cpio`, `cpio`, `ar`, `tar`, `xz` and `zstd` for `fetch-packages.sh`; and,
unless DriverSample.efi is already built, `gcc`, `g++`, `make`, `git`, `nasm`, `python3`
and the libuuid headers for [`build-driver-sample.sh`](build-driver-sample.sh), which
[`build-secboot-firmware.sh`](build-secboot-firmware.sh) needs too unless the i686 and
aarch64 Secure Boot firmware is already built.
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

[`scenarios.tsv`](scenarios.tsv) lists the scenarios and the boots of each. Its options column
sets how a scenario's Linux runs, the firmware that it boots, the architectures that boot it
and the QEMU devices that it adds: [`scenario-options.sh`](scenario-options.sh) parses it, and
`run.sh` runs that parser's table test,
[`scenario-options-test.sh`](scenario-options-test.sh), before any boot. Each file in
[`guest/tests/`](guest/tests/) is one test binary, which a boot names, and its module
documentation says what it checks. The guest tests refuse to run on a machine whose kernel
command line lacks `uefisettings.test=`. They build only with the `test-vm` feature, which
`run.sh` enables, so each file needs a `[[test]]` entry with
`required-features = ["test-vm"]` in [`guest/Cargo.toml`](guest/Cargo.toml).

A UEFI Shell boot names a script of [`shell/`](shell/) instead of a test binary: `run.sh`
boots no kernel, so the firmware starts its UEFI Shell, which runs the script as
`startup.nsh` from a copy of the ESP that also holds `uefisettings.efi`. Then
[`check-shell-log.sh`](check-shell-log.sh) checks each step of the script in
`bootN.console.log` against the `.tsv` file of the script: its output, which `%lasterror%`
the shell set, and the JSON of `uefisettings.efi`. The line `@LINUX@` of a script starts
Linux from the shell, after `uefisettings.efi` has run, into the guest test `boot_smoke`,
which must pass too.

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
[`vars/my-ifr-nv-data-runtime-my-efi-var.json`](vars/my-ifr-nv-data-runtime-my-efi-var.json)
also creates its EFI variable `MyEfiVar` with runtime access, which its `Vfr.vfr` declares
boot-service-only, as some vendors' firmware gives every non-volatile variable runtime
access: in the scenario `hii`, `uefisettings` reads and writes it by its own attributes.
[`vars/my-ifr-nv-data-auth27.json`](vars/my-ifr-nv-data-auth27.json) and
[`vars/my-ifr-nv-data-authA7.json`](vars/my-ifr-nv-data-authA7.json) create it with the
same data and authenticated access, the attributes 0x27 and 0xA7, for the UEFI Shell
scenarios `shell-auth27` and `shell-authA7`: `uefisettings.efi` decodes the first but not
the second, and writes neither.

`publish-hiidb.efi rt-data-global-variable-forms` publishes, after the firmware's own
package lists, those of
[`publish-hiidb/src/global_variable_forms.rs`](publish-hiidb/src/global_variable_forms.rs):
forms whose questions sit on EFI global variables of the firmware, some of them volatile,
under VarStores that declare every one non-volatile.

`publish-hiidb.efi acpi-table` sets no `HiiDB` variable: it installs the database as the body
of a `QHII` ACPI table through `EFI_ACPI_TABLE_PROTOCOL`, which `uefisettings` reads from
`/sys/firmware/acpi/tables/QHII`. QEMU's `-acpitable` cannot add it: only the x86 machines
take that option. `publish-hiidb.efi acpi-table-hiid` installs an `HIID` table instead, the
other vendor ACPI table that `uefisettings` reads: the scenario `hii-acpi-hiid`.
`publish-hiidb.efi acpi-table-junk-qhii` installs a `QHII` table whose body holds no HII
package list: in the scenario `hii-acpi-two-tables`, `uefisettings` moves on past it to the
`HIID` table.

`publish-hiidb.efi reserved` and `publish-hiidb.efi acpi-nvs` put the copy in memory that the
firmware reserves without the RUNTIME attribute, which `uefisettings` refuses, as it reads only
EFI runtime regions. No scenario boots them.

`publish-hiidb.efi password-forms` publishes nothing: it registers the forms of
[`publish-hiidb/src/password_forms.rs`](publish-hiidb/src/password_forms.rs) in the HII
database, which `uefisettings.efi` exports in the UEFI Shell: PASSWORD questions in the
layout of AMI firmware's `AMITSESetup`, which
[`vars/amitse-setup.json`](vars/amitse-setup.json) creates, and a question on a volatile
variable.

`publish-hiidb.efi install-config-tables` sets no `HiiDB`: it installs a copy of the HII
database, in a zeroed runtime pool a quarter larger, as the EFI configuration table of the HII
database protocol's GUID, as EDK2 does with `PcdHiiOsRuntimeSupport`, which OVMF and ArmVirt
set to FALSE. No scenario boots it.

## Secure Boot

The scenarios with `firmware=secboot-setup` or `firmware=secboot-user` in their options boot
firmware with Secure Boot, which authenticated variable writes need (UEFI 2.11 §8.2.6): the
pinned `OVMF_CODE_4M.secboot.fd` on x86_64, with SMM, and on i686 and aarch64 the firmware that
[`build-secboot-firmware.sh`](build-secboot-firmware.sh) builds on the first run that needs it
from `edk2-stable202508`, the last EDK2 release with OVMF IA32, which EDK2 commit
1fb88ffe284782cc79e306306b8d19829b6248b7 ("OvmfPkg: Remove OVMF IA32") removed, with the
`iasl` that [`host-packages`](host-packages) pins; its comments say why the pinned images do
not serve.
`run.sh` keeps that firmware in `target/qemu-test/<arch>/secboot-firmware/` and the EDK2 clone
in `target/qemu-test/edk2-secboot/`; delete the first after a change to
`build-secboot-firmware.sh` or `host-packages`. Secure Boot images hold no UEFI Shell, so the
Shell boots of these scenarios get the pinned `efi-shell-*` package's on the ESP, as its
removable media boot loader.

`secboot-setup`'s variable store is a template copy, in Setup Mode. In `secboot-user`'s,
`run.sh` enrolls as PK, KEK and db the certificates of keys that `openssl` generates for the
scenario, in its directory of the run, and clears `SecureBootEnable`: the firmware is in User
Mode and verifies authenticated variable writes, but not images, as the pinned Shell refuses
to run under Secure Boot outside Setup Mode. [`auth-payload.sh`](auth-payload.sh) signs a db
append of another certificate with KEK, with db's key, which KEK lacks, and with a foreign
key, which `run.sh` generates with the others but enrolls nowhere, and `run.sh` flips a byte
of a copy of the first, for the Linux test `secboot` and, through
`publish-hiidb.efi set-auth-variables=PATH[,PATH]...`, for the Shell, which reads the
statuses that the driver puts in `AuthProbeLog`: the firmware accepts the KEK-signed append
and refuses the other three.
