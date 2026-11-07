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
[`fetch-packages.sh`](fetch-packages.sh) downloads. `run.sh` first runs
[`fetch-packages-test.sh`](fetch-packages-test.sh), which checks on local fixtures how that
script unpacks a package and how it fails. The scenarios `crash-guard-*` whose
options say `guest=unfixed` or `guest=unfixed-v5.8` boot the kernels without upstream Linux
0e8d2444168d that [`guest-packages-x86_64-unfixed`](guest-packages-x86_64-unfixed),
[`guest-packages-x86_64-unfixed-v5.8`](guest-packages-x86_64-unfixed-v5.8),
[`guest-packages-i686-unfixed`](guest-packages-i686-unfixed) and
[`guest-packages-aarch64-unfixed`](guest-packages-aarch64-unfixed) pin, which crash on an
efivarfs write when the firmware's `EFI_RT_PROPERTIES_TABLE` leaves out `SetVariable()`: the
guest test [`efivarfs_crash_guard`](guest/tests/efivarfs_crash_guard.rs) checks that
`uefisettings` refuses those writes and makes the others.

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
`startup.nsh` from a copy of the ESP that also holds `uefisettings.efi` and, in `\capsule`,
the capsule payloads of [`shell/capsule/`](shell/capsule/). Then
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
[`vars/my-ifr-nv-data-auth27.json`](vars/my-ifr-nv-data-auth27.json) creates it with
authenticated access, the attributes 0x27, for the UEFI Shell scenario `shell-auth27`:
`uefisettings.efi` decodes it, and does not write it.

`publish-hiidb.efi rt-data-global-variable-forms` publishes, after the firmware's own
package lists, those of
[`publish-hiidb/src/global_variable_forms.rs`](publish-hiidb/src/global_variable_forms.rs):
forms whose questions sit on EFI global variables of the firmware, some of them volatile,
under VarStores that declare every one non-volatile.
In the scenario `hii-global-variables`, `publish-hiidb.efi padded-strings` runs first: it
publishes nothing, but registers the package list of
[`publish-hiidb/src/padded_strings.rs`](publish-hiidb/src/padded_strings.rs) in the HII
database, a strings package whose header holds padding after its Language, which the firmware
exports as it is.

`publish-hiidb.efi rt-data-readwrite-forms` creates the variable `ReadWriteData` unless it
exists, as a driver creates its storage, registers the forms of
[`publish-hiidb/src/readwrite_forms.rs`](publish-hiidb/src/readwrite_forms.rs) in the HII
database, then publishes the database as `rt-data` does: questions whose values READ and WRITE
expressions give and keep (UEFI 2.11 §33.2.5.4.1), over `ReadWriteData` and over the buffer
VarStore `AbsentBuffer`, which has no variable, and questions without a VarStore that
`uefisettings` refuses, each for its own reason. "Computed value", on `ReadWriteData` too, has
an EFI_IFR_VALUE instead, which gives it the value of "Linked value" plus 0x10, never its stored
byte, and makes it read-only (UEFI 2.11 §33.3.8.3.88). The scenarios `hii-readwrite` and
`shell-readwrite` get and set them from Linux and from the UEFI Shell, and DriverSample's
"Serial port number", whose WRITE sets three more fields.

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

`publish-hiidb.efi enhanced-auth-forms` registers the forms of
[`publish-hiidb/src/enhanced_auth_forms.rs`](publish-hiidb/src/enhanced_auth_forms.rs) the
same way, for the UEFI Shell scenario `shell-auth87`: questions on the variables that
[`vars/enhanced-auth-87.json`](vars/enhanced-auth-87.json) creates with the attributes 0x87,
among them EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS, their values behind
EFI_VARIABLE_AUTHENTICATION_3 metadata: `uefisettings.efi` decodes the value behind the
metadata of `EnhancedAuthData`, refuses that of `EnhancedAuthRefused`, and writes neither.
No edk2 firmware makes such variables, so the scenario checks only that `uefisettings.efi`
decodes the bytes that GetVariable() returns as seeded.

`publish-hiidb.efi install-config-tables` sets no `HiiDB`: it installs a copy of the HII
database, in a zeroed runtime pool a quarter larger, as the EFI configuration table of the HII
database protocol's GUID, as EDK2 does with `PcdHiiOsRuntimeSupport`, which OVMF and ArmVirt
set to FALSE. No scenario boots it.

`publish-hiidb.efi rt-properties-no-set-variable` publishes nothing: it installs an
`EFI_RT_PROPERTIES_TABLE` that lists every runtime service but `SetVariable()`, as firmware
that cannot write variables at runtime publishes, and `publish-hiidb.efi rt-properties-all` one
that lists every runtime service.
`rt-properties-version-2` and `rt-properties-version-2-all` install the same tables with
Version 2, which no UEFI version defines and which Linux reads all the same.

`publish-hiidb.efi json-config-data` publishes nothing: it installs an
`EFI_JSON_CAPSULE_CONFIG_DATA` of two items, JSON text and bytes that are no UTF-8, as the EFI
configuration table of `EFI_JSON_CONFIG_DATA_TABLE_GUID`, at an address that it never converts,
as it does not run when `SetVirtualAddressMap()` does. The scenario `json-config-data` checks
that the Linux build refuses `capsule config-data`, and `shell-json-config-data` that
`uefisettings.efi` prints it in the UEFI Shell.
`publish-hiidb.efi json-config-data-past-region` installs the same
table with a TotalLength of 16 MiB, past the runtime region that holds it,
`json-config-data-boot-services` in boot services data, and `json-config-data-mmio` points the
configuration table at runtime memory-mapped I/O; the scenarios
`shell-json-config-data-past-region`, `-boot-services` and `-mmio` check that the UEFI Shell
refuses each.

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
and refuses the other three. The `write-signed` scenarios write the same payloads with
`variable write-signed`, from the Linux test `write_signed` and from `uefisettings.efi`, and in
`secboot-setup`'s Setup Mode check that it refuses the db append before any write. In User Mode
they also create `WriteSignedProbe`, a variable of no policy, with a KEK-signed write without
`--append`, which `auth-payload.sh` signs too.

The `sign` scenarios have `variable write-signed` sign with keys that `run.sh` puts in `/sign`
of the initramfs and `\sign` of the ESP, in User Mode: db appends with KEK's key over each
digest, and with a leaf key whose bundle carries the CA that KEK issued it, which the firmware
accepts, and with db's key, a foreign key and the leaf key without its CA, which it refuses.
The Linux test signs at the system clock's second. `shell-sign-user`, with `devices=virtio-rng`,
also creates `PrivateProbe`, a private authenticated variable, with the foreign key, then
writes it again with that key and with db's. `shell-sign-no-rng`, without that device, lists the
handles of EFI_RNG_PROTOCOL first, and expects the refusal to sign where `dh` lists none, as
`check-shell-log.sh`'s `if-line` and `unless-line` checks tell. In `secboot-setup`'s Setup Mode,
`sign-setup` and `shell-sign-setup` check that it refuses KEK, signed with PK's key, before any
write, and writes it with `--allow-setup-mode-write-without-signature-check`, then PK, signed with
its own key, after which the firmware is in User Mode; `sign-setup` then checks that it refuses a
KEK append signed with a foreign key, with the flag too.
