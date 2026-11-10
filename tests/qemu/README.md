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
The scenario `hii-platform-lang` boots the guest of `hii` and sets `PlatformLang` to `fr-FR`
first, so that the texts of `hii list-questions` follow it unless `--language` states another.

`publish-hiidb.efi rt-data-global-variable-forms` publishes, after the firmware's own
package lists, those of
[`publish-hiidb/src/global_variable_forms.rs`](publish-hiidb/src/global_variable_forms.rs):
forms whose questions sit on EFI global variables of the firmware, some of them volatile,
under VarStores that declare every one non-volatile.
In the scenario `hii-global-variables`, `publish-hiidb.efi padded-strings` runs first: it
publishes nothing, but registers the package list of
[`publish-hiidb/src/padded_strings.rs`](publish-hiidb/src/padded_strings.rs) in the HII
database, a strings package whose header holds padding after its Language, which the firmware
exports as it is. `publish-hiidb.efi string-blocks` then registers that of
[`publish-hiidb/src/string_blocks.rs`](publish-hiidb/src/string_blocks.rs): a strings package
of every string block type, then one of a single string, to which the firmware's HII database
appends an `EFI_HII_SIBT_SKIP2` block up to the first package's last string ID. The test
compares that ID with the last one that `uefisettings` reads, so it checks how `uefisettings`
counts string IDs, not how it decodes SCSU strings, which edk2 widens byte by byte.

`publish-hiidb.efi rt-data-readwrite-forms` creates the variable `ReadWriteData` unless it
exists, as a driver creates its storage, registers the forms of
[`publish-hiidb/src/readwrite_forms.rs`](publish-hiidb/src/readwrite_forms.rs) in the HII
database, then publishes the database as `rt-data` does: questions whose values READ and WRITE
expressions give and keep (UEFI 2.11 §33.2.5.4.1), over `ReadWriteData` and over the buffer
VarStore `AbsentBuffer`, which has no variable, and questions without a VarStore that
`uefisettings` refuses, each for its own reason. "Computed value", on `ReadWriteData` too, has
an EFI_IFR_VALUE instead, which gives it the value of "Linked value" plus 0x10, never its stored
byte, and makes it read-only (UEFI 2.11 §33.3.8.3.88). "Option width", a UINT16 ONE_OF on
`ReadWriteData`, has the UINT8 option "Narrow", which `set` writes zero-extended in both bytes
of the question. The scenarios `hii-readwrite` and
`shell-readwrite` get and set them from Linux and from the UEFI Shell, and DriverSample's
"Serial port number", whose WRITE sets three more fields.

`publish-hiidb.efi acpi-table` sets no `HiiDB` variable: it installs the database as the body
of a `QHII` ACPI table through `EFI_ACPI_TABLE_PROTOCOL`, which `uefisettings` reads from
`/sys/firmware/acpi/tables/QHII`. QEMU's `-acpitable` cannot add it: only the x86 machines
take that option. `publish-hiidb.efi acpi-table-hiid` installs an `HIID` table instead, the
other vendor ACPI table that `uefisettings` reads: the scenario `hii-acpi-hiid`.
`publish-hiidb.efi acpi-table-junk-qhii` installs a `QHII` table whose body holds no HII
package list: in the scenario `hii-acpi-two-tables`, `uefisettings` moves on past it to the
`HIID` table. In these scenarios, `--hii-source acpi hii extract-db` writes exactly the
database of the table that it reads. Under `lockdown=integrity`, which refuses `/dev/mem`, the
scenario `hii-lockdown-acpi` checks that the vendor ACPI table method still reads the database,
and `hii-lockdown-efivar`, with `publish-hiidb.efi rt-data`, that the `HiiDB` variable method
refuses before it opens `/dev/mem`, naming lockdown, and that the automatic order stops there.

`publish-hiidb.efi reserved` and `publish-hiidb.efi acpi-nvs` put the copy in memory that the
firmware reserves without the RUNTIME attribute, which `uefisettings` refuses by default, as it
reads only EFI runtime regions. The scenario `hii-reserved` checks that refusal of extract-db
and set, and that `--efivar-memory firmware-reserved` reads the copy. In the scenario
`hii-acpi-nvs`, on x86_64 and i686, Linux marks the ACPI NVS copy busy, which `/dev/mem`
refuses to map under `CONFIG_IO_STRICT_DEVMEM`, and on x86_64 to read (i686's Linux fails read()
of it with EFAULT, past its low memory): with `--efivar-memory firmware-reserved`, the `HiiDB`
variable method reports the kernel's refusal. The scenario skips aarch64 because arm64 Linux
v6.11 registers nomap memory as a non-busy reserved resource, which devmem_is_allowed() admits
(lib/devmem_is_allowed.c:21-28; arch/arm64/kernel/setup.c:227-229).
The scenario `hii-devmem-guard` checks that the `HiiDB` variable method refuses a copy in loader
data, which Linux makes System RAM, by its range check before any read.

The scenario `hii-none` publishes the database in no way: every hii command that reads it
fails, and names the absent source of each method of `--hii-source auto`. On aarch64, the
scenarios `hii-no-memory-map-efivar`, with `publish-hiidb.efi rt-data`, and
`hii-no-memory-map-systab`, with `publish-hiidb.efi install-config-tables`, run `uefisettings`
in a mount namespace without `/sys/firmware/fdt` and `/proc/kcore`, where no EFI memory map
bounds the reads of firmware memory: both methods refuse, naming the missing FDT.

`publish-hiidb.efi password-forms` publishes nothing: it registers the forms of
[`publish-hiidb/src/password_forms.rs`](publish-hiidb/src/password_forms.rs) in the HII
database, which `uefisettings.efi` exports in the UEFI Shell: PASSWORD questions in the
layout of AMI firmware's `AMITSESetup`, which
[`vars/amitse-setup.json`](vars/amitse-setup.json) creates, and a question on a volatile
variable. It also creates the variable `PlaintextPassword` unless it exists and registers the
forms of
[`publish-hiidb/src/plaintext_password_forms.rs`](publish-hiidb/src/plaintext_password_forms.rs):
a PASSWORD question whose password `PlaintextPassword` keeps as plaintext, a NUMERIC over its
bytes and one beside it. `publish-hiidb.efi rt-data-password-forms` does the same, then
publishes the database as `rt-data` does. The scenarios `shell-password` and `hii-password`
check, in the UEFI Shell and from Linux, that a question whose bytes overlap a password's
shows no byte of it and that `set` refuses it, while the questions beside the passwords read
and write.

`publish-hiidb.efi enhanced-auth-forms` registers the forms of
[`publish-hiidb/src/enhanced_auth_forms.rs`](publish-hiidb/src/enhanced_auth_forms.rs) the
same way, for the UEFI Shell scenario `shell-auth87` and, with `publish-hiidb.efi rt-data`
after it, the Linux scenario `hii-auth87`: questions on the variables that
[`vars/enhanced-auth-87.json`](vars/enhanced-auth-87.json) creates with the attributes 0x87,
among them EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS, their values behind
EFI_VARIABLE_AUTHENTICATION_3 metadata: `uefisettings.efi` and `uefisettings` decode the value
behind the metadata of `EnhancedAuthData`, refuse that of `EnhancedAuthRefused`, and write
neither. No edk2 firmware makes such variables, so the scenarios check only that they decode
the bytes that GetVariable() and efivarfs return as seeded.

`publish-hiidb.efi dropped-password-forms` registers those of
[`publish-hiidb/src/dropped_password_forms.rs`](publish-hiidb/src/dropped_password_forms.rs):
two form sets on the variable that [`vars/dropped-password.json`](vars/dropped-password.json)
creates, the second with a PASSWORD and an op shorter than its minimum, which UEFI 2.11
§33.2.5.10.1 calls malformed. `uefisettings` ignores that form set, so in the scenario
`shell-dropped-password` `uefisettings.efi` reads and writes no variable.

`publish-hiidb.efi formset-skip-forms` registers those of
[`publish-hiidb/src/formset_skip_forms.rs`](publish-hiidb/src/formset_skip_forms.rs): two package
lists on the variables that [`vars/formset-skip.json`](vars/formset-skip.json) creates, one of four
form sets, the second with a PASSWORD on a variable of its own and an op shorter than its minimum,
and one of two form sets on one variable, the first such a form set. `uefisettings` ignores those
form sets and reads the others, which edk2's walk for form sets finds after them: in the scenario
`hii-formset-skip`, whose later `publish-hiidb.efi rt-data` exports the database, `uefisettings`
reads and writes the questions of the form sets that it reads, but withholds every byte of each
variable that a form set that it ignores declares, that of the second list too, and names those
that it ignores, while in `shell-formset-skip` `uefisettings.efi` reads and writes no variable. The
third form set of the first list has a second form with a PASSWORD and a CHECKBOX op shorter than
its minimum: `uefisettings` disables that form alone, names it with the IFR that it ignores, and
withholds the bytes of its PASSWORD, which a question of a fourth form set overlaps.
`publish-hiidb.efi disabled-form-forms` registers a package list of such a form set alone, on the
variable that [`vars/disabled-form.json`](vars/disabled-form.json) creates: in the scenario
`shell-disabled-form`, `uefisettings.efi` reads and writes the questions of its other form, and
no byte of that PASSWORD.

`publish-hiidb.efi short-var-store-forms` registers those of
[`publish-hiidb/src/short_var_store_forms.rs`](publish-hiidb/src/short_var_store_forms.rs):
questions on a VARSTORE_EFI of the form before UEFI 2.3.1, each on the EFI variable of its
VarName, which [`vars/short-var-store.json`](vars/short-var-store.json) creates, among them a
CHECKBOX that a SUPPRESS_IF with a GET hides and whose WRITE expression holds a SET, and a
PASSWORD; it does not create ShortVarD, the variable of a UINT16 NUMERIC.
`publish-hiidb.efi rt-data-short-var-store-forms` does the same, then publishes the database as
`rt-data` does. The scenarios `shell-short-var-store` and `short-var-store` check, in the UEFI
Shell and from Linux, that `get` and `set` read and write the variable of each question's
VarName, and the GET and the SET those of theirs, while no byte of the password's variable is
read or written, and that `set` creates ShortVarD with the store's Attributes.

`publish-hiidb.efi outside-form-set-password-forms` creates the variable `OutsidePassword`
unless it exists and registers the forms of
[`publish-hiidb/src/outside_form_set_password_forms.rs`](publish-hiidb/src/outside_form_set_password_forms.rs):
a PASSWORD question outside any form set, which no Forms Browser shows but edk2's Config
Keyword Handler finds, on the VarStoreId of the form set's VARSTORE_EFI `OutsidePassword`,
which keeps its password, and NUMERICs over and beside the password's bytes.
`publish-hiidb.efi rt-data-outside-form-set-password-forms` does the same, then publishes the
database as `rt-data` does. In the scenario `shell-outside-form-set-password`
`uefisettings.efi` reads and writes no variable of the HII database, and in
`hii-outside-form-set-password` Linux shows no byte of the password and `set` refuses the
question over it, while the question beside it reads.

`publish-hiidb.efi first-store-password-forms` creates the variables `FirstStore` and
`PasswordStore` unless they exist and registers the forms of
[`publish-hiidb/src/first_store_password_forms.rs`](publish-hiidb/src/first_store_password_forms.rs):
a form set whose VARSTORE_EFI `FirstStore` is the first VarStore of its VarStoreId in the form
package, with NUMERICs over and beside the bytes that keep a password, then a form set whose
PASSWORD question of that VarStoreId is on its VARSTORE_EFI `PasswordStore`. edk2's Config
Keyword Handler takes the first VarStore of a question's VarStoreId in the form package, so
`FirstStore` keeps that password. `publish-hiidb.efi rt-data-first-store-password-forms` does the
same, then publishes the database as `rt-data` does. In the scenarios
`shell-first-store-password` and `hii-first-store-password` `uefisettings` shows no byte of the
password in the UEFI Shell and from Linux and `set` refuses the question over it, while the
question beside it reads, and in the UEFI Shell writes.

`publish-hiidb.efi install-config-tables` sets no `HiiDB`: it installs a copy of the HII
database, in a zeroed runtime pool a quarter larger, as the EFI configuration table of the HII
database protocol's GUID, as EDK2 does with `PcdHiiOsRuntimeSupport`, which OVMF and ArmVirt
set to FALSE. The scenario `hii-systab` and, on aarch64 with `kernel=vamap`, `hii-systab-vamap`
check that the Linux build reads it with `--hii-source systab` and in the automatic order, where
the vendor ACPI tables and the `HiiDB` variable report their sources absent.

`publish-hiidb.efi export-config` installs the current configuration that EDK2 exports with
`PcdHiiOsRuntimeSupport` too (UEFI 2.11 §33.2.11.1): `ExportConfig()`'s results, in a zeroed
runtime pool a quarter larger, as the EFI configuration table of the HII Configuration Routing
Protocol's GUID. Before that, it registers the forms of
[`publish-hiidb/src/password_forms.rs`](publish-hiidb/src/password_forms.rs) for a handle
with a device path of its own, as a driver does, and after the results it appends a
`<ConfigResp>` that fills the bytes of their PASSWORD questions in `AMITSESetup` with 0xA5
and sets the ONE_OF after them to 1, as that driver's `ExtractConfig()` would export it. In
the scenario `hii-snapshot`,
[`vars/my-ifr-nv-data-boot-services.json`](vars/my-ifr-nv-data-boot-services.json) creates
DriverSample's variable without runtime access and with values other than its defaults, so
Linux does not see it: `uefisettings` shows the values of its questions and of that ONE_OF
from the snapshot, prints and logs no byte of the passwords, and `set` refuses DriverSample's
questions as without the snapshot.

`publish-hiidb.efi rt-properties-no-set-variable` publishes nothing: it installs an
`EFI_RT_PROPERTIES_TABLE` that lists every runtime service but `SetVariable()`, as firmware
that cannot write variables at runtime publishes, and `publish-hiidb.efi rt-properties-all` one
that lists every runtime service.
`rt-properties-version-2` and `rt-properties-version-2-all` install the same tables with
Version 2, which no UEFI version defines and which Linux reads all the same.
Where neither the kernel's symbols nor its `generic_ops` tell, as on i686 or under
`kernel.kptr_restrict=2`, the scenarios `crash-guard-nosetvar-i686` and
`crash-guard-nosetvar-kptr2` check that `uefisettings` refuses the write by the table that it
reads from `/dev/mem`, and `crash-guard-all-ro-kptr2` that it writes by the one that lists
`SetVariable()`.

`publish-hiidb.efi json-config-data` publishes nothing: it installs an
`EFI_JSON_CAPSULE_CONFIG_DATA` of two items, JSON text and bytes that are no UTF-8, as the EFI
configuration table of `EFI_JSON_CONFIG_DATA_TABLE_GUID`, at an address that it never converts,
as it does not run when `SetVirtualAddressMap()` does. The scenarios `json-config-data` and, on
aarch64 with `kernel=vamap`, `json-config-data-vamap` check that the Linux build prints it with
`capsule config-data`, and `shell-json-config-data` that `uefisettings.efi` prints it in the UEFI
Shell.
`publish-hiidb.efi json-config-data-past-region` installs the same
table with a TotalLength of 16 MiB, past the runtime region that holds it,
`json-config-data-boot-services` in boot services data, and `json-config-data-mmio` points the
configuration table at runtime memory-mapped I/O; the scenarios `json-config-data-past-region`,
`-boot-services` and `-mmio` check that the Linux build refuses each, and
`shell-json-config-data-past-region`, `-boot-services` and `-mmio` that the UEFI Shell does.

`publish-hiidb.efi json-capsule-result` publishes nothing either: it installs the result of
processing a JSON capsule, an `EFI_CAPSULE_RESULT_VARIABLE_HEADER` and an
`EFI_CAPSULE_RESULT_VARIABLE_JSON`, as the EFI configuration table of
`EFI_JSON_CAPSULE_RESULT_TABLE_GUID`, with a CapsuleStatus of the driver's width, at an address
that it never converts. The scenarios `capsule-results` (x86_64, aarch64) and
`capsule-results-i686` check that the Linux build prints it with `capsule result-table`, and print
with `capsule results` the variables of
[`vars/capsule-results-64.json`](vars/capsule-results-64.json) or
[`vars/capsule-results-32.json`](vars/capsule-results-32.json): three results, of a JSON capsule,
of a CapsuleGuid that no specification defines and of an FMP capsule, with the 48-byte header of
64-bit firmware or the 44-byte header of 32-bit firmware, a fourth of 3 bytes, which do not decode,
and CapsuleMax and CapsuleLast. Each is non-volatile, CapsuleMax too, which edk2 writes with BS|RT only
(edk2-stable202608 MdeModulePkg/Library/DxeCapsuleLibFmp/DxeCapsuleReportLib.c
InitCapsuleMaxVariable()), as the variable store that seeds them holds no volatile variable.
`shell-capsule-results` and `shell-capsule-results-i686` check that `uefisettings.efi` prints the
same results in the UEFI Shell, and the table.

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
`sign-user` and `shell-sign-user` also write `EnhancedProbe` with
EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS: the payload that `auth-payload.sh auth3` signs, and
those that `variable write-signed` signs at a TimeStamp, with a nonce and with a NewCert. Linux
refuses them before any write, as its efivarfs lacks the attribute, and the firmware with
EFI_INVALID_PARAMETER, as EDK2's variable driver takes no such attribute; the variable stays
absent.

`shell-devdb-setup` checks, in Setup Mode, that `uefisettings.efi` refuses an append to devdb, the
device signature database of UEFI 2.11 §32.6.3, signed with PK's key, before any write, and
appends with `--allow-setup-mode-write-without-signature-check`, which creates devdb; that the
firmware then refuses an append signed with KEK's key, as edk2 takes devdb's updates only from the
signer that created it, and takes one signed with PK's; and, in its Linux boot, that `variable
write-signed` refuses another append without the flag. `variable-get-devdb` and
`shell-variable-get-devdb` read, on the default firmware, the devdb that
[`vars/devdb.json`](vars/devdb.json) seeds, and check that `variable set` refuses to write it.
