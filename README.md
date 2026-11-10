# `uefisettings`

## About

`uefisettings` is a tool to read and write BIOS settings on a local host. It currently supports two interfaces:

* HiiDB (used in OCP and also has partial support in other platforms)
* iLO BlobStore (used in HPE)

---

## Install

```sh
cargo install uefisettings
```

## Build manually

```sh
cd /tmp
git clone https://github.com/linuxboot/uefisettings
cd uefisettings
cargo install --path .
~/.cargo/bin/uefisettings --help
```

---

## Usage examples

### Reset TPM

```sh
uefisettings hii set 'Pending operation' 'TPM Clear'
```

### Check if TXT is enabled

```sh
if [[ "$(uefisettings hii get --json 'Enable Intel(R) TXT' | jq -r '.responses | .[].question.answer')" = "Enable" ]]; then
    # Do something if TXT is enabled
fi
```

### Inspect a Linux machine's settings on macOS

```sh
# on the Linux machine
sudo uefisettings hii extract-db hiidb.bin
uefisettings hii dump-efivars -f hiidb.bin efivars
# on the Mac, with the efivars directory copied over
uefisettings hii list-questions --efivars efivars
```

---

## Available commands

```plain
Commands:
  capsule            Commands that pass capsules to this machine's firmware, or show the
                     configuration data and the capsule processing results that it reports
  get                Auto-identify backend and get the current value of a question
  help               Print this message or the help of the given subcommand(s)
  hii                Commands which work on machines exposing the UEFI HiiDB
  identify           Auto-identify backend and display hardware/bios-information
  ilo                Commands which work on machines having HPE's Ilo BMC
  set                Auto-identify backend and set/change the value of a question
  show-translations  Show the translation/spellings database for questions and answers
  variable           Commands on this machine's EFI variables
```

`hii`:

```plain
Commands:
  dump-efivars    Copy the HiiDB and the EFI variables that its questions read into a new directory,
                  for --efivars on another machine
  extract-db      Dump HiiDB into a file
  get             Get the current value of a question
  help            Print this message or the help of the given subcommand(s)
  list-questions  List questions HiiDB. Note that these are not all possible questions, because we
                  don't parse certain non-useful question types
  list-strings    List all strings-id, string pairs in HiiDB, with each strings package's language
  set             Set/change the value of a question
  show-ifr        Show a human readable representation of the Hii Forms
```

`variable`:

```plain
Commands:
  get           Show the attributes and the decoded value of a global variable of UEFI 2.11 section
                3.3, but its load options, hot keys and device paths, or of a signature database, or
                that it is absent
  help          Print this message or the help of the given subcommand(s)
  info          Show the attributes and the size of an EFI variable, never its data
  list          List the name and vendor GUID of every EFI variable, never its data
  set           Set a global variable of UEFI 2.11 section 3.3 that the OS may write: Timeout,
                BootOrder, DriverOrder, SysPrepOrder, BootNext, PlatformLang or OsIndications
  storage       Show the storage space of the EFI variables of some attributes, and how much of it
                is left
  write-signed  Write an EFI variable from a signed payload, or from new data that a key signs; the
                firmware verifies the signature
```

`capsule`:

```plain
Commands:
  config-data   Print the configuration data of the firmware's JSON configuration table: each item
                as text if it is UTF-8, else as hex
  deliver       Deliver a file to the firmware, unchanged, as the JSON payload of a configuration
                capsule; it never resets the machine
  help          Print this message or the help of the given subcommand(s)
  result-table  Print the result of processing a JSON capsule that the firmware reports in its JSON
                capsule result table
  results       Print the results of capsule processing that the firmware reports in its Capsule####
                variables, and the CapsuleMax and CapsuleLast variables that name them
```

`ilo`:

```plain
Commands:
  get                      Get the current value of a question
  help                     Print this message or the help of the given subcommand(s)
  set                      Set/change the value of a question
  show-attributes          List bios attributes and their current values
  show-pending-attributes  List all pending changes that will take effect after reboot
```

---

## In the UEFI Shell

`uefisettings.efi` runs `get`, `set`, `show-translations`, the `variable` and `capsule` commands
and the `hii` commands but `extract-db` and `dump-efivars` in the UEFI Shell, before an OS boots;
it also reaches boot-service-only variables, and has no `-f` or `--efivars`.

```sh
rustup target add x86_64-unknown-uefi  # or i686-unknown-uefi, aarch64-unknown-uefi
cargo build --release --target x86_64-unknown-uefi
```

```plain
FS0:\> uefisettings.efi hii get --json "Activate this check box"
```

Exit statuses, setup passwords, `variable`, capsules and Secure Boot: see the
[appendix](#appendix).

---

## On Windows

On Windows, when a driver implementing the IOCTL contract in
[hiidb_driver.rs](src/lib/hii/hiidb_driver.rs) is installed, `uefisettings` reads
the live HiiDB through that driver, and reads the EFI variables through the firmware
environment calls, which enable the SeSystemEnvironmentPrivilege. The privilege must
be assigned to the process token; running elevated alone does not guarantee it.
Pass `--no-efivars` to read no variables. No driver is shipped with this repository,
and none has been tested here. Without a driver, `-f` still reads a HiiDB file, and,
when such a driver is installed, `hii extract-db` writes its HiiDB to a file.
`variable list` and `variable storage` fail there: the firmware environment calls reach a
variable by its name only, and have no QueryVariableInfo(). So does `capsule deliver`: those calls
reach EFI variables only. `capsule config-data` and `capsule result-table` fail too:
`uefisettings` reads the configuration tables of the EFI System Table only in the UEFI Shell, and on
Linux on x86, x86_64 and aarch64.

---

## On macOS

`cargo install uefisettings` builds on macOS too. That build reads nothing of the Mac's firmware
and writes nothing: `hii get`, `hii list-questions` and `hii show-ifr` read question values from
an efivars dump that `hii dump-efivars` wrote on Linux (`--efivars DIR`, with its HiiDB unless
`-f` names one) or from none (`--no-efivars`, with `-f`), and `hii list-strings` reads the HiiDB
file of `-f`. It has no `get`, `set`, `identify`, `ilo`, `variable`, `capsule`, `hii set`,
`hii extract-db` or `hii dump-efivars`. Dumps: see the [appendix](#appendix).

---

## Changing UEFI settings with automation

To change BIOS settings from Linux terminal there are usually next ways available:

* On [Open Compute Project](https://www.opencompute.org/) hardware - read/parse a binary database called Hii (defined in the UEFI spec) and manipulate binary files in the `/sys` file system to change settings. This approach may also work on some non-OCP consumer hardware like your laptops.
* On Hewlett Packard Enterprise hardware - use HPE's redfish API to read/write settings. This requires the presence of HPE's iLO BMC.
* Use different proprietary tools like SCELNX from AMI or conrep from HPE. However, these require additional kernel modules to be loaded.

But this tool is an unified opensource approach to manipulate UEFI settings on any platform.

---

## How it works

### For OCP hardware

* Extract HiiDB. Linux exposes no file that holds it, so the standard way is to follow the EFI System Table: `/sys/firmware/efi/config_table` holds the address of its `EFI_CONFIGURATION_TABLE` array, the entry for `gEfiHiiDatabaseProtocolGuid` points at the exported database, and every step is read from `/dev/mem`. The firmware must install that entry (`PcdHiiOsRuntimeSupport`, TRUE by default in edk2), and not every kernel creates `config_table`. The length is not recorded, so it is found by walking the package lists up to the zero padding after them.
* If that fails, the reason is logged at debug level and the vendor ACPI table `QHII` or `HIID` is tried: if the firmware publishes a copy of the HiiDB there, `uefisettings` reads it from `/sys/firmware/acpi/tables/QHII`, else from `/sys/firmware/acpi/tables/HIID` (skip the 36-byte ACPI header), without `/dev/mem`, moving on past tables that are absent or fail their checks. This is the way where `/dev/mem` cannot reach the database (e.g. aarch64, whose EFI runtime memory is `nomap`).
* If that fails too, the reason is logged at debug level and the OCP way is used: read the physical address and length from the `HiiDB-1b838190-4625-4ead-abc9-cd5e6af18fe0` efivar and then read that memory from `/dev/mem`, only from an EFI runtime region of the firmware's memory map, and only once the kernel lockdown mode, which needs securityfs mounted, allows `/dev/mem`.
* Library (`hii`) in Rust partially implements the UEFI Hii specification.
* It parses the HiiDB op-codes into a DOM tree like representation which can be read by machines and humans.
* It can ask questions about UEFI settings from HiiDB and get their answers.
* `get`, `set` and `hii list-questions` evaluate the `suppressif`, `grayoutif` and `disableif` conditions of questions as EDK2's setup browser does, and select only questions that none of them suppresses, grays out or disables, unless `--include` names that state (`grayed-out`, `suppressed`, `disabled`); an answer ends with the state of a question that is not selectable. Where a condition cannot be evaluated from Linux, `set` refuses the question, while `get` and `hii list-questions` show it with the states it may be in and why. A one-of option in a `suppressif` counts as suppressed, and a question that a `locked` (`EFI_IFR_LOCKED`) locks as grayed out. UEFI 2.11 §33.3.8.3.37 addresses LOCKED to Forms Editors; uefisettings follows edk2-stable202608 SetupBrowserDxe, which grays out a locked statement and every statement of a locked form (Presentation.c InitializeDisplayStatement, IfrParse.c ParseOpCodes).
* `set` refuses a question that `EFI_IFR_FLAG_READ_ONLY` makes read-only (UEFI 2.11 §33.3.8.2.2), as EDK2's keyword handler does, unless `--include read-only` names it, and always one that an `EFI_IFR_VALUE` makes read-only (§33.3.8.3.88), before it writes any question; the refusal names the states to include to write it or to select a question of the same text that it writes. Of questions with the same text, `get` and `set` pick a writable one first among matches equally certain to be selected. `get`, `hii get` and `hii list-questions` show read-only questions and refuse `--include read-only`.
* Each question that `get`, `set` and `hii list-questions` print lists the Flags of its question header that are set (UEFI 2.11 §33.3.8.2.2), such as `READ_ONLY` and `RESET_REQUIRED`, in `flags`.
* They also list, in `defaults`, each default that the IFR of the question declares (UEFI 2.11 §33.2.5.8), from an `EFI_IFR_DEFAULT`, the default flags of its options or the flags of a checkbox, with its value and the name of its default store. defaults lists the defaults the IFR declares, per DefaultId; it omits edk2-stable202608 GetQuestionDefault's fallbacks to another default store and to a per-type value.
* Change UEFI settings by calculating the correct offsets and writing to entries in `efivarfs`.
* Before the first write, `set` checks that it cannot crash Linux: Linux v5.8 (f88814cc2578; stable 5.7.11) to v6.7 without the upstream fix 0e8d2444168d crash on an efivarfs write when the firmware's `EFI_RT_PROPERTIES_TABLE` leaves out `SetVariable()`. It writes when `/proc/kallsyms` names `efivarfs_reconfigure`, the function of that fix, or, on x86_64 and on aarch64 from Linux v5.14, when the `set_variable` of Linux's `generic_ops`, which it reads through `/proc/kcore` (unless `lockdown=confidentiality`) at the address that `/proc/kallsyms` gives, is a `*_set_variable` function, and refuses when that `set_variable` is NULL. Where neither tells, it writes when the kernel log (`/dev/kmsg`, or `syslog(2)` under `printk.devkmsg=off`) names no such table that Linux applied, and else, on x86, x86_64 and aarch64, reads the table itself from `/dev/mem` as `capsule config-data` reads its table, unless the kernel lockdown mode refuses `/dev/mem`: it writes when the table lists `SetVariable()`, or the firmware lists no such table, and refuses when the table leaves it out. Otherwise it refuses, and `uefisettings.efi` in the UEFI Shell can change the setting.
* Questions read and set their EFI variable by its own attributes, as efivarfs gives them, since firmware may give a variable runtime access that its form does not declare. The attributes that the form (`VARSTORE_EFI`) declares explain only a variable that efivarfs does not list, or none read under `--no-efivars`.

### For HPE hardware

* Unlike OCP Hardware, HPE does not expose HiiDB in `efivarfs`.
* Instead they provide a way to change UEFI settings via iLO using the Redfish API.
* Redfish can be consumed over:
  * Standard networking protocols like TCP but this requires authentication credentials and network access to the BMC.
  * By accessing `/dev/hpilo` directly. This doesn't require authentication credentials. HPE doesn't provide any documentation for this approach but they provide an opensource [ilorest CLI tool](https://github.com/HewlettPackard?q=ilorest&type=all&language=&sort=) which calls a closed-source dynamically loaded shared object library called `ilorest_chif.so` which does the magic. The transport method used here instead of TCP is called Blobstore2.
* We are forbidden from disassembling *ilorest_chif.so* but we figured out most of its function signatures by looking at Apache2-licensed HPE's python ilorest CLI tool which calls it.
* Blobstore2 communication logic and rust bindings to `ilorest_chif.so` are implemented in the `ilorest` library. Feel free to use opensource implementation instead of `ilorest_chif.so` to avoid license problems.

The opensource ilorest study results are published in [`doc/ilorest.md`](doc/ilorest.md).

---

## Update Thrift files

The Rust crates in [`thrift/rust`](./thrift/rust/) are generated from the IDL files in [`thrift`](./thrift/). Only their `Cargo.toml` files are written by hand; do not edit the generated `src/` directories.

1. Edit `thrift/<name>.thrift`. A new IDL file also needs a crate manifest, `thrift/rust/<name>_thrift/Cargo.toml`, and a constant in `thrift/lib.rs`.
2. Run `thrift/regenerate.sh`. The first run builds the code generator, `thrift1`, from the pinned fbthrift commit and caches it. The header of the script lists the requirements; `UEFISETTINGS_THRIFT_JOBS` sets how many compiler processes run at a time (default: 1).
3. Commit the `.thrift` file together with the regenerated `thrift/rust/*/src`.

`thrift/regenerate.sh --check` fails if the generated code is out of date or if `thrift/rust` or one of its crate directories holds files that the script does not manage, other than the `Cargo.lock` and `target/` that Cargo creates.

## Checks

The `Makefile` in the root of the repository runs the checks that a change should pass: the lints (`make lint`: rustfmt, clippy for x86_64, aarch64, i686, UEFI, macOS and Windows, and the docs), the tests (`make test`, and `make test-i686` on 32-bit glibc) and the QEMU tests (`make test-e2e-qemu`).

The checks need GNU make and bash, and rustup unless `make RUST_TOOLCHAIN=` runs them on the cargo of `PATH`.

```sh
make setup           # once: installs, through rustup, the Rust toolchain, components and targets of the checks
make                 # every check, stopping at the first that fails
make -k              # every check, even after one fails
make <check>...      # the named checks, e.g. make clippy-aarch64 doc
make lint test test-i686 # every check but the QEMU tests
make RUST_TOOLCHAIN= # the checks on the cargo of PATH
make help            # lists the checks
```

`make test-i686` also needs an x86 host (x86_64 or i686), which runs the i686 test binaries, and gcc's 32-bit libraries (Ubuntu: `gcc-multilib`, or, next to the `gcc-aarch64-linux-gnu` of [`tests/qemu/ubuntu-packages`](tests/qemu/ubuntu-packages), which conflicts with it, `libc6-dev-i386` and `lib32gcc-<gcc version>-dev`; Fedora: `glibc-devel.i686`).

`make test-e2e-qemu`, the QEMU tests, also needs an x86_64 host with `/dev/kvm` and the packages that [`tests/qemu/README.md`](tests/qemu/README.md) lists.

On macOS, whose make 3.81 ignores the `Makefile`'s `.SHELLFLAGS`, `brew install make` installs GNU make as `gmake`: `gmake setup test` runs the unit tests.

GitHub Actions runs the checks, and the unit tests on arm64 and Intel Macs and on x86_64 Windows, on every pull request and every push to main, as [`.github/workflows/checks.yml`](.github/workflows/checks.yml) describes.

## QEMU tests

End-to-end tests boot QEMU guests and run `uefisettings` against emulated firmware; [`tests/qemu/README.md`](tests/qemu/README.md) explains how to run them.

## Appendix

<details>
<summary>Inspecting a machine's settings elsewhere</summary>

`hii dump-efivars` copies the EFI variables that the HiiDB's questions read, so that `hii get`,
`hii list-questions` and `hii show-ifr` can answer from them on another machine: each that
efivarfs lists, also one whose form declares it boot-service-only, while it reports the others
as missing. The dump also holds the HiiDB, as `hiidb.bin`, and records its format and
redaction in `uefisettings-dump.json`:

```sh
# on the machine to inspect
sudo uefisettings hii extract-db hiidb.bin
uefisettings hii dump-efivars -f hiidb.bin efivars
# on any machine, Linux or macOS
uefisettings hii list-questions --efivars efivars
```

`extract-db` reads the HiiDB from the EFI configuration table, failing that from the vendor ACPI
table `QHII` or `HIID`, and failing that through the OCP efivar and /dev/mem; all need root (the
table is root-only, /dev/mem needs CAP_SYS_RAWIO).
`dump-efivars -f` reads only efivarfs, whose files every user can read, so run it unprivileged:
as root, it would leave a directory that only root can read.

Without `-f`, `--efivars` reads the HiiDB that the dump saved. A directory without
`uefisettings-dump.json` holds plain efivar files, read with the HiiDB of `-f` or this machine.

The dump keeps the HiiDB whole, whose strings can name the machine (a MAC address, for one), and
of each EFI variable only the bytes that questions decode unless `--unredacted` is given; even those
can be secrets, so share it only with people you trust. A redacted dump also keeps, for variables
with EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS, the EFI_VARIABLE_AUTHENTICATION_3 metadata that
`get` accepts (time stamp or nonce, and certificate digest), which it needs to find their values.
It zeroes every other byte, so `--efivars` refuses it with another HiiDB (`-f`), whose questions
would read those zeros as values; a later uefisettings that decodes more reads them as values too.

On a case-insensitive file system, such as APFS unless formatted case-sensitive, `--efivars`
reads each efivar file by its exact name. Two files whose names differ only in case become one
there, which it cannot detect, so keep such a dump on a case-sensitive volume. HFS+, unlike APFS,
stores names decomposed (NFD), so there an efivar file whose name is not ASCII may not match.

Never copy a dump into /sys/firmware/efi/efivars: its files are in efivarfs's write format, so
they would create absent variables and overwrite writable ones, such as BootOrder and Timeout.

</details>

<details>
<summary>AMI Setup access level</summary>

AMI firmware's Setup grays out or hides some questions by the access level of its session, which
it keeps in the VarStore `SystemAccess` (E770BB69-BCB4-4D04-9E97-23FF9456FEAC: 0 Administrator,
1 User). Where Linux cannot read that variable, those questions are undetermined, and `set`
refuses them unless `--include` selects their states, such as `grayed-out`.
`--access-level administrator|user`, on `get`, `set`, `hii get`, `hii set` and
`hii list-questions`, evaluates those conditions at the stated level instead, and fails on a
HiiDB that declares no `SystemAccess`:

```sh
uefisettings hii list-questions --access-level administrator
```

`--access-level` changes no variable: the questions on `SystemAccess` itself still answer with its
stored value, or why it cannot be read.

uefisettings never takes, checks or circumvents a firmware password, because UEFI variable writes
carry none. With an Administrator password installed, `administrator` lets root select from the OS
the questions that the firmware's Setup reserves for Administrator sessions, as
`--include grayed-out` already does more broadly.

</details>

<details>
<summary>Questions with READ and WRITE expressions, and without a VarStore</summary>

A question can take its value through a READ expression and keep it through a WRITE expression
(UEFI 2.11 §33.2.5.4.1), which a setup browser evaluates in a FORM, or in a FORM_MAP with the
standard map method. `get`, `hii get`, `hii list-questions` and the conditions of other questions
take the value of the question's EFI_IFR_VALUE expression, if any, else of its READ expression, or
the stored value where it is UNDEFINED or malformed, as a browser does; where it uses an operator
or a value that uefisettings cannot evaluate, or reaches a question through more than 8 nested READ
expressions or back to itself, `get` says which. `set` sets THIS to the new value and evaluates the
WRITE expression before any write: the SETs of the expression, then the question's own value, which
wins where they overlap, go into one write per EFI variable, which keeps the bytes between them. It
writes nothing when a SET names a VarStore whose variable it may not write, such as one that does
not exist, or when the expression uses an operator that uefisettings does not evaluate, and names
the VarStore or the operator. GET and SET take VarOffset on VARSTORE and VARSTORE_EFI; a
VARSTORE_NAME_VALUE, which only its driver's EFI_HII_CONFIG_ACCESS_PROTOCOL reaches, is not read or
set.

A question without a VarStore (VarStoreId 0) has a value only through an EFI_IFR_VALUE, READ or
WRITE expression, or, with EFI_IFR_FLAG_CALLBACK, through its driver's
EFI_HII_CONFIG_ACCESS_PROTOCOL.CallBack() (UEFI 2.11 §33.2.5.6, §33.3.8.2.2). `get` shows, and
`set` refuses with, what it lacks:

| The question has | `get` | `set` |
|---|---|---|
| EFI_IFR_VALUE | the value of VALUE | refused: read-only (UEFI 2.11 §33.3.8.3.88) |
| READ and WRITE | the value of READ | through WRITE |
| READ only | the value of READ | refused: nothing keeps a changed value |
| WRITE only | refused: no value to retrieve | through WRITE |
| neither, nor EFI_IFR_FLAG_CALLBACK | refused: one of them is required | refused |
| EFI_IFR_FLAG_CALLBACK only | refused: its driver keeps the value | refused |
| EFI_IFR_FLAG_CALLBACK with READ (get) or WRITE (set) | refused: its driver's CallBack() may override the expression | refused |

`get` refuses too where READ gives no value, as no stored value takes its place, and `set` where
WRITE sets no VarStore. A browser lets the driver override READ with
CallBack(EFI_BROWSER_ACTION_RETRIEVE) and calls CallBack() around WRITE, so a question with
EFI_IFR_FLAG_CALLBACK is its driver's to answer. On Linux, Windows and macOS, which run after
ExitBootServices(), when no EFI device-handle-based protocol may be used (UEFI 2.11 §7.4.6), the
refusal points to `uefisettings.efi` in the UEFI Shell, which calls no CallBack() yet and refuses
it as well. `hii list-questions` and `hii show-ifr` never call CallBack(): they show such a
question with the refusal of `get`.

</details>

<details>
<summary>EFI variables</summary>

`variable list [--guid GUID]` prints the name and vendor GUID of every EFI variable as a JSON
array, sorted by name, then GUID, outside the thrift IDL of the other commands and with no `-j`;
`--guid` keeps those of one vendor. It reads no variable's data. On Linux it lists the files of
efivarfs, which shows each `/` of a name as `!` and holds the variables with runtime access only
(UEFI 2.10 §8.2.2), none of Linux's own random seed (from Linux 6.2 on): those that
GetNextVariableName() gave when efivarfs was mounted, up to the first name longer than 255
characters or given twice, and those written through it since. `uefisettings.efi` lists the
boot-service-only variables too. A name with a surrogate code unit, which the UCS-2 of CHAR16 does
not hold (UEFI 2.11 §2.3.1), lists with U+FFFD for each, under which `variable info` finds no
variable.

```sh
uefisettings variable list --guid 8BE4DF61-93CA-11D2-AA0D-00E098032B8C
```

`variable info NAME GUID` prints the attributes bitmask and the data size of an EFI variable, but
never its data, such as of AMI firmware's `AMITSESetup`, as a JSON object of its own, with no `-j`.
On Linux it reads the variable's efivar file and prints none of the data, as efivarfs sets the size
of the file only when it lists or writes the variable but reads the variable from the firmware at
each read; a variable without runtime access is missing there, and so is one that the firmware
dropped after efivarfs listed it. On Windows it reads all of the data through
GetFirmwareEnvironmentVariableExW, which tells the size no other way, and prints none of it.
`uefisettings.efi` keeps `hii variable-info` for it.

```plain
FS0:\> uefisettings.efi variable info AMITSESetup C811FA38-42C8-4579-A9BB-60E94EDDFB34
```

`variable get NAME [GUID]` prints a global variable of UEFI 2.11 §3.3, or the signature database db,
dbx, dbt, dbr (§32.7.1) or devdb (§32.7.2), decoded, as a JSON object of its own, with no `-j`:
`variable`, its efivar name, `attributes`, its bitmask, and `value`, or `"absent": true` if the
firmware has not created it. GUID, if given, must be the variable's own, which it defaults to:
`D719B2CB-3D3A-4596-A3BC-DAD00E67656F` for db, dbx, dbt and dbr,
`B9C2B4F4-BF5F-462D-8ADF-C5C70AC35DAD` for devdb, else `8BE4DF61-93CA-11D2-AA0D-00E098032B8C`.
`Timeout` is its seconds, or `"wait for user input"` for 0xFFFF; `BootOrder`, `DriverOrder` and
`SysPrepOrder` list their load options, such as `"Boot0001"`, and `BootNext` and `BootCurrent` name
one; `PlatformLang` and `PlatformLangCodes` are their text; `OsIndications` and
`OsIndicationsSupported` list their bits, as `BOOT_TO_FW_UI` for `EFI_OS_INDICATIONS_BOOT_TO_FW_UI`,
and each reserved bit in hex; `SecureBoot`, `SetupMode`, `AuditMode`, `DeployedMode`, `VendorKeys`,
`devAuthBoot` and `HwErrRecSupport` are their number; `BootOptionSupport` lists its flags and its
key press `count`; `SignatureSupport` and `OsRecoveryOrder` list their GUIDs; `PK`, `KEK`, the
signature databases and their `*Default` list their EFI_SIGNATURE_LISTs, each a `type` GUID and its
`signatures`, each an `owner` GUID and the `sha256` of its data. The load options, hot keys and
device paths of §3.3 are left to `variable info`.

```sh
uefisettings variable get SecureBoot
```

`variable set NAME VALUE` sets a global variable of UEFI 2.11 §3.3 that the OS may write and prints
what it wrote, as `variable get` prints it. VALUE is the value as `variable get` shows it, lists
comma-separated: `Timeout` takes seconds or `"wait for user input"`; `BootOrder`, `DriverOrder` and
`SysPrepOrder` take their load options, each of which must exist, none twice; `BootNext` takes one
`Boot####` that exists; `PlatformLang` takes one of the codes of `PlatformLangCodes`;
`OsIndications` takes bits of `OsIndicationsSupported`, such as `BOOT_TO_FW_UI`, or `none`, and
keeps its reserved bits. A missing variable is created with the attributes of UEFI 2.11 Table 3.1,
NV+BS+RT; an existing one keeps its own. It refuses, naming the spec's words, the variables that the
OS does not write, such as `SetupMode`, `SecureBoot` and the Secure Boot Policy Variables, which
take authenticated writes.

```sh
uefisettings variable set BootOrder Boot0002,Boot0001
```

`variable storage [--attributes ATTRIBUTES]` prints what QueryVariableInfo() (UEFI 2.10 §8.2.4)
tells of the storage of the variables of those attributes, by default the non-volatile ones that
the OS reaches (`non-volatile,bootservice-access,runtime-access`), as a JSON object of its own:
`maximum_variable_storage_size`, `remaining_variable_storage_size` and `maximum_variable_size`,
in bytes. On Linux it reads the statfs of efivarfs, which tells, from Linux 6.5 on, the storage
of those default attributes only, and no maximum variable size, which shows as `null`. Linux 6.5 to
6.5.4 fail that statfs, and with it `variable list` and `variable info` of a missing variable, where
the firmware's QueryVariableInfo() fails or is not supported at runtime (fixed by 79b83606abc7 in
6.5.5 and 6.6).

`variable write-signed NAME GUID --attributes ATTRIBUTES [--append] --payload-file FILE` writes
a payload that the caller signed, an EFI_VARIABLE_AUTHENTICATION_2 descriptor and then the
variable's new data (UEFI 2.11 §8.2.6), such as a db update, to an EFI variable unchanged, with those
attributes and EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS, and with `--append` also
EFI_VARIABLE_APPEND_WRITE. The firmware verifies the signature, which covers the name, the
vendor GUID, the attributes and the time stamp that the payload was made for. Before any write,
uefisettings refuses a payload without a complete descriptor, one without data unless `--append`
is given, and attributes without bootservice-access or runtime-access, either of which would
delete the variable, and, while SetupMode is 1, a Secure Boot policy variable (PK, KEK,
OsRecoveryOrder, OsRecovery####, and every variable of EFI_IMAGE_SECURITY_DATABASE_GUID, such as
db, dbx, dbt and dbr; §3.3), which the firmware writes then without checking the signature, or a
device signature database (every variable of EFI_DEVICE_SECURITY_DATABASE_GUID, such as devdb),
which the firmware may write then without checking the signature (§32.6.3), unless
`--allow-setup-mode-write-without-signature-check` is given. In User Mode, a KEK or PK signs db,
dbx, dbt and dbr (§32.5.3), and only PK signs devdb (§32.6.2, §32.6.3). edk2-stable202608 departs
from that for devdb: it verifies devdb as any other time-based authenticated variable, in Setup
Mode too, and then takes updates only from its first signer (SecurityPkg AuthVariableLib's
AuthVariableLibProcessVariable routes devdb to ProcessVariable, and AuthService.c's
VerifyTimeBasedPayload checks it in its AuthVarTypePriv branch).
It prints nothing when the firmware accepts the payload. On Linux it checks first, as `set`
does, that the write cannot crash Linux, then writes the variable's efivar file;
`uefisettings.efi` calls SetVariable() and names the status that it returns, such as
SECURITY_VIOLATION; on Windows it calls SetFirmwareEnvironmentVariableExW.

```plain
FS0:\> uefisettings.efi variable write-signed db D719B2CB-3D3A-4596-A3BC-DAD00E67656F --attributes non-volatile,bootservice-access,runtime-access --append --payload-file db-append.auth
```

`variable write-signed NAME GUID --attributes ATTRIBUTES [--append] --data-file FILE
--signing-key-file KEY --signing-certificate-file CERTIFICATES [--digest sha256|sha384|sha512]
[--timestamp TIME]` signs the new data in FILE itself: KEY, an unencrypted PEM RSA private key of
2048 to 4096 bits, signs the EFI_VARIABLE_AUTHENTICATION_2 of §8.2.6, a PKCS #7 SignedData without
signed attributes over SHA-256 or the `--digest`, which carries CERTIFICATES, a PEM bundle of KEY's
certificate and then any others, such as intermediate CAs, in the order of DER (X.690 §11.6).
uefisettings writes it, then the data, as above, and refuses the same writes before it signs.
The TimeStamp is TIME, a GMT time such as 2026-11-07T00:00:00Z, or else the current second of the
system clock; `uefisettings.efi` reads no clock, so it signs the all-zero TimeStamp of §8.2.6 for
`--append`, and needs `--timestamp` without it. RSA signs blinded, over a random source seeded
once from getrandom, or from EFI_RNG_PROTOCOL in the UEFI Shell, which refuses to sign without
it. rsa has no release that fixes RUSTSEC-2023-0071's timing leak; blinding is partial
hardening, and uefisettings runs as the advisory's workaround allows: local use on a
non-compromised computer. uefisettings reads KEY as a secret; KEY and CERTIFICATES hold at most
64 KiB each.

`--allow-setup-mode-write-without-signature-check` has either form write, while SetupMode is 1, a
Secure Boot policy variable, which the firmware writes then without checking the signature (§3.3,
§32.3), as to enroll KEK and then PK, or a device signature database, which the firmware may write
then without checking the signature (§32.6.3); the payload is still an
EFI_VARIABLE_AUTHENTICATION_2, and a write without data and without `--append` stays refused, as
edk2 deletes the variable then. Writing PK moves Setup Mode to User Mode, and Audit Mode to Deployed
Mode (§32.3.1, §32.3.4). PK may have to be signed with its own key (§32.3.1).

```sh
uefisettings variable write-signed db D719B2CB-3D3A-4596-A3BC-DAD00E67656F --attributes non-volatile,bootservice-access,runtime-access --append --data-file db.esl --signing-key-file kek.key --signing-certificate-file kek.pem
```

</details>

<details>
<summary>Capsules</summary>

`capsule deliver PAYLOAD --capsule-id ID` passes the file PAYLOAD to the firmware, unchanged, as
the JSON payload of a configuration capsule (UEFI 2.11 §23.5): an EFI_CAPSULE_HEADER whose
CapsuleGuid is EFI_JSON_CAPSULE_ID_GUID, an EFI_JSON_CAPSULE_HEADER whose CapsuleId is ID, then
the payload, which uefisettings neither parses nor checks against a schema; it refuses an empty
one, which the firmware "will not" process (§23.5.3). It prints a JSON object of its own, with no
`-j`: `capsule_size`, the bytes delivered, and what QueryCapsuleCapabilities() (§8.5.3.4) told of
the capsule, `maximum_capsule_size` and `reset_type`, an EFI_RESET_TYPE (§8.5.1.1: 0 cold, 1 warm, 2
shutdown, 3 platform-specific) that it returned for this capsule, or `null` where uefisettings does
not see them. A capsule that `uefisettings.efi` delivers has no CAPSULE_FLAGS_PERSIST_ACROSS_RESET,
so the firmware has processed it when UpdateCapsule() returns (§8.5.3.1), and its `reset_type`
states no reset requirement, which only a query with that flag determines (§8.5.3.4; edk2 answers
EfiResetCold for every such capsule). It never resets the machine.

`uefisettings.efi` asks QueryCapsuleCapabilities() first, then passes a capsule no larger than it
takes to UpdateCapsule(), for the firmware to process before that returns.

```plain
FS0:\> uefisettings.efi capsule deliver config.json --capsule-id 1
```

On Linux, `uefisettings` writes the capsule to `/dev/efi_capsule_loader`, which needs
CONFIG_EFI_CAPSULE_LOADER. That loader asks QueryCapsuleCapabilities() and calls UpdateCapsule()
itself, and tells its writer neither MaximumCapsuleSize nor ResetType: a refusal is the write's
errno (EINVAL for EFI_UNSUPPORTED, ENOSPC for EFI_OUT_OF_RESOURCES or a capsule over
MaximumCapsuleSize), and the reset type appears only in the kernel record of a successful upload, so
`maximum_capsule_size` and `reset_type` are `null`. As "firmware configuration and firmware update
are not available in EFI runtime" (§23.5.1), the capsule asks the firmware to process it after a
reset (CAPSULE_FLAGS_PERSIST_ACROSS_RESET), and Linux makes its next reboot the reset that the
firmware asked for.

`capsule config-data` prints the configuration data that the firmware reports in its JSON
configuration table, the EFI_JSON_CAPSULE_CONFIG_DATA of the configuration table of
EFI_JSON_CONFIG_DATA_TABLE_GUID (§4.6.1.2, §23.5.2), as a JSON object of its own, with no `-j`:
`items`, the ConfigData of each item in order, as `{"text": ...}` if it is UTF-8, else as
`{"hex": ...}`. It fails where the firmware lists no such table. On Linux it reads the table
from `/dev/mem`, as root, where the EFI System Table that Linux locates lists it (x86:
`/sys/kernel/boot_params/data` and `/sys/firmware/efi/config_table`; aarch64: the FDT of
`/sys/firmware/fdt`), and only inside one EFI runtime region of the firmware's memory map that is no
memory-mapped I/O (x86: `/sys/firmware/efi/runtime-map`; aarch64: the FDT's, from `/proc/kcore`),
once the kernel lockdown mode allows `/dev/mem`; it takes the table's address as virtual first, as
SetVirtualAddressMap() converts it (§4.6.1.2), then as physical. The firmware reports
cached configuration data unless OsIndications held JSON_CONFIG_DATA_REFRESH at boot, when it
collects the current data and clears that bit (§8.5.4):
`variable set OsIndications JSON_CONFIG_DATA_REFRESH` asks for current data at the next boot,
where OsIndicationsSupported lists that bit.

```plain
FS0:\> uefisettings.efi capsule config-data
```

`capsule results` prints the results of capsule processing that the firmware reports in EFI
variables of EFI_CAPSULE_REPORT_GUID (§8.5.6), as a JSON object of its own, with no `-j`:
`capsule_max` and `capsule_last`, the names that CapsuleMax and CapsuleLast hold, or `null` where
the firmware has no such variable, and `results`, each variable Capsule0000 to CapsuleFFFF that the
firmware wrote, in name order, as `{"name": ..., "result": ...}`. Each variable is decoded on its
own, so one that does not decode hides no other: it shows as `{"name": ..., "error": ..., "data":
{"hex": ...}}`, its data in hex, and a CapsuleMax or CapsuleLast that holds no name as `{"error":
..., "data": ...}`. A result holds the fields of its EFI_CAPSULE_RESULT_VARIABLE_HEADER:
`variable_total_size`, `capsule_guid`, `capsule_processed`, an EFI_TIME of `year`, `month`, `day`,
`hour`, `minute`, `second`, `nanosecond`, `time_zone` and `daylight`, and `capsule_status`, an
EFI_STATUS in hex, such as `"0x8000000000000002"`: its high bit is that of the firmware's UINTN,
and a JSON number that large loses its low bits where JSON numbers are doubles. The result of an
FMP capsule has `fmp` (§8.5.6.1.2): its `payload_index`, `update_image_index`,
`update_image_type_id`, `capsule_file_name` and `capsule_target`, each string empty where the
firmware wrote only its zero terminator. The result of a JSON capsule has `json` (§8.5.6.1.3): its
`capsule_id` and its `resp`, as `{"text": ...}` if it is UTF-8, else as `{"hex": ...}`; that of any
other CapsuleGuid, or of an FMP or JSON part of a Version but 1, has `data`, the bytes after the
header, as `{"hex": ...}`. The header's CapsuleStatus is a UINTN,
so its size depends on the firmware's width, which Linux tells in
`/sys/firmware/efi/fw_platform_size`; `uefisettings.efi` runs on firmware of its own width.
Windows lists no variables, so there `uefisettings` reads CapsuleMax and CapsuleLast, then each name
from Capsule0000 up to the greater of the two, one call each: with edk2's default CapsuleMax,
CapsuleFFFF, that is 65,538 calls. It spells the names in the case of the letter digits of
CapsuleMax, else of CapsuleLast, as names are case-sensitive, and without one it reads an absent
name with a letter digit in uppercase, then in lowercase. It takes the firmware's width to be its
own, which is wrong for a 32-bit build under WOW64 and for 64-bit Windows on 32-bit UEFI.

`capsule result-table` prints the result of processing a JSON capsule that the firmware reports in
the configuration table of EFI_JSON_CAPSULE_RESULT_TABLE_GUID (§4.6.1.2, §23.5.3), as `results`
prints one, and fails where the firmware lists no such table, as it does until it processes a JSON
capsule. It reads the table as `capsule config-data` reads its own.

```plain
FS0:\> uefisettings.efi capsule results
```

</details>

<details>
<summary>UEFI Shell details</summary>

A failing command returns EFI_ABORTED, which `%lasterror%` shows as 0x15 (0x80000015 on i686).

Questions never read a VarStore that a password question names: they show
`<ValueUnavailable: VarStore holds a password>`, and `set` refuses them. The UEFI Shell runs no
setup browser, so nothing there asks for or checks a setup password: in a HiiDB that declares a
password question, `set` writes nothing unless `--bypass-setup-password` is given.

`set` refuses a variable without EFI_VARIABLE_NON_VOLATILE unless `--allow-volatile` is given.
The UEFI Shell runs before ExitBootServices, when SetVariable() still sets volatile variables
(UEFI 2.11 §8.2.3), but the written value lasts only until the next reset or power cycle: when a
variable that `set` writes is volatile, as read before the write, its answer ends with
` <volatile: lasts until the next reset or power cycle>`. Linux and Windows write after
ExitBootServices, when SetVariable() sets no volatile variable (UEFI 2.11 §8.2.3), so they take
no `--allow-volatile`.

With Secure Boot enabled, the firmware starts an image only if its signature database (db) holds
the certificate of its signature or its hash, so sign `uefisettings.efi` with a key that the
machine's db trusts.

</details>
