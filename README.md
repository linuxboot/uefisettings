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
  get                Auto-identify backend and get the current value of a question
  help               Print this message or the help of the given subcommand(s)
  hii                Commands which work on machines exposing the UEFI HiiDB
  identify           Auto-identify backend and display hardware/bios-information
  ilo                Commands which work on machines having HPE's Ilo BMC
  set                Auto-identify backend and set/change the value of a question
  show-translations  Show the translation/spellings database for questions and answers
  variable           Commands on this machine's EFI variables, which never print their data
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
  list-strings    List all strings-id, string pairs in HiiDB
  set             Set/change the value of a question
  show-ifr        Show a human readable representation of the Hii Forms
```

`variable`:

```plain
Commands:
  help  Print this message or the help of the given subcommand(s)
  info  Show the attributes and the size of an EFI variable, never its data
  list  List the name and vendor GUID of every EFI variable, never its data
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

`uefisettings.efi` runs `get`, `set`, `show-translations`, the `variable` commands and the
`hii` commands but `extract-db` and `dump-efivars` in the UEFI Shell, before an OS boots; it
also reaches boot-service-only variables, and has no `-f` or `--efivars`.

```sh
rustup target add x86_64-unknown-uefi  # or i686-unknown-uefi, aarch64-unknown-uefi
cargo build --release --target x86_64-unknown-uefi
```

```plain
FS0:\> uefisettings.efi hii get --json "Activate this check box"
```

Exit statuses, setup passwords, `variable` and Secure Boot: see the [appendix](#appendix).

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
`variable list` fails there: the firmware environment calls reach a variable by its name only.

---

## On macOS

`cargo install uefisettings` builds on macOS too. That build reads nothing of the Mac's firmware
and writes nothing: `hii get`, `hii list-questions` and `hii show-ifr` read question values from
an efivars dump that `hii dump-efivars` wrote on Linux (`--efivars DIR`, with its HiiDB unless
`-f` names one) or from none (`--no-efivars`, with `-f`), and `hii list-strings` reads the HiiDB
file of `-f`. It has no `get`, `set`, `identify`, `ilo`, `variable`, `hii set`,
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
* `get`, `set` and `hii list-questions` evaluate the `suppressif`, `grayoutif` and `disableif` conditions of questions as EDK2's setup browser does, and select only questions that none of them suppresses, grays out or disables, unless `--include` names that state (`grayed-out`, `suppressed`, `disabled`); an answer ends with the state of a question that is not selectable. Where a condition cannot be evaluated from Linux, `set` refuses the question, while `get` and `hii list-questions` show it with the states it may be in and why. A one-of option in a `suppressif` counts as suppressed.
* Change UEFI settings by calculating the correct offsets and writing to entries in `efivarfs`.
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
can be secrets, so share it only with people you trust. A redacted dump zeroes every other byte,
so `--efivars` refuses it with another HiiDB (`-f`), whose questions would read those zeros as
values; a later uefisettings that decodes more reads them as values too.

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

</details>

<details>
<summary>UEFI Shell details</summary>

A failing command returns EFI_ABORTED, which `%lasterror%` shows as 0x15 (0x80000015 on i686).

Questions never read a VarStore that a password question names: they show
`<ValueUnavailable: VarStore holds a password>`, and `set` refuses them. The UEFI Shell runs no
setup browser, so nothing there asks for or checks a setup password: in a HiiDB that declares a
password question, `set` writes nothing unless `--bypass-setup-password` is given.

With Secure Boot enabled, the firmware starts an image only if its signature database (db) holds
the certificate of its signature or its hash, so sign `uefisettings.efi` with a key that the
machine's db trusts.

</details>
