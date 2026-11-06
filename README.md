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
  list-questions  List the one-of, numeric, checkbox, date, time, ordered-list and string
                  questions of the HiiDB, and its cross-reference questions on a VarStore, whose
                  values get reads; set does not write a cross-reference's value, the target of
                  its link
  list-strings    List all strings-id, string pairs in HiiDB, with each strings package's language
  set             Set/change the value of a question
  show-ifr        Show a human readable representation of the Hii Forms
```

Questions never read or write the bytes of a password question that uefisettings finds, in a
disabled form too: a question whose bytes overlap a password's shows `<ValueUnavailable: its bytes
hold a password>`, and `set` refuses it; the other questions of its VarStore read and write. Outside
the UEFI Shell, a password question in a FormSet that uefisettings ignores, as it ignores one with a
VarStore op in a form that a malformed op disables, can keep its password in a variable that the
FormSet declares, and one that edk2 parses into a FormSet whose
FORM_SET op opens no scope, past the End where uefisettings ends it, in one that the ops from that
op up to the next FORM_SET op declare, or in any variable of the GUID of such a VarStore whose
variable names it does not read, as those of a VARSTORE_EFI of the form before UEFI 2.3.1, which
its questions' VarNames name, so `get`, `set` and the redacted `dump-efivars` withhold every byte
of each of those, and, for a password question whose op ends before its
MaxSize, every byte of its variable from its offset on. A password question in IFR that
uefisettings ignores, or outside any FormSet, keeps its password at its offset in each variable of a
VarStore of its VarStoreId in its package list too, which edk2's Config Keyword Handler may take,
and a VarStore outside any FormSet that does not parse may hold a password in any variable of its
GUID, so they withhold those bytes too. A password question whose op ends before its question
header keeps its password where edk2 reads that header, in the bytes after the op: from its offset
on in each VarStore of its VarStoreId in its package list; one whose header runs past its form
package, or whose header past its op names VarStoreId 0, may name no VarStore, so they read and
write no variable of a HiiDB with one, nor do `hii list-questions` and `hii show-ifr` but with
`--no-efivars`. A VarStore in the scope of an unknown opcode, which edk2's Forms Browser skips but
its Config Keyword Handler takes, counts as one outside any FormSet, also for the password questions
of FormSets of its VarStoreId. IFR after an op that does not fit its form
package has no op boundary, so they read and write no variable of such a HiiDB, nor do
`hii list-questions` and `hii show-ifr` but with `--no-efivars`. A password question of a VarStoreId
that no VarStore of its form package that decodes declares names no VarStore (UEFI 2.11
§33.3.8.2.2 asks for "a previously declared variable store"), and edk2's Forms Browser finds none
for it but a VarStore op of its FormSet, outside an unknown opcode's scope, that does not decode,
whose fields it reads past the op's end, so they read and write no variable of a HiiDB with one,
nor do `hii list-questions` and
`hii show-ifr` but with `--no-efivars`; one whose FormSet declares no VarStore of its VarStoreId,
which another VarStore of its form package declares, keeps its password at its offset in the first
of those, which edk2's Config Keyword Handler takes, where `get` withholds it, and they warn of it.
A password question that edk2 may
route to a VARSTORE_NAME_VALUE, whose values its driver exposes, as UEFI 2.11 §33.2.5.6 says,
through EFI_HII_CONFIG_ACCESS_PROTOCOL, in storage of its own choosing, may keep its password in any
variable, so they read and write no variable of a HiiDB with one, as for IFR without an op boundary,
nor do `hii list-questions` and `hii show-ifr` but with `--no-efivars`. A password question of
VarStoreId 0 names no VarStore (UEFI 2.11 §33.3.8.2.2): with EFI_IFR_FLAG_CALLBACK its driver keeps
the password where it chooses (edk2-stable202608 SetupBrowserDxe/Setup.c:6468-6498,
Presentation.c:1695-1701); without it edk2 keeps it only where the SET ops of its WRITE say, or
nowhere (Setup.c:1997-2002, :2009-2056), which uefisettings does not follow, so it refuses alike, a
departure that fails closed: they read and write no variable of a HiiDB with one either, nor do
`hii list-questions` and `hii show-ifr` but with `--no-efivars`.
The UEFI Shell build reads and
writes no variable of a HiiDB with such a password question or with IFR that it ignores.

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
it also reaches boot-service-only variables and the Time Services, which date and time questions
of EFI Date/Time Storage read and write, and has no `-f` or `--efivars`. It reads the HiiDB
through the HII Database Protocol, and accepts `--hii-source` and `--efivar-memory` only to ignore
them.

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
when such a driver is installed, `hii extract-db` writes its HiiDB to a file. `--hii-source` and
`--efivar-memory` are accepted and ignored.
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
`hii extract-db` or `hii dump-efivars`; it accepts `--hii-source` and `--efivar-memory` and ignores
them. Dumps: see the [appendix](#appendix).

---

## Unsafe operations

`uefisettings` refuses each operation below unless `--i-am-fine-to-brick-this-system` is given,
which only the commands of the operations take; the refusal names it. The flag lifts only a
refusal whose only basis is `uefisettings`' judgement that the operation may harm the machine: (1)
an IFR restriction that binds writers outside the browser or declares the value invalid; (2)
fail-closed uncertainty about the write itself, never one whose lift would disclose a secret; (3)
weakened Secure Boot or setup-password protection; (4) irreversible actions; (5) reads of memory
that may be device memory. Condition states and the inputs of conditions are selection, which
`--include` and the input flags state; the flag never lifts routing, invalid operations or
confidentiality. A command runs every check that the flag does not lift first, except that `set`
and `hii set` on Linux with `--efivar-memory firmware-reserved` read the HiiDB, which their other
checks need, before those checks. A command prints a `warning:` line on stderr for each operation
that the flag let through, also when it then fails: `get` and the `hii` commands that read this
machine's HiiDB without writing (`get`, `show-ifr`, `list-strings`, `list-questions`,
`dump-efivars`, `extract-db`) print it right after the read, and any other error after the flag
let an operation through begins `after <n> unsafe operation(s) that
--i-am-fine-to-brick-this-system let through`. Its output on stdout, `--json` too, stays the same
otherwise.

| Operation | Commands | Build | Consequence |
|---|---|---|---|
| A write in a HiiDB that declares a setup password question | `set`, `hii set`, `hii keyword set` | UEFI Shell | No password is asked or checked, as the UEFI Shell runs no setup browser |
| A write of a question that `EFI_IFR_FLAG_READ_ONLY` makes read-only | `set`, `hii set` | Linux, UEFI Shell, Windows | A value changes that the firmware declares read-only; the Keyword Handler refuses it as "a violation of system policy" (UEFI 2.11 §35.3.2) |
| A signed write of a Secure Boot policy variable (PK, KEK, OsRecoveryOrder, OsRecovery####, any variable of EFI_IMAGE_SECURITY_DATABASE_GUID) while SetupMode is 1, cannot be read or holds other than a UINT8 of 0 or 1 | `variable write-signed` | Linux, UEFI Shell, Windows | The firmware writes it without checking the signature (UEFI 2.11 §3.3, §32.3) |
| A signed write of a device signature database (any variable of EFI_DEVICE_SECURITY_DATABASE_GUID) while SetupMode is 1, cannot be read or holds other than a UINT8 of 0 or 1 | `variable write-signed` | Linux, UEFI Shell, Windows | The firmware may write it without checking the signature (UEFI 2.11 §32.6.3) |
| Setting AuditMode to 1, which enters Audit Mode | `variable set` | UEFI Shell | "PK is cleared" and SetupMode becomes 1 (UEFI 2.11 §32.3.3), so the firmware writes Secure Boot policy variables without checking their signatures (§32.3) |
| Setting DeployedMode to 1, which enters Deployed Mode | `variable set` | UEFI Shell | Leaving Deployed Mode "requires a secure platform-specific method, or deleting the PK, which is authenticated" (UEFI 2.11 §32.3) |
| A read of the HiiDB with `--efivar-memory firmware-reserved` | `get`, `set` and every `hii` command that reads this machine's HiiDB | Linux | The read may reach device memory, whose reads can have side effects: of I/O memory, "Accidental access to this is obviously disastrous" (Linux 6.11 lib/Kconfig.debug:1911-1913), and EfiReservedMemoryType is "Not usable." (UEFI 2.11 §7.2 Table 7.6) |

`capsule deliver` takes no flag: its payload goes to the firmware's JSON configuration processor,
which UEFI 2.11 has check it against a schema and answer per capsule (§8.5.6.1.3), unlike
SetVariable(), which stores bytes with "no read, write, or delete security protection" (§8.2.3).

`get` of a question whose value only its driver keeps takes no flag either: it restores any store
that its RETRIEVE Callback() changed, which undoes only the driver's own change, and its
ExtractConfig() reads of the FormSet's Buffer and Name/Value stores reach the driver without the
flag too (see the UEFI Shell details).

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

* Extract HiiDB. Linux exposes no file that holds it, and `/sys/firmware/efi/systab` does not list its address, so `uefisettings` reads it in one of three ways, which `--hii-source` names; by default (`--hii-source auto`) it tries them in this order:
  * `acpi`: if the firmware publishes a copy of the HiiDB as the vendor ACPI table `QHII` or `HIID`, `uefisettings` reads it from `/sys/firmware/acpi/tables/QHII`, else from `/sys/firmware/acpi/tables/HIID` (skip the 36-byte ACPI header), without `/dev/mem`, moving on past tables that are absent or fail their checks. This is the way that needs no `/dev/mem`, so it reads under kernel lockdown too.
  * `efivar`, the OCP way: read the physical address and length from the `HiiDB-1b838190-4625-4ead-abc9-cd5e6af18fe0` efivar and then read that memory from `/dev/mem`, only from an EFI runtime region of the firmware's memory map (with `--efivar-memory firmware-reserved` and `--i-am-fine-to-brick-this-system`, from one firmware-reserved region of it instead: Reserved or ACPI Non-volatile Storage on x86, reserved, runtime services, ACPI NVS or PAL code memory on aarch64, never one that touches runtime memory-mapped I/O; see [Unsafe operations](#unsafe-operations)), and only once the kernel lockdown mode, which needs securityfs mounted, allows `/dev/mem`.
  * `systab`, on x86, x86_64 and aarch64: read the HII database export that the firmware lists as the EFI configuration table of `EFI_HII_DATABASE_PROTOCOL_GUID` (UEFI 2.11 §33.2.11.1), as EDK2 does where `PcdHiiOsRuntimeSupport` is TRUE, from `/dev/mem`, as `capsule config-data` reads its table: the package lists from the buffer's start up to a package list header of zeros, which EDK2 leaves after them, refusing fewer zero bytes than a header before other bytes, which EDK2's export into its old buffer can leave, or up to the end of the buffer's EFI runtime region, each whole inside that region and ending with an EFI_HII_PACKAGE_END package exactly at its PackageLength (UEFI 2.11 §33.3.1.1), which the other ways do not require, at most 16 MiB in all. It takes the table's address as physical first, then as virtual. It does not support Xen: on aarch64, where `/chosen` has no `linux,uefi-system-table` and `/hypervisor/uefi` holds Xen's `xen,uefi-system-table`, it fails. On x86 it reads only where Linux exports /sys/firmware/efi/runtime-map (CONFIG_EFI_RUNTIME_MAP, which CONFIG_EFI selects with CONFIG_KEXEC_CORE: Linux v6.11 arch/x86/Kconfig:2001, :2054), which bounds its reads.
    The configuration that the firmware exports with HII ExportConfig() and lists as the EFI configuration table of `EFI_HII_CONFIG_ROUTING_PROTOCOL_GUID` (UEFI 2.11 §33.2.11.1) is read the same way: its text up to its first NUL CHAR16, inside the buffer's EFI runtime region.

  `auto` moves on while a way finds its source absent (no vendor ACPI table file, no `HiiDB` variable, no EFI System Table that Linux locates, as on a BIOS boot or an aarch64 boot without UEFI, or no such configuration table) or fails otherwise, such as a table that fails its checks or a missing memory map, and stops at a refusal: kernel lockdown, the kernel refusing `/dev/mem` or `/proc/kcore` (no `CAP_SYS_RAWIO`, `CONFIG_STRICT_DEVMEM`), a file that the user may not read, or an unsafe operation without `--i-am-fine-to-brick-this-system`. Its error names each way that it tried, in order, with why, absent apart from refused; with `RUST_LOG=warn`, `uefisettings` logs each way that failed before the one that gave the HiiDB, and with `RUST_LOG=debug` also that way. A named way is the only one tried. `identify` checks the same ways for the HII backend: it finds none where each way finds its source absent, and assumes it, with a warning that `RUST_LOG=warn` shows, where a way's check fails or is refused, such as under kernel lockdown or without `CAP_SYS_RAWIO`. `--hii-source` and `--efivar-memory` may also follow the command; the UEFI Shell, Windows and macOS builds accept both and ignore them.
* Library (`hii`) in Rust partially implements the UEFI Hii specification.
* It parses the HiiDB op-codes into a DOM tree like representation which can be read by machines and humans.
* It can ask questions about UEFI settings from HiiDB and get their answers.
* The texts of a HiiDB and of EFI variables, such as prompts, helps and option texts, can hold characters that a terminal takes as commands, as a reordering of the text after them or as line breaks. The text output shows each control character (Unicode Cc), Bidi_Control character, U+2028 and U+2029 escaped as Rust's `char::escape_debug` spells it, such as `\u{1b}`, `\r` and `\u{202e}`, and `\` as `\\`, so that no text shows as another's escape; `hii show-ifr` shows a text's own line break as `\n` inside its line. A console that shows a character as another, such as edk2's VT100 terminal showing U+2510 as `\`, can still make a text look like an escape. `--json` keeps each text exact, and spells U+007F to U+009F, Bidi_Control characters, U+2028 and U+2029 as JSON `\u` escapes, which JSON parsers read back as those characters. `set` and `hii set` match VALUE and `--item` against the raw texts only, whether a prompt, a QuestionId or a keyword selects the question: a shown text that holds an escape matches only an option whose raw text is that text. The UEFI Shell build also escapes each character that `EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL.TestString()` of the console it prints to refuses, as `\u{10d}` in text and as a JSON escape in a JSON string, as edk2's VT100 and PC-ANSI terminals would write such a character's low byte, such as CR for U+010D; it fails rather than print where that call fails. Every build escapes U+FFF0 and U+FFF1, which edk2's GraphicsConsole takes as a lasting change of the width of the characters after them, as `\u{fff0}` and `\u{fff1}` in text and as JSON escapes.
* `get`, `set` and `hii list-questions` evaluate the `suppressif`, `grayoutif` and `disableif` conditions of questions as EDK2's setup browser does, and select only questions that none of them suppresses, grays out or disables, unless `--include` names that state (`grayed-out`, `suppressed`, `disabled`); an answer ends with the state of a question that is not selectable. Where a condition cannot be evaluated from Linux, `set` refuses the question, while `get` and `hii list-questions` show it with the states it may be in and why. A one-of option in a `suppressif` counts as suppressed, and a question that a `locked` (`EFI_IFR_LOCKED`) locks as grayed out. UEFI 2.11 §33.3.8.3.37 addresses LOCKED to Forms Editors; uefisettings follows edk2-stable202608 SetupBrowserDxe, which grays out a locked statement and every statement of a locked form (Presentation.c InitializeDisplayStatement, IfrParse.c ParseOpCodes).
* `set` refuses a question that `EFI_IFR_FLAG_READ_ONLY` makes read-only (UEFI 2.11 §33.3.8.2.2), as EDK2's keyword handler does, unless `--i-am-fine-to-brick-this-system` is given (see [Unsafe operations](#unsafe-operations)), and always one that an `EFI_IFR_VALUE` makes read-only (§33.3.8.3.88), before it writes any question; the refusal names the states to include to select a question of the same text that `set` writes, if any: a writable one, and, with that flag, one that `EFI_IFR_FLAG_READ_ONLY` makes read-only. Of questions with the same text, `get` and `set` pick a writable one first among matches equally certain to be selected. `get`, `hii get` and `hii list-questions` show read-only questions.
* Where efivarfs lacks the variable of a question, as the firmware has not created it or gives it no runtime access, `get`, `hii list-questions` and `hii show-ifr` take its value from the current configuration that edk2 firmware exports with `ExportConfig()` at ReadyToBoot when built with `PcdHiiOsRuntimeSupport`, its default (UEFI 2.11 §33.2.11.1); so do the questions of name/value storage, which no EFI variable holds. uefisettings reads that snapshot on x86, x86_64 and arm64 from `/dev/mem`, as it reads the HiiDB that the configuration table lists. A value from it ends with ` <snapshot>`, as does the option of a ONE_OF that such a value in the EFI_IFR_VALUE of an option of Type OTHER decides, and so does the state that a condition decides from such a value, even selectable (` <selectable> <snapshot>`); `get` refuses a question that such a state excludes, naming the snapshot. `set` never reads the snapshot: it refuses those questions as without it. No snapshot is read with `--efivars` or `--no-efivars`, where the firmware lists none, or where `/dev/mem` cannot be read (without root, or under a kernel lockdown). The bytes of PASSWORD questions are dropped from it, so a question over them shows withheld, and a PASSWORD question whose VarStore is unknown, or IFR that uefisettings ignores, which may hold one, keeps the whole snapshot off, as uefisettings could not withhold the bytes of that password.
* Each question that `get`, `set` and `hii list-questions` print lists the Flags of its question header that are set (UEFI 2.11 §33.3.8.2.2), such as `READ_ONLY` and `RESET_REQUIRED`, in `flags`. A question of a FormSet whose ClassGuids hold `EFI_HII_REST_STYLE_FORMSET_GUID` lists `REST_STYLE`, which its Flags can then omit.
* They also list, in `defaults`, each default that the IFR of the question declares (UEFI 2.11 §33.2.5.8), from an `EFI_IFR_DEFAULT`, the default flags of its options or the flags of a checkbox, with its value and the name of its default store. defaults lists the defaults the IFR declares, per DefaultId; it omits edk2-stable202608 GetQuestionDefault's fallbacks to another default store and to a per-type value.
* And `question_id`, the QuestionId of the question header, 1 to 65535; `form_set_guid`, the GUID of the question's FormSet; and in `keywords`, its prompt in each strings package of a configuration language (one whose language starts with `x-`, UEFI 2.11 §33.2.6.1), with that language as `namespace_id`: its keyword strings (UEFI 2.11 §35.2.1.6), those that a `<KeywordRequest>` can name: whose language is a `<NameSpaceId>`, and whose prompt a `<Keyword>`, text without `&`, `=` or control characters with at most one `:`, which only 1 to 4 digits may follow. The Ilo backend sets none of `flags`, `defaults`, `question_id`, `form_set_guid` and `keywords`, so its text output shows them as `None`.
* A form that holds an op shorter than the minimum length of its opcode or than the length that its Flags, Type or ListLength require, which UEFI 2.11 §33.2.5.10.1 calls malformed, or an op that uefisettings does not decode, is disabled: none of its questions is read or set, and the other forms of its FormSet are. A FormSet whose IFR does not parse, which holds such an op outside its forms, or whose scopes nest too deep, is ignored, the first FormSet of a form package too, as UEFI 2.11 §33.2.5.10.1 ignores a malformed forms set, and the FormSets after it are read, as edk2-stable202608 SetupBrowserDxe GetIfrBinaryData finds them. `get` and `set` list the IFR that uefisettings ignores, disabled forms too, which may hold more questions, in `ignored_ifr`: its package list, its offset in the form package and why; `hii show-ifr` prints each disabled form. `set` names it when no question has the text, its first 16 records and the count of the rest, and `hii list-questions`, whose output stays a list of questions, prints it on stderr.
* Change UEFI settings by calculating the correct offsets and writing to entries in `efivarfs`.
* `set` writes each EFI variable of the questions that match once, with the changes of all of them, in one SetVariable(), which saves all of the data of a non-volatile variable or none (UEFI 2.11 §8.2.3), in the order in which the questions first change each variable. It stops at the first write that fails, and its error names the writes done, the one that failed and those not attempted, each by the package lists of its questions and its EFI variable. Through `efivarfs` it refuses, before any write, two variables whose names differ only in `/` and `!`, which `efivarfs` keeps in one file.
* `set` takes the value of a numeric question in decimal, or in hexadecimal after `0x` or `0X`, whatever the question displays (UEFI 2.11 §33.3.8.3.47: "Input is still allowed in any form"); `get` shows it in decimal. On a question that displays signed decimals, the hexadecimal digits are the stored bits, so `0xFF` sets an 8-bit one to -1, and a sign or more digits than its bits hold are refused. A checkbox takes 0 or 1.
* `get` shows the value of a date question as `YYYY-MM-DD` and of a time question as `HH:MM:SS` (UEFI 2.11 §33.2.5.4.6, §33.2.5.4.11), with dashes in each field that the question suppresses, which a browser neither displays nor updates. `set` takes the same text: it refuses digits in a suppressed field, whose stored value it keeps, except a day that the new month or year lacks, which becomes the month's last day after a month change, else 1, as EDK2's setup browser adjusts it (edk2-stable202608 DisplayEngineDxe/InputHandler.c AdjustQuestionValue). It checks each other field against the ranges of EDK2's setup browser: month 1 to 12, the days of the month (February 29 in a leap year only), year 1 to 65535, hour up to 23, minute and second up to 59. In conditions, as in EDK2's setup browser, a date or time compares with another as its bytes, and with a number not at all; arithmetic takes its bytes as a number.
* A date or time question whose UEFI Storage is the system time or the wake-up time, its EFI Date/Time Storage (UEFI 2.11 §33.2.5.6), keeps its value there, in addition to its VarStore, if any. In the UEFI Shell, `get` shows the fields of GetTime()'s or GetWakeupTime()'s time, or the status of the service that fails, and `set` reads that time first, changes the question's fields, keeps the others, the TimeZone and Daylight too, and writes it back with SetTime() or SetWakeupTime(TRUE, …), then writes the question's VarStore, if any; where that write fails, the error names the time written. `set` of a wake-up time thus arms the alarm, which "causes the system to wake up or power on at the set time" (UEFI 2.11 §8.3.4), as EDK2's setup browser does (edk2-stable202608 SetupBrowserDxe/Setup.c:2051). Before any write, `set` refuses a time outside the ranges of UEFI 2.11 §8.3.1, such as a year before 1900. A GET or SET of a date or time without a VarStore, which conditions and WRITE expressions may hold, reads or writes a field of GetTime()'s time, as EDK2's setup browser does. On Linux, Windows and macOS, which reach no Time Services, `get` shows `<ValueUnavailable: EFI Date/Time Storage (UEFI 2.11 §33.2.5.6) is read only through GetTime(); run uefisettings.efi in the UEFI Shell>` (GetWakeupTime() for a wake-up time), also where the ExportConfig snapshot holds the bytes of its VarStore, as that snapshot holds no EFI_TIME, and `set` refuses the question, with every other question that it selects, before any write.
* An ordered-list question (UEFI 2.11 §33.2.5.4.8, §33.3.8.3.53) holds its items in up to MaxContainers containers, each as wide as the Type of its first option, as EDK2's setup browser sizes them (edk2-stable202608 SetupBrowserDxe/IfrParse.c), and a container of 0 ends them. `get` and `hii list-questions` show the texts of the options of its items in order, joined by `, `, each with the state of its option, such as `USB <option suppressed>`, and `--json` lists them without states as `items`; without a value they show its default, whose missing containers are empty. An option flagged as a default gives that default instead of an option, as in EDK2's setup browser. `set` takes the items with `--item TEXT`, once per container, in order, instead of VALUE, and writes the rest of the containers empty. Before any write, it refuses more items than MaxContainers, fewer under `EFI_IFR_NO_EMPTY_SET`, an option twice under `EFI_IFR_UNIQUE_SET`, an item whose option conditions hide unless `--include` selects its state, and a list that drops a stored item whose option conditions hide: `--include suppressed` with that item keeps it.
* A cross-reference question (UEFI 2.11 §33.2.5.4.10, §33.3.8.3.59) on a VarStore holds an `EFI_HII_REF`, which `get` and `hii list-questions` show as `QuestionId 0x0005, FormId 0x0001, FormSetGuid 8C78A505-BAA0-4C4A-869F-000000000502, DevicePath "PciRoot(0x0)/Pci(0x1,0x0)"`: the DevicePath as the text of its string in the language of the other texts, `DevicePath none` for string 0, which links within the device path of the question's form set, or `DevicePath string 0x0063 not found` for a string without a text in that language or a display language; without a value they show its default of Type `EFI_IFR_TYPE_REF`. Any of `EFI_IFR_REF` to `EFI_IFR_REF5` holds one on a VarStore, as in EDK2's setup browser (edk2-stable202608 SetupBrowserDxe/IfrParse.c), though the spec gives storage to `EFI_IFR_REF5` only. The value is the target of the question's link, not a setting, so `set` refuses it before any write: `cannot set question "…": set does not write the EFI_HII_REF of a cross-reference question, the target of its link (UEFI 2.11 §33.2.5.4.10)`. A cross-reference question without a VarStore is a link with no value, which is not listed.
* A string question (UEFI 2.11 §33.2.5.4.9, §33.3.8.3.70) holds MaxSize CHAR16s of UCS-2 (UEFI 2.11 §33.2.6), as EDK2's setup browser sizes them (edk2-stable202608 SetupBrowserDxe/IfrParse.c:2225). `get` and `hii list-questions` show its characters up to the first NULL, all MaxSize of them without one, and refuse a UTF-16 surrogate, which UCS-2 has no character for; without a value they show its default, the text of its string in the language of the other texts, cut to MaxSize characters, or `unknown (…)` for a string that the package list lacks or that holds a character beyond UCS-2: the string of an `EFI_IFR_DEFAULT`, else of a flagged `EFI_IFR_ONE_OF_OPTION` of Type `EFI_IFR_TYPE_STRING` that no `EFI_IFR_SUPPRESS_IF` hides, as EFI_IFR_STRING (UEFI 2.11 §33.3.8.3.70) orders them; EDK2's setup browser takes them from the ALTCFG defaults that HiiDatabaseDxe/ConfigRouting.c builds (:3218-3235) for storage other than a VARSTORE_EFI before UEFI 2.3.1 (EFI_HII_VARSTORE_EFI_VARIABLE, edk2-stable202608 SetupBrowserDxe/Setup.h:104, IfrParse.c:1901-1910), in a form set with EFI_HII_CONFIG_ACCESS_PROTOCOL (Setup.c:4449), and skips them for that storage (Setup.c:4140); its fallback takes the options of one-of questions alone (Setup.c:4525). `set` writes at most MaxSize − 1 characters of VALUE, NULL-padded to MaxSize CHAR16s, so that a NULL ends them: UEFI 2.11 §33.2.5.4.9 says "the buffer size must exceed the size of the NULL-terminated string". EDK2's setup browser takes MaxSize characters (edk2-stable202608 DisplayEngineDxe/InputHandler.c:260), which its Library/UefiHiiLib/HiiLib.c:1833 then reads past, so that DriverSampleDxe/DriverSample.c:2012-2022 unloads the driver, and on which MdePkg BaseLib/SafeString.c:256-259 StrCpyS fails. Before any write, `set` refuses more characters than that, fewer than MinSize, as EDK2's setup browser does, every VALUE of a string question of MaxSize 0 or of a MinSize above MaxSize − 1, a NULL, a character beyond UCS-2, a character of the Private Use Area U+E000..U+F8FF, of which UEFI 2.11 §33.2.6.2.1 says "UEFI prohibits use of this area in a UEFI environment.", other than the Common Control Codes U+F620..U+F62B and U+F700..U+F8FF, font display hints that UEFI 2.11 §33.2.6.2.4 Table 33.3 allows within strings, and a Mandatory Break of UEFI 2.11 §33.2.6.2.5 Table 33.4 (U+000A, U+000C, U+000D, U+2028 or U+2029) without the flag `EFI_IFR_STRING_MULTI_LINE` of EFI_IFR_STRING (UEFI 2.11 §33.3.8.3.70), which says "If it is clear, then multi-line editing should not be allowed." EDK2's setup browser ignores that flag, ends input at a carriage return and stores any other character typed, a line feed and the Private Use Area too (InputHandler.c:208, :256-262). A string question of name/value storage takes its characters from its setting in the `ExportConfig()` snapshot, 4 hex digits each, most significant first, as EDK2's setup browser reads them (edk2-stable202608 SetupBrowserDxe/Setup.c:1564-1579): up to a NULL, as UEFI 2.11 §33.2.5.4.9 ends the hex dump, or MaxSize characters, as Setup.c writes them without one (:2139-2148); an empty setting is an empty string. A setting whose digits are no `<String>` (UEFI 2.11 §35.2.1.2), whose last CHAR16 Setup.c would take from fewer than 4 digits (:1571-1573), or that holds characters other than NULL past MaxSize, which Setup.c would cut (:1557-1561), gives no value.
* `set` gives one value to every question that it selects, so where it selects questions of more than one kind, such as a numeric question and a date, it refuses them all before any write, naming each kind and the package lists of its questions.
* Before the first write, `set` checks that it cannot crash Linux: Linux v5.8 (f88814cc2578; stable 5.7.11) to v6.7 without the upstream fix 0e8d2444168d crash on an efivarfs write when the firmware's `EFI_RT_PROPERTIES_TABLE` leaves out `SetVariable()`. It writes when `/proc/kallsyms` names `efivarfs_reconfigure`, the function of that fix, or, on x86_64 and on aarch64 from Linux v5.14, when the `set_variable` of Linux's `generic_ops`, which it reads through `/proc/kcore` (unless `lockdown=confidentiality`) at the address that `/proc/kallsyms` gives, is a `*_set_variable` function, and refuses when that `set_variable` is NULL. Where neither tells, it writes when the kernel log (`/dev/kmsg`, or `syslog(2)` under `printk.devkmsg=off`) names no such table that Linux applied, and else, on x86, x86_64 and aarch64, reads the table itself from `/dev/mem` as `capsule config-data` reads its table, unless the kernel lockdown mode refuses `/dev/mem`: it writes when the table lists `SetVariable()`, or the firmware lists no such table, and refuses when the table leaves it out. Otherwise it refuses, and `uefisettings.efi` in the UEFI Shell can change the setting.
* Questions read and set their EFI variable by its own attributes, as efivarfs gives them, since firmware may give a variable runtime access that its form does not declare. The attributes that the form (`VARSTORE_EFI`) declares explain only a variable that efivarfs does not list, or none read under `--no-efivars`.
* A question on a `VARSTORE_EFI` of the form before UEFI 2.3.1, an op shorter than `EFI_IFR_VARSTORE_EFI` without its Size and Name, keeps its value alone in the EFI variable of the store's GUID that its VarName names, from byte 0, as edk2-stable202608 SetupBrowserDxe reads and writes it (Setup.c:1764-1782, :2061-2077), though UEFI 2.11 defines only the form with Size and Name (§33.3.8.3.91): a numeric, one-of, checkbox, date or time question, an ordered-list question, and a cross-reference question, whose `EFI_HII_REF` `set` refuses as on any VarStore. Such a variable holds the StorageWidth that edk2-stable202608 SetupBrowserDxe/IfrParse.c gives the question, and `get` and `set` refuse a variable of another size. For a cross-reference question UEFI 2.11 §33.2.5.4.10 requires exactly the size of `EFI_HII_REF`; for the ordered-list and the other questions this departs from edk2, which reads the bytes of a smaller one and ignores the `EFI_BUFFER_TOO_SMALL` of a larger one (Setup.c:1772-1782; UEFI 2.11 §8.2.1). `get` and `set` also refuse an ordered-list question without options, to which edk2 gives no StorageWidth, and refuse a question before its store, as "An EFI_IFR_VARSTORE_EFI with a specified VarStoreId must appear in the IFR before it can be referenced by a question" (§33.3.8.3.91). Where the variable is missing, `get` shows it missing, and `set` creates it with the store's Attributes, that of an ordered-list question with the new items and the rest of its containers empty, as edk2 writes the zeroed value that it keeps (IfrParse.c:2493; Setup.c:1779-1782, :5725-5727, :2069-2075); it creates none at OS runtime without `EFI_VARIABLE_RUNTIME_ACCESS`, nor on Windows.

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

`extract-db` reads the HiiDB as `--hii-source` says, by default from the vendor ACPI table `QHII`
or `HIID` or, failing that, from /dev/mem; each needs root (the table is root-only, /dev/mem needs
CAP_SYS_RAWIO).
`dump-efivars -f` reads only efivarfs, whose files every user can read, so run it unprivileged:
as root, it would leave a directory that only root can read.

Without `-f`, `--efivars` reads the HiiDB that the dump saved. A directory without
`uefisettings-dump.json` holds plain efivar files, read with the HiiDB of `-f` or this machine.

The dump keeps the HiiDB whole, whose strings can name the machine (a MAC address, for one), and
of each EFI variable only the bytes that questions decode unless `--unredacted` is given; even those
can be secrets, the free text of string questions among them, so share it only with people you
trust. A redacted dump also keeps, for variables with EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS,
the EFI_VARIABLE_AUTHENTICATION_3 metadata that `get` accepts (time stamp or nonce, and certificate
digest), which it needs to find their values. It zeroes every other byte, so `--efivars` refuses it
with another HiiDB (`-f`), whose questions would read those zeros as values; a later uefisettings
that decodes more reads them as values too.

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
<summary>Languages of prompts, help and option texts</summary>

A package list holds a strings package per language (UEFI 2.11 §33.2.6). uefisettings shows each
package list's texts in the platform language, the EFI variable `PlatformLang`: from the strings
package that edk2's `GetBestLanguage` picks for it (the language, then the language cut at each
`-`, ignoring ASCII case), else from the first package whose language does not start with `x-`.
Languages that start with `x-` are configuration languages (§33.2.6.1), whose strings are keywords,
not texts; uefisettings takes `X-` as `x-`, as it compares languages ignoring ASCII case. A string
that the chosen package lacks comes from another package of a display language, and one that only
`x-` packages hold shows as `""`.

`PlatformLang` falls back in three cases:

- An absent or malformed `PlatformLang` picks no package: uefisettings warns, and texts come from
  the first package of a display language.
- A `PlatformLang` outside `PlatformLangCodes` picks its package as any other does, as edk2's
  `HiiGetString` takes it. On a running machine the firmware replaces an unsupported value at
  initialization (UEFI 2.11 §3.3), so only an `--efivars DIR` dump can carry one.
- A `PlatformLang` that starts with `x-` shows the keywords as names, as `--language x-UEFI-ns`
  does.

`--language TAG`, on `get`, `set`, `hii get`, `hii set`, `hii list-questions` and `hii show-ifr`,
shows the texts in TAG instead, else in `PlatformLang`; `--language x-UEFI-ns` shows the keywords. `--efivars DIR` takes `PlatformLang` from the
dump, except on macOS, which reads none; `--no-efivars` takes none.

QUESTION and VALUE still match the texts of every display language. `get` and `set` select by
QUESTION only when one language holds it as the prompt of every question it names, and a ONE_OF
VALUE names an option only when one language holds it as the text of every option it names;
otherwise they refuse, naming each match, and write nothing.

Texts used to come from the first strings package that held each string, in any language. Since
they follow `PlatformLang`, the name of a question changes where an `x-` package, or a package of
another language, precedes the chosen one; scripts that parse names should pin the language:

```sh
uefisettings hii list-questions --language en-US --json
```

</details>

<details>
<summary>Selecting a question by QuestionId or keyword</summary>

`get`, `set`, `hii get` and `hii set` select by one of QUESTION, `--question-id` and `--keyword`;
the Ilo backend selects only by QUESTION.

`--question-id GUID:ID` selects the question of QuestionId ID (UEFI 2.11 §33.3.8.2.2) in the
FormSet of GUID, in every package list that holds that FormSet. ID is decimal or 0x hex, 1 to
0xFFFF, as `hii list-questions --json` shows `form_set_guid` and `question_id`. It selects
questions whose prompt is empty or shared with others.

`--keyword KEYWORD` selects the questions of the statements that KEYWORD names as edk2's Keyword
Handler finds them without PATH (edk2-stable202608 ConfigKeywordHandler.c), in the strings
packages whose language starts with `x-UEFI` (its UEFI_CONFIG_LANG, where §35.3.3 says `x-UEFI-`),
or with LANGUAGE under `--keyword-namespace LANGUAGE`: in each package list, the first such
strings package (GetStringIdFromRecord), there the lowest string ID whose text is KEYWORD, exactly
and with its case (GetStringIdFromString), and the statement that this string prompts
(FindQuestionFromStringId). KEYWORD is the KEYWORD of a keyword string (§35.2.1.6), a `<Keyword>`
with any instance suffix, such as `ChipsetSATAPortEnable:5`, the spec's example of a setting with
several instances, and `hii list-questions --json` shows each question's in `keywords`.
uefisettings reads the keywords from the HiiDB, as it reads prompts; it does not call
`EFI_CONFIG_KEYWORD_HANDLER_PROTOCOL`, and it selects in a package list without a device path too,
which no `<KeywordResp>` could name. LANGUAGE must be a `<NameSpaceId>` that is a configuration
language, one that starts with `x-`, as NamespaceId is "the platform configuration language to
search through" (§35.3.3), so that KEYWORD never matches a prompt of a display language.

`get` and `set` refuse a KEYWORD that another strings package of the namespace in its package list
holds too, or that prompts more than one statement of its list, which firmware may take instead,
and a KEYWORD that names questions of more than one namespace, and a `--question-id` that two
questions of one FormSet hold, naming each match, and write nothing. `set` takes VALUE literally with `--question-id` and `--keyword`: the spellings database,
which lets VALUE take other spellings by QUESTION, keys them by prompt.

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
EFI_HII_CONFIG_ACCESS_PROTOCOL.CallBack() (UEFI 2.11 §33.2.5.6, §33.3.8.2.2), but a date or time
question of EFI Date/Time Storage, which keeps its value there. `get` shows, and `set` refuses
with, what it lacks; but the READ, WRITE and EFI_IFR_VALUE expressions of an ordered-list question
give or take a buffer, those of a cross-reference question on a VarStore an EFI_HII_REF, and those
of a string question its characters, which uefisettings does not evaluate, so `get` shows that,
and `set` refuses it, with or without a VarStore:

| The question has | `get` | `set` |
|---|---|---|
| EFI_IFR_VALUE | the value of VALUE | refused: read-only (UEFI 2.11 §33.3.8.3.88) |
| READ and WRITE | the value of READ | through WRITE |
| READ only | the value of READ | refused: nothing keeps a changed value |
| WRITE only | refused: no value to retrieve | through WRITE |
| neither, nor EFI_IFR_FLAG_CALLBACK | refused: one of them is required | refused |
| EFI_IFR_FLAG_CALLBACK only | its driver's CallBack(): see below | its driver's CallBack(): see below |
| EFI_IFR_FLAG_CALLBACK with READ (get) or WRITE (set) | as above, but refused where RETRIEVE fails: uefisettings does not evaluate READ beside CallBack() | refused before any write: uefisettings does not evaluate WRITE beside CallBack() |

`get` refuses too where READ gives no value, as no stored value takes its place, and `set` where
WRITE sets no VarStore. A browser lets the driver override READ with
CallBack(EFI_BROWSER_ACTION_RETRIEVE) and calls CallBack() around WRITE, so a question with
EFI_IFR_FLAG_CALLBACK is its driver's to answer. On Linux, Windows and macOS, which run after
ExitBootServices(), when no EFI device-handle-based protocol may be used (UEFI 2.11 §7.4.6), the
refusal points to `uefisettings.efi` in the UEFI Shell, which calls CallBack(): see the UEFI Shell
details. `hii list-questions` and `hii show-ifr` never call CallBack(): they show such a question
with the refusal of `get`.

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

`variable set AuditMode 1 --i-am-fine-to-brick-this-system`, in the UEFI Shell, enters Audit Mode
from Setup Mode or User Mode, which clears PK and sets SetupMode to 1 and DeployedMode to 0 (UEFI
2.11 §32.3.3); setting PK then enters Deployed Mode, not User Mode (§32.3.4). It reads SetupMode,
AuditMode and DeployedMode first and refuses, before any write, a firmware without them, as edk2 is,
values that tell no mode of §32.3, and Audit Mode from Audit Mode or Deployed Mode, with the flag
too; only then, without the flag, it refuses AuditMode (see [Unsafe
operations](#unsafe-operations)). Linux and Windows refuse it first, naming no flag, as AuditMode
"Always becomes read-only after ExitBootServices() is called" (§3.3). It prints a warning of the
transition on stderr, then what it wrote, as set does, and `status`, what SetVariable() returned:
`EFI_SUCCESS`, or `EFI_WARN_RESET_REQUIRED` if the firmware queued the transition for the next
reset, the mode variables unchanged until then (§32.3); a firmware that has queued one refuses
another with EFI_ALREADY_STARTED, which set reports as an error.

```plain
FS0:\> uefisettings.efi variable set AuditMode 1 --i-am-fine-to-brick-this-system
```

`variable set DeployedMode 1 --i-am-fine-to-brick-this-system`, in the UEFI Shell, enters Deployed
Mode from User Mode, which sets SetupMode to 0, and AuditMode to 0 and DeployedMode to 1, both made
read-only (§32.3.4); leaving it "requires a secure platform-specific method, or deleting the PK,
which is authenticated" (§32.3). It checks the mode variables as for Audit Mode and refuses Deployed
Mode from Setup Mode, which §32.3 lists no unauthenticated transition to it from, and from Audit
Mode, where SetupMode is 1 and enrolling PK enters Deployed Mode instead, as `variable write-signed
PK` does with the flag (§32.3.4); it refuses these with the flag too, and only then, without the
flag, DeployedMode. Linux and Windows refuse it first, naming no flag, as DeployedMode "Always
becomes read-only after ExitBootServices() is called" (§3.3). It prints as for Audit Mode: §32.3 and
§32.3.4 have this transition take effect immediately, so `EFI_WARN_RESET_REQUIRED` there is a
firmware departure that set reports as returned.

```plain
FS0:\> uefisettings.efi variable set DeployedMode 1 --i-am-fine-to-brick-this-system
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
delete the variable, and, while SetupMode is 1, or cannot be read or holds other than a UINT8 of
0 or 1, which may be 1, a Secure Boot policy variable (PK, KEK,
OsRecoveryOrder, OsRecovery####, and every variable of EFI_IMAGE_SECURITY_DATABASE_GUID, such as
db, dbx, dbt and dbr; §3.3), which the firmware writes then without checking the signature, or a
device signature database (every variable of EFI_DEVICE_SECURITY_DATABASE_GUID, such as devdb),
which the firmware may write then without checking the signature (§32.6.3), unless
`--i-am-fine-to-brick-this-system` is given (see [Unsafe operations](#unsafe-operations)). In User
Mode, a KEK or PK signs db, dbx, dbt and dbr (§32.5.3), and only PK signs devdb (§32.6.2, §32.6.3).
edk2-stable202608 departs from that for devdb: it verifies devdb as any other time-based
authenticated variable, in Setup Mode too, and then takes updates only from its first signer
(SecurityPkg AuthVariableLib's AuthVariableLibProcessVariable routes devdb to ProcessVariable, and
AuthService.c's VerifyTimeBasedPayload checks it in its AuthVarTypePriv branch).
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
uefisettings writes it, then the data, as above, and refuses the same writes: before it signs,
all but a write while SetupMode is 1, cannot be read or holds other than a UINT8 of 0 or 1,
which it refuses after.
The TimeStamp is TIME, a GMT time such as 2026-11-07T00:00:00Z, or else the current second of the
system clock; `uefisettings.efi` reads no clock, so it signs the all-zero TimeStamp of §8.2.6 for
`--append`, and needs `--timestamp` without it. RSA signs blinded, over a random source seeded
once from getrandom, or from EFI_RNG_PROTOCOL in the UEFI Shell, which refuses to sign without
it. rsa has no release that fixes RUSTSEC-2023-0071's timing leak; blinding is partial
hardening, and uefisettings runs as the advisory's workaround allows: local use on a
non-compromised computer. uefisettings reads KEY as a secret; KEY and CERTIFICATES hold at most
64 KiB each.

`--i-am-fine-to-brick-this-system` has either form write, while SetupMode is 1, cannot be read
or holds other than a UINT8 of 0 or 1, a
Secure Boot policy variable, which the firmware writes then without checking the signature (§3.3,
§32.3), as to enroll KEK and then PK, or a device signature database, which the firmware may write
then without checking the signature (§32.6.3). The payload of a Secure Boot policy variable is
still an EFI_VARIABLE_AUTHENTICATION_2; that of a device signature database may be either
descriptor: an EFI_VARIABLE_AUTHENTICATION_3 with `enhanced-authenticated-access`, as §32.6.3
formats a Setup Mode write, or an EFI_VARIABLE_AUTHENTICATION_2, which edk2 takes. A write without
data and without `--append` stays refused, as edk2 deletes the variable then. uefisettings still
reads SetupMode then, refusing where it cannot, and warns of each such write on stderr. Writing PK
moves Setup Mode to User Mode, and Audit Mode to Deployed Mode (§32.3.1, §32.3.4). PK may have to
be signed with its own key (§32.3.1).

```sh
uefisettings variable write-signed db D719B2CB-3D3A-4596-A3BC-DAD00E67656F --attributes non-volatile,bootservice-access,runtime-access --append --data-file db.esl --signing-key-file kek.key --signing-certificate-file kek.pem
```

With `enhanced-authenticated-access` in ATTRIBUTES, both forms write a variable of
EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS, whose descriptor is an EFI_VARIABLE_AUTHENTICATION_3
(§8.2.5), without EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS. uefisettings checks the
payload of `--payload-file` before it writes it unchanged: the 12-byte
EFI_VARIABLE_AUTHENTICATION_3 of Version 1, its EFI_TIME or EFI_VARIABLE_AUTHENTICATION_3_NONCE, a
NewCert if Flags has EFI_VARIABLE_ENHANCED_AUTH_FLAG_UPDATE_CERT, then the SigningCert, each
certificate a WIN_CERTIFICATE_UEFI_GUID of PKCS #7 on a 4-byte boundary after zero bytes, as C lays
the structures out, and MetadataSize their size, then the data. With `--data-file`, KEY signs over
SHA-256 or the `--digest`, as above, and `--timestamp TIME` or `--nonce HEX` gives the Type; the
firmware takes only a TimeStamp later than the variable's, or a nonce other than its own, and makes
one for an all-zero nonce where it can. `--current-nonce HEX`, the variable's nonce, is required to
update a NONCE variable, and `--new-signing-key-file KEY2 --new-signing-certificate-file
CERTIFICATES2` adds a NewCert, which KEY2 signs over the same digest and which hands the variable
to KEY2; with it, the data may be empty, to change the certificate alone. uefisettings does not
compare these with the stored variable: the firmware does. Before it seeds or writes, it refuses a
write without data or NewCert, which would delete the variable, a Secure Boot policy variable,
which takes only an EFI_VARIABLE_AUTHENTICATION_2, a device signature database while SetupMode is
1, as above, and on Linux every such write, as efivarfs lacks the attribute (EFI_VARIABLE_MASK in
include/linux/efi.h); `uefisettings.efi` writes them in the UEFI Shell.

```plain
FS0:\> uefisettings.efi variable write-signed Example DE145B29-C3CD-455F-91DE-A76237B67C52 --attributes non-volatile,bootservice-access,runtime-access,enhanced-authenticated-access --data-file example.bin --signing-key-file owner.key --signing-certificate-file owner.pem --nonce 00000000000000000000000000000000
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

The UEFI Shell runs no setup browser, so nothing there asks for or checks a setup password: in a
HiiDB that declares a password question, `set` writes nothing unless
`--i-am-fine-to-brick-this-system` is given (see [Unsafe operations](#unsafe-operations)).

`set` refuses a variable without EFI_VARIABLE_NON_VOLATILE unless `--allow-volatile` is given.
The UEFI Shell runs before ExitBootServices, when SetVariable() still sets volatile variables
(UEFI 2.11 §8.2.3), but the written value lasts only until the next reset or power cycle: when a
variable that `set` writes is volatile, as read before the write, its answer ends with
` <volatile: lasts until the next reset or power cycle>`. Linux and Windows write after
ExitBootServices, when SetVariable() sets no volatile variable (UEFI 2.11 §8.2.3), so they take
no `--allow-volatile`.

`hii keyword get` and `hii keyword set` read and write questions by the keywords of UEFI
configuration languages such as `x-UEFI-ns`, through EFI_CONFIG_KEYWORD_HANDLER_PROTOCOL (UEFI
2.11 §35.3.1), which no OS reaches. `get` takes a `<MultiKeywordRequest>`, `<KeywordRequest>`s
joined by `&`, each of an optional PATH, the hex digits of the device path of the keyword's
package list, and a KEYWORD, and prints GetData()'s `<KeywordResp>`s, one per request and package
list without PATH, in the requests' order. It reads the keyword's question whatever its
conditions, as GetData() does, so it takes no `--include`, but not one whose bytes, as GetData()
reads them, overlap a password's. It refuses every request that it would not read, and a question
that two requests name, before any GetData(), and reads the keywords of each configuration
language with one GetData(): when one fails, it prints the `<KeywordResp>`s read before it and
the requests read no value of, and calls no further GetData(). A `<Filter>` after the KEYWORD
(§35.2.1.6) selects the
questions whose `EFI_IFR_FLAG_READ_ONLY` and HII Keyword Data Type, by §35.2.1.6's table, pass
it, from the IFR before any GetData(), which gets no `<Filter>`. This departs from
edk2-stable202608's GetData(): the `<Filter>` selects among the instances, which §35.2.1.6 makes
every one for a request without PATH, where edk2 fails the call with
KEYWORD_HANDLER_INCOMPATIBLE_VALUE_DETECTED (ConfigKeywordHandler.c:3341-3346); a CHECKBOX is
`Boolean` by the table, where edk2's `Numeric[:n]` passes it (:597-619); and a request that no
instance passes is refused before any GetData(). `--filter-by-get-data` sends GetData() each
instance with its PATH and the `<Filter>` unchanged instead, so on edk2 one instance that does not
pass it fails the whole GetData().
`set` takes a `<MultiKeywordResp>`,
refuses it if `set` would refuse a keyword's question or value, if SetData() would write one
otherwise than `set` (edk2's evaluates no condition or expression, sends no Callback() and checks
no option or range), or if two keywords write a byte of one variable, and else writes every
keyword with one SetData() and prints what GetData() reads back, which must hold each VALUE
written, as a number. It never writes a read-only question, which the Keyword Handler refuses,
even with `--i-am-fine-to-brick-this-system`; else `--include`, that flag and `--allow-volatile`
work as for `set`: the `<KeywordResp>` of a keyword whose variable is volatile
ends with ` <volatile: lasts until the next reset or power cycle>`. `-j` prints JSON instead.
A VALUE holds every byte that SetData() writes, last byte first, as edk2's GetValueOfNumber
(ConfigRouting.c:518) and UEFI 2.11 §35.4.6's example read it, where §35.2.1.5 lists a
`<Number>`'s bytes in memory order: of a DATE or TIME each field, which `set` takes as the digits
of its text, so a field that the question suppresses must be the one that `set` keeps; of an
ORDERED_LIST each container, whose options up to the first empty one `set` takes as `--item`s,
every container after it empty. A container is as wide as the Type of the ONE_OF_OPTION right
after the ORDERED_LIST, as edk2's GetWidth takes it, where UEFI 2.11 §33.2.5.4.8 gives it one
byte; a VALUE is refused where `set` writes containers of another width, that of the first option
that is no default. A REF, whose EFI_HII_REF `set` does not write, is refused. Of a STRING, a
VALUE holds all MaxSize CHAR16s, as edk2's GetWidth takes them, so `AB` of MaxSize 4 is
`0000000000420041`; UEFI 2.11 §33.2.5.4.9 represents a STRING's result as "hex dump of the
string, including the terminating NULL character", but a VALUE of fewer bytes is refused, as
edk2-stable202608 ConfigRouting.c HiiConfigToBlock copies the question's width (:6353) from a
buffer of half the VALUE's digits (:508-509): `set`'s checks take its text up to the first NULL,
and a VALUE that is not the bytes that `set` writes for that text, NULL-padded (UEFI 2.11
§33.2.5.4.9), or that holds a UTF-16 surrogate is refused.

```plain
FS0:\> uefisettings.efi hii keyword get --namespace x-UEFI-ns KEYWORD=<keyword>
FS0:\> uefisettings.efi hii keyword set "NAMESPACE=x-UEFI-ns&PATH=<hex digits>&KEYWORD=<keyword>&VALUE=<hex digits>"
```

A question without a VarStore whose value only its driver keeps (EFI_IFR_FLAG_CALLBACK, UEFI 2.11
§33.2.5.6) is reached through that driver's EFI_HII_CONFIG_ACCESS_PROTOCOL.Callback(), with the
browser actions that a forms browser sends, as no forms browser runs. `get` sends FORM_OPEN,
RETRIEVE and FORM_CLOSE, and shows the value that RETRIEVE gave; `set` refuses such a question.
Only `get` calls a driver: `list-questions`, `show-ifr`, the dumps and `get --no-efivars` show why
such a question has no value, and so does `get` on Linux, Windows and macOS.

uefisettings exchanges a value with Callback() only for a one-of, numeric or checkbox question: it
refuses an ordered-list or string question, or a date or time question outside EFI Date/Time
Storage, with EFI_IFR_FLAG_CALLBACK and no VarStore, and names its op. A Callback() names its question by
QuestionId alone, "The unique value that identifies the particular question" (UEFI 2.11
§33.3.8.2.2), so uefisettings calls none for a question whose QuestionId another question of its
FormSet also has, such as a password question: it refuses that question and names the other's op.

Each Callback() sequence runs between reads of the stores of the question's FormSet: of its Buffer
and Name/Value stores by EFI_HII_CONFIG_ROUTING_PROTOCOL.ExtractConfig() of the settings that a
forms browser requests, and of its EFI variable stores. A store that cannot be read refuses before
the first Callback(). Settings that change between two reads before it, as a timestamp does, are
listed and not compared. A store that the Callback()s changed is restored, a Buffer or Name/Value
store by one RouteConfig() of all its settings, and the answer is refused: the driver has already
acted on the change, and any effect outside the FormSet's stores stays. The reads never request the
bytes of a PASSWORD question, and read them as zero in an EFI variable store, so a Callback() that
changes only them goes unnoticed, and a changed store that holds one is not restored, as a
RouteConfig() without the password bytes may clear it and SetVariable() would write zeros over them.
`get` of a question with a READ expression shows RETRIEVE's value, as a forms browser does. Where
RETRIEVE fails, a forms browser keeps READ's value, but uefisettings does not evaluate READ beside
a driver's Callback()s, so `get` refuses and says so. A Callback() that asks the forms browser to
save the FormSet's modified values, which only a forms browser's edit buffer holds, or returns an
ActionRequest that UEFI 2.11 §35.5.4 does not define refuses the answer too; a request for a
platform reset or to discard modified values is noted.

With Secure Boot enabled, the firmware starts an image only if its signature database (db) holds
the certificate of its signature or its hash, so sign `uefisettings.efi` with a key that the
machine's db trusts.

</details>
