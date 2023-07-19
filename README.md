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

---

## Available commands

```plain
SUBCOMMANDS:
    get         Auto-identify backend and get the current value of a question
    help        Print this message or the help of the given subcommand(s)
    hii         Commands which work on machines exposing the UEFI HiiDB
    identify    Auto-identify backend and display hardware/bios-information
    ilo         Commands which work on machines having HPE's Ilo BMC
    set         Auto-identify backend and set/change the value of a question
```

`hii`:

```plain
SUBCOMMANDS:
    extract-db      Dump HiiDB into a file
    get             Get the current value of a question
    help            Print this message or the help of the given subcommand(s)
    list-strings    List all strings-id, string pairs in HiiDB
    set             Set/change the value of a question
    show-ifr        Show a human readable representation of the Hii Forms
```

`ilo`:

```plain
SUBCOMMANDS:
    get                Get the current value of a question
    help               Print this message or the help of the given subcommand(s)
    set                Set/change the value of a question
    show-attributes    List bios attributes and their current values
```

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

* Extract HiiDB from `/dev/mem` after getting offsets from `efivarfs`.
* Library (`hii`) in Rust partially implements the UEFI Hii specification.
* It parses the HiiDB op-codes into a DOM tree like representation which can be read by machines and humans.
* It can ask questions about UEFI settings from HiiDB and get their answers.
* Change UEFI settings by calculating the correct offsets and writing to entries in `efivarfs`.

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

If one needs to update a file inside [`thrift`](./thrift/) directory then:

1. Install fbthrift compiler: `cargo install fbthrift_compiler && (sudo dnf install -y fbthrift || sudo apt install -y fbthrift)`
2. Update the `.thrift` file.
3. Run `~/.cargo/bin/compiler path/to/updated/file.thrift`.
4. Run `mv lib.rs path/to/generated/rust/file.rs`.

For example:

```sh
# Install fbthrift compiler
cargo install fbthrift_compiler
sudo dnf install -y fbthrift

# Update file
vi thrift/uefisettings_spellings_db.thrift

# Re-generate the rust file from the thrift file.
cargo install fbthrift_compiler
~/.cargo/bin/compiler thrift/uefisettings_spellings_db.thrift
mv lib.rs thrift/rust/uefisettings_spellings_db_thrift/uefisettings_spellings_db.rs
```
