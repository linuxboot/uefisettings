# QEMU tests

These tests boot QEMU guests under OVMF and run `uefisettings` inside them, so they
exercise the CLI against real UEFI firmware, efivarfs and `/dev/mem` without touching the
machine that runs them.

## Running

`make qemu` runs the checks of the QEMU test crate and then every scenario, on the Rust
toolchain and targets that `make setup` installs (see the Checks section of the
repository's README):

```sh
make setup    # once
make qemu
```

It needs an x86_64 host with `/dev/kvm` and, on Ubuntu 24.04, the packages of
[`ubuntu-packages`](ubuntu-packages):

```sh
xargs --arg-file=tests/qemu/ubuntu-packages sudo apt-get install --yes
```

`run.sh` alone runs the scenarios on the active toolchain of rustup, which then needs the
musl target:

```sh
rustup target add x86_64-unknown-linux-musl   # once
tests/qemu/run.sh               # every scenario
tests/qemu/run.sh boot-smoke    # the named scenarios
```

Elsewhere, the environment variables in the header of [`run.sh`](run.sh) give the paths
of QEMU, the OVMF code and variable images and a static busybox, and these tools must be
on `PATH`: `jq` and `cpio` for `run.sh`, and `curl`, `rpm2cpio` and `cpio` for
[`fetch-kernel.sh`](fetch-kernel.sh).

`QEMU` must name the `qemu-system-x86_64` binary or a wrapper that `exec`s it: `run.sh`
stops a boot after 120 s by signalling that program, not its children, so a wrapper that
runs QEMU as a child would leave the guest running.

Each run writes to `target/qemu-test/<UTC time>/`, with one directory per scenario. For
each boot `N`, `bootN.console.log` has the firmware, kernel and `init` output and
`bootN.test.log` the test output.

[`scenarios.tsv`](scenarios.tsv) lists the scenarios and the boots of each; each file in
[`guest/tests/`](guest/tests/) is one test binary, which a boot names, and its module
documentation says what it checks. The guest tests refuse to run on a machine whose kernel
command line lacks `uefisettings.test=`. They build only with the `test-vm` feature, which
`run.sh` enables, so each file needs a `[[test]]` entry with
`required-features = ["test-vm"]` in [`guest/Cargo.toml`](guest/Cargo.toml).
