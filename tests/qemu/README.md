# QEMU tests

These tests boot QEMU guests under OVMF and run `uefisettings` inside them, so they
exercise the CLI against real UEFI firmware, efivarfs and `/dev/mem` without touching the
machine that runs them.

## Running

```sh
tests/qemu/run.sh               # every scenario
tests/qemu/run.sh boot-smoke    # the named scenarios
```

`run.sh` needs KVM and, on Ubuntu 24.04, which CI uses, the packages of
[`ubuntu-packages`](ubuntu-packages) and the musl target:

```sh
xargs --arg-file=tests/qemu/ubuntu-packages sudo apt-get install --yes
rustup target add x86_64-unknown-linux-musl
```

Elsewhere, the environment variables in the header of [`run.sh`](run.sh) give the paths
of QEMU, the OVMF code and variable images and a static busybox, and these tools must be
on `PATH`: `jq` and `cpio` for `run.sh`, and `curl`, `rpm2cpio` and `cpio` for
[`fetch-kernel.sh`](fetch-kernel.sh).

Each run writes to `target/qemu-test/<UTC time>/`, with one directory per scenario. For
each boot `N`, `bootN.console.log` has the firmware, kernel and `init` output and
`bootN.test.log` the test output.

[`scenarios.tsv`](scenarios.tsv) lists the scenarios and the boots of each; each file in
[`guest/tests/`](guest/tests/) is one test binary, which a boot names, and its module
documentation says what it checks. The guest tests refuse to run on a machine whose kernel
command line lacks `uefisettings.test=`. They build only with the `test-vm` feature, which
`run.sh` enables, so each file needs a `[[test]]` entry with
`required-features = ["test-vm"]` in [`guest/Cargo.toml`](guest/Cargo.toml).
