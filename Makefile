# Copyright 2023 Meta Platforms, Inc. and affiliates.
#
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# The checks of uefisettings. They need GNU make and bash, rustup while
# RUST_TOOLCHAIN is set, as it is by default, for test-i686 an x86 host with
# gcc's 32-bit libraries, which README.md names, and for test-e2e-qemu an
# x86_64 host with /dev/kvm and what tests/qemu/README.md lists:
#   make                 every check of CHECKS, stopping at the first that fails
#   make -k              every check of CHECKS, even after one fails
#   make <check>...      the named checks, e.g. make clippy-aarch64 doc
#   make lint            the checks of LINTS
#   make lint test test-i686
#                        every check but test-e2e-qemu
#   make RUST_TOOLCHAIN= the checks on the cargo of PATH
#   make setup           installs, through rustup, the toolchain, components and
#                        targets that the checks use
#   make help            the checks
# make -n <check> prints the commands of a check without running them. The
# checks install nothing themselves.
#
# A CI host runs make setup && make -k under timeout, as nothing bounds the time
# that cargo takes: timeout -k 60 <seconds> bash -c 'make setup && make -k'. It
# may keep target/qemu-test/packages and target/qemu-test/driver-sample
# between runs: tests/qemu/fetch-packages.sh downloads only the packages that are
# missing there or fail their sha256 check, and tests/qemu/run.sh builds
# DriverSample only when it is missing, so delete target/qemu-test/driver-sample
# after a change to build-driver-sample.sh.

SHELL := bash
.SHELLFLAGS := -euo pipefail -c

# The Rust release that the checks run on: newer releases bring lints that the
# code does not satisfy yet. make setup installs it; while RUST_TOOLCHAIN is set,
# the checks first check that rustup has it with clippy, rustfmt and TARGETS, and
# fail without them instead of installing them. RUST_TOOLCHAIN= runs the checks
# on the cargo of PATH. When that cargo is rustup's, RUSTUP_AUTO_INSTALL=0 keeps
# it from installing a missing toolchain, as it does while RUST_TOOLCHAIN is set;
# only setup, which installs, runs rustup with auto-install on.
RUST_TOOLCHAIN ?= 1.93.1
ifneq ($(RUST_TOOLCHAIN),)
export RUSTUP_TOOLCHAIN := $(RUST_TOOLCHAIN)
endif
export RUSTUP_AUTO_INSTALL := 0

# Any compiler warning fails the checks, also one in the generated crates of
# thrift/, which build as dependencies that clippy does not lint. Cargo caps the
# lints of registry crates. RUSTFLAGS replaces the rustflags of cargo's config
# files, and cargo would take CARGO_ENCODED_RUSTFLAGS instead of RUSTFLAGS, so
# the checks drop it.
export RUSTFLAGS := -D warnings
unexport CARGO_ENCODED_RUSTFLAGS

# The targets that the checks build for, comma-separated as rustup takes them.
TARGETS := x86_64-unknown-linux-gnu,aarch64-unknown-linux-gnu,i686-unknown-linux-gnu,x86_64-unknown-linux-musl,x86_64-unknown-uefi
comma := ,

# CI runs lint test test-i686 and test-e2e-qemu: a new check joins LINTS or CI
# runs it too.
LINTS := fmt clippy-x86_64 clippy-aarch64 clippy-i686 clippy-uefi doc
CHECKS := $(LINTS) test test-i686 test-e2e-qemu

.PHONY: check lint help setup toolchain $(CHECKS)

check: $(CHECKS)

lint: $(LINTS)

help:
	@echo "checks: $(CHECKS)"
	@echo "make runs every check; make <check>... runs the named ones."
	@echo "make lint runs $(LINTS)."
	@echo "make lint test test-i686 runs every check but test-e2e-qemu."
	@echo "make -k runs every check, even after one fails."
	@echo "make -n <check> prints the commands of a check without running them."
	@echo "make RUST_TOOLCHAIN= runs the checks on the cargo of PATH."
	@echo "make setup installs the Rust toolchain, components and targets of the checks."

# With RUST_TOOLCHAIN=, adds the components and targets to the active toolchain
# of rustup, which rustup first installs when it is missing.
setup: export RUSTUP_AUTO_INSTALL := 1
setup:
ifneq ($(RUST_TOOLCHAIN),)
	rustup toolchain install '$(RUST_TOOLCHAIN)' --profile minimal --no-self-update \
		--component clippy,rustfmt --target $(TARGETS)
else
	rustup component add clippy rustfmt
	rustup target add $(subst $(comma), ,$(TARGETS))
endif

# Fails the checks, before any cargo call, when their toolchain is missing.
toolchain:
	@scripts/check-toolchain.sh '$(RUST_TOOLCHAIN)' '$(TARGETS)'

# Covers the workspace's QEMU test crates too.
fmt: toolchain
	cargo fmt --check

clippy-x86_64 clippy-aarch64 clippy-i686: clippy-%: toolchain
	cargo clippy --locked --workspace --all-targets --all-features --target $*-unknown-linux-gnu -- -D warnings

# publish-hiidb, the one crate built for UEFI.
clippy-uefi: toolchain
	cargo clippy --locked --release --target x86_64-unknown-uefi --manifest-path tests/qemu/publish-hiidb/Cargo.toml -- -D warnings

test: toolchain
	scripts/assert-tests-ran.sh cargo test --locked

# The tests on 32-bit glibc, where off_t has 32 bits; this host runs them.
test-i686: toolchain
	scripts/assert-tests-ran.sh cargo test --locked --target i686-unknown-linux-gnu

doc: toolchain
	RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps --document-private-items --locked

# Boots the scenarios of tests/qemu/scenarios.tsv under KVM, with logs in
# target/qemu-test/<UTC time>/; see tests/qemu/README.md.
test-e2e-qemu: toolchain
	tests/qemu/run.sh
