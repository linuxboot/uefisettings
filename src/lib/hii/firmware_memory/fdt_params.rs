// Copyright 2023 Meta Platforms, Inc. and affiliates.
//
// Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! The UEFI parameters that arm64's EFI stub passes to Linux in the FDT's /chosen node (Linux
//! Documentation/arch/arm/uefi.rst, drivers/firmware/efi/libstub/fdt.c update_fdt()).

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;

use super::array_at;

/// The FDT header's magic (scripts/dtc/libfdt/fdt.h FDT_MAGIC).
const FDT_MAGIC: u32 = 0xd00d_feed;
/// The structure block's tokens (scripts/dtc/libfdt/fdt.h).
const FDT_BEGIN_NODE: u32 = 0x1;
const FDT_END_NODE: u32 = 0x2;
const FDT_PROP: u32 = 0x3;
const FDT_NOP: u32 = 0x4;
const FDT_END: u32 = 0x9;
/// The size and alignment of a structure block token.
const FDT_TAG_SIZE: usize = 4;
/// The path of /chosen, from the root, whose name is empty.
const CHOSEN_PATH: &[&[u8]] = &[b"", b"chosen"];
/// The path of /hypervisor/uefi, where Xen gives its EFI parameters (Linux v6.11
/// drivers/firmware/efi/fdtparams.c:37-46).
const XEN_UEFI_PATH: &[&[u8]] = &[b"", b"hypervisor", b"uefi"];
/// Xen's property of the System Table in /hypervisor/uefi (Linux v6.11
/// drivers/firmware/efi/fdtparams.c:41).
const XEN_SYSTEM_TABLE: &[u8] = b"xen,uefi-system-table";

/// The names and values of a node's properties, in their order.
type Properties<'a> = Vec<(&'a [u8], &'a [u8])>;

/// The /chosen properties that locate the memory map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::hii) struct UefiFdtParams {
    /// linux,uefi-mmap-start
    pub(in crate::hii) mmap_start: u64,
    /// linux,uefi-mmap-size
    pub(in crate::hii) mmap_size: usize,
    /// linux,uefi-mmap-desc-size
    pub(in crate::hii) mmap_desc_size: usize,
    /// linux,uefi-mmap-desc-ver
    pub(in crate::hii) mmap_desc_ver: u32,
}

impl UefiFdtParams {
    /// The UEFI parameters in /chosen of the flattened device tree `fdt`.
    pub(super) fn parse(fdt: &[u8]) -> Result<Self> {
        let chosen = chosen_properties(fdt)?;
        Ok(Self {
            mmap_start: u64::from_be_bytes(chosen_value(&chosen, "linux,uefi-mmap-start")?),
            mmap_size: usize::try_from(u32::from_be_bytes(chosen_value(
                &chosen,
                "linux,uefi-mmap-size",
            )?))?,
            mmap_desc_size: usize::try_from(u32::from_be_bytes(chosen_value(
                &chosen,
                "linux,uefi-mmap-desc-size",
            )?))?,
            mmap_desc_ver: u32::from_be_bytes(chosen_value(&chosen, "linux,uefi-mmap-desc-ver")?),
        })
    }
}

/// What a flattened device tree gives of the EFI System Table. Unlike Linux v6.11 with
/// CONFIG_XEN, which tries /hypervisor/uefi first and, without xen,uefi-system-table there,
/// finds no UEFI (drivers/firmware/efi/fdtparams.c:36-48, :106-132), this reads /chosen first:
/// Linux's EFI stub writes linux,uefi-system-table there
/// (Documentation/arch/arm/uefi.rst:49-55), and Xen gives a guest its EFI parameters in
/// /hypervisor/uefi instead (Documentation/devicetree/bindings/arm/xen.txt:22-23, :58-60). Node
/// names match exactly, where Linux also takes one with a unit address
/// (scripts/dtc/libfdt/fdt_ro.c:26-29).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::hii) enum FdtSystemTable {
    /// The physical address of linux,uefi-system-table in /chosen, which must have 8 bytes, as
    /// the stub writes it (Documentation/arch/arm/uefi.rst:55), where Linux also reads 4
    /// (fdtparams.c:71).
    At(u64),
    /// /chosen has no linux,uefi-system-table, and no /hypervisor/uefi holds
    /// xen,uefi-system-table: Linux finds no UEFI (fdtparams.c:107-109, :118-122, :130-132).
    Absent,
    /// /chosen has no linux,uefi-system-table, and /hypervisor/uefi holds Xen's
    /// xen,uefi-system-table, whose value this does not read (fdtparams.c:38-41).
    Xen,
}

/// What the flattened device tree `fdt` gives of the EFI System Table: linux,uefi-system-table
/// in /chosen, or, without it, whether /hypervisor/uefi holds Xen's xen,uefi-system-table.
pub(in crate::hii) fn uefi_system_table(fdt: &[u8]) -> Result<FdtSystemTable> {
    let chosen = node_properties(fdt, CHOSEN_PATH)?.unwrap_or_default();
    if let Some(address) = optional_chosen_value(&chosen, "linux,uefi-system-table")? {
        return Ok(FdtSystemTable::At(u64::from_be_bytes(address)));
    }
    let xen = node_properties(fdt, XEN_UEFI_PATH)?.unwrap_or_default();
    Ok(if xen.iter().any(|&(name, _)| name == XEN_SYSTEM_TABLE) {
        FdtSystemTable::Xen
    } else {
        FdtSystemTable::Absent
    })
}

/// The value of the property `name` in `chosen`, the properties of /chosen, which has `N`
/// bytes.
fn chosen_value<const N: usize>(chosen: &[(&[u8], &[u8])], name: &str) -> Result<[u8; N]> {
    optional_chosen_value(chosen, name)?.with_context(|| format!("/chosen has no {name}"))
}

/// chosen_value, or None without the property.
fn optional_chosen_value<const N: usize>(
    chosen: &[(&[u8], &[u8])],
    name: &str,
) -> Result<Option<[u8; N]>> {
    chosen
        .iter()
        .find(|(key, _)| *key == name.as_bytes())
        .map(|&(_, value)| {
            value
                .try_into()
                .with_context(|| format!("{name} has {} bytes, not {N}", value.len()))
        })
        .transpose()
}

/// The big-endian u32 at `offset` of the FDT `fdt`.
fn fdt_u32(fdt: &[u8], offset: usize) -> Result<u32> {
    array_at(fdt, offset)
        .map(u32::from_be_bytes)
        .with_context(|| format!("the FDT ends before offset {offset:#x}"))
}

/// The NUL-terminated string at `offset` of the FDT `fdt`, without its NUL.
fn fdt_string(fdt: &[u8], offset: usize) -> Result<&[u8]> {
    let rest = fdt
        .get(offset..)
        .with_context(|| format!("the FDT ends before offset {offset:#x}"))?;
    rest.iter()
        .position(|&byte| byte == 0)
        .and_then(|end| rest.get(..end))
        .with_context(|| format!("the FDT string at {offset:#x} has no NUL"))
}

/// `offset` advanced past `length` bytes, padded to FDT_TAG_SIZE.
fn fdt_advance(offset: usize, length: usize) -> Result<usize> {
    length
        .checked_next_multiple_of(FDT_TAG_SIZE)
        .and_then(|padded| offset.checked_add(padded))
        .with_context(|| format!("the FDT offset {offset:#x} overflows"))
}

/// The names and values of the properties of /chosen in the FDT `fdt`.
fn chosen_properties(fdt: &[u8]) -> Result<Properties<'_>> {
    node_properties(fdt, CHOSEN_PATH)?.context("the FDT has no /chosen")
}

/// The names and values of the properties of the node at `node` in the FDT `fdt`, or None
/// without that node.
fn node_properties<'a>(fdt: &'a [u8], node: &[&[u8]]) -> Result<Option<Properties<'a>>> {
    let magic = fdt_u32(fdt, 0)?;
    if magic != FDT_MAGIC {
        bail!("FDT magic {magic:#x} is not {FDT_MAGIC:#x}");
    }
    let structure = usize::try_from(fdt_u32(fdt, 8)?)?;
    let strings = usize::try_from(fdt_u32(fdt, 12)?)?;

    // The names of the nodes from the root, whose name is empty, to the current one.
    let mut path: Vec<&[u8]> = Vec::new();
    let mut properties = Vec::new();
    let mut offset = structure;
    loop {
        let token_at = offset;
        let token = fdt_u32(fdt, token_at)?;
        offset = fdt_advance(token_at, FDT_TAG_SIZE)?;
        let in_node = path.as_slice() == node;
        match token {
            FDT_BEGIN_NODE => {
                let name = fdt_string(fdt, offset)?;
                // The name and its NUL
                offset = fdt_advance(offset, name.len().saturating_add(1))?;
                path.push(name);
            }
            FDT_END_NODE if in_node => return Ok(Some(properties)),
            FDT_END_NODE => {
                path.pop().context("the FDT ends a node it did not begin")?;
            }
            FDT_PROP => {
                let length = usize::try_from(fdt_u32(fdt, offset)?)?;
                let name_offset =
                    usize::try_from(fdt_u32(fdt, fdt_advance(offset, FDT_TAG_SIZE)?)?)?;
                let value_start = fdt_advance(offset, 2 * FDT_TAG_SIZE)?;
                let value = value_start
                    .checked_add(length)
                    .and_then(|value_end| fdt.get(value_start..value_end))
                    .with_context(|| format!("the FDT ends inside the property at {offset:#x}"))?;
                if in_node {
                    let name = strings
                        .checked_add(name_offset)
                        .context("an FDT property name offset overflows")?;
                    properties.push((fdt_string(fdt, name)?, value));
                }
                offset = fdt_advance(value_start, length)?;
            }
            FDT_NOP => {}
            FDT_END => return Ok(None),
            other => bail!("unknown FDT token {other:#x} at {token_at:#x}"),
        }
    }
}

/// FDTs for the tests of the efivar source.
#[cfg(test)]
pub(in crate::hii) mod fixture {
    use super::*;

    /// A property of the structure block: its token, length, name offset and padded value.
    pub(in crate::hii) fn property(name_offset: u32, value: &[u8]) -> Vec<u8> {
        let mut bytes = [
            FDT_PROP.to_be_bytes(),
            u32::try_from(value.len())
                .expect("a u32 length")
                .to_be_bytes(),
            name_offset.to_be_bytes(),
        ]
        .concat();
        bytes.extend(value);
        bytes.resize(bytes.len().next_multiple_of(FDT_TAG_SIZE), 0);
        bytes
    }

    /// A node of the structure block: its name, padded, and `body`.
    pub(in crate::hii) fn node(name: &str, body: &[u8]) -> Vec<u8> {
        let mut bytes = FDT_BEGIN_NODE.to_be_bytes().to_vec();
        bytes.extend(name.as_bytes());
        bytes.push(0);
        bytes.resize(bytes.len().next_multiple_of(FDT_TAG_SIZE), 0);
        bytes.extend(body);
        bytes.extend(FDT_END_NODE.to_be_bytes());
        bytes
    }

    /// An FDT whose strings block holds `names`, with the structure block `structure`.
    pub(in crate::hii) fn fdt(names: &[&str], structure: &[u8]) -> Vec<u8> {
        let structure_offset = 40u32;
        let strings: Vec<u8> = names
            .iter()
            .flat_map(|name| name.bytes().chain([0]))
            .collect();
        let structure = [structure, &FDT_END.to_be_bytes()].concat();
        let strings_offset =
            structure_offset + u32::try_from(structure.len()).expect("a u32 offset");
        let mut header = [
            FDT_MAGIC,
            0, // totalsize, unread
            structure_offset,
            strings_offset,
        ]
        .map(u32::to_be_bytes)
        .concat();
        header.resize(
            usize::try_from(structure_offset).expect("a usize offset"),
            0,
        );
        [header, structure, strings].concat()
    }

    /// The name offsets of PARAM_NAMES in the strings block of fdt(&PARAM_NAMES, ...).
    pub(in crate::hii) const PARAM_NAMES: [&str; 4] = [
        "linux,uefi-mmap-start",
        "linux,uefi-mmap-size",
        "linux,uefi-mmap-desc-size",
        "linux,uefi-mmap-desc-ver",
    ];

    pub(in crate::hii) fn name_offset(name: &str) -> u32 {
        let index = PARAM_NAMES
            .iter()
            .position(|known| *known == name)
            .expect("a name of PARAM_NAMES");
        let offset: usize = PARAM_NAMES[..index].iter().map(|n| n.len() + 1).sum();
        u32::try_from(offset).expect("a u32 offset")
    }

    /// The /chosen properties of `params`, as arm64's stub writes them, in its order, but
    /// `skipped`.
    pub(in crate::hii) fn uefi_properties_of(
        params: &UefiFdtParams,
        skipped: Option<&str>,
    ) -> Vec<u8> {
        [
            (
                "linux,uefi-mmap-start",
                params.mmap_start.to_be_bytes().to_vec(),
            ),
            ("linux,uefi-mmap-size", be_u32_bytes(params.mmap_size)),
            (
                "linux,uefi-mmap-desc-size",
                be_u32_bytes(params.mmap_desc_size),
            ),
            (
                "linux,uefi-mmap-desc-ver",
                params.mmap_desc_ver.to_be_bytes().to_vec(),
            ),
        ]
        .iter()
        .filter(|(name, _)| Some(*name) != skipped)
        .flat_map(|(name, value)| property(name_offset(name), value))
        .collect()
    }

    fn be_u32_bytes(value: usize) -> Vec<u8> {
        u32::try_from(value)
            .expect("a u32 value")
            .to_be_bytes()
            .to_vec()
    }

    /// An FDT whose /chosen gives no EFI parameters, as where Linux was booted without UEFI.
    pub(in crate::hii) fn no_uefi_fdt() -> Vec<u8> {
        fdt(&PARAM_NAMES, &node("", &node("chosen", &[])))
    }

    /// An FDT whose /hypervisor/uefi holds the properties `names`, each of 8 bytes, after
    /// PARAM_NAMES in its strings block, and whose /chosen holds no EFI parameters.
    pub(super) fn hypervisor_uefi_fdt(names: &[&str]) -> Vec<u8> {
        let mut offset: usize = PARAM_NAMES.iter().map(|name| name.len() + 1).sum();
        let mut properties = Vec::new();
        for name in names {
            let name_offset = u32::try_from(offset).expect("a u32 offset");
            properties.extend(property(name_offset, &0x7f9e_8018u64.to_be_bytes()));
            offset += name.len() + 1;
        }
        let hypervisor = node("hypervisor", &node("uefi", &properties));
        fdt(
            &[&PARAM_NAMES[..], names].concat(),
            &node("", &[hypervisor, node("chosen", &[])].concat()),
        )
    }

    /// An FDT whose /hypervisor/uefi holds xen,uefi-system-table, where Xen gives the System
    /// Table (Linux v6.11 Documentation/devicetree/bindings/arm/xen.txt:22-29), and whose
    /// /chosen holds no EFI parameters.
    pub(in crate::hii) fn xen_uefi_fdt() -> Vec<u8> {
        hypervisor_uefi_fdt(&["xen,uefi-system-table"])
    }

    /// An FDT whose /chosen holds `params` only.
    pub(in crate::hii) fn uefi_fdt(params: &UefiFdtParams) -> Vec<u8> {
        let chosen = node("chosen", &uefi_properties_of(params, None));
        fdt(&PARAM_NAMES, &node("", &chosen))
    }

    /// The name of the System Table's property, after PARAM_NAMES in the strings block of
    /// uefi_fdt_with_system_table's FDT.
    const SYSTEM_TABLE_NAME: &str = "linux,uefi-system-table";

    /// An FDT whose /chosen holds linux,uefi-system-table of `value`, as the stub writes it
    /// first, then `params`.
    pub(in crate::hii) fn uefi_fdt_with_system_table(
        params: &UefiFdtParams,
        value: &[u8],
    ) -> Vec<u8> {
        let names = [&PARAM_NAMES[..], &[SYSTEM_TABLE_NAME]].concat();
        let offset: usize = PARAM_NAMES.iter().map(|name| name.len() + 1).sum();
        let system_table = property(u32::try_from(offset).expect("a u32 offset"), value);
        let chosen = node(
            "chosen",
            &[system_table, uefi_properties_of(params, None)].concat(),
        );
        fdt(&names, &node("", &chosen))
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::*;
    use super::*;

    /// The /chosen properties of WANT, but `skipped`.
    fn uefi_properties_but(skipped: Option<&str>) -> Vec<u8> {
        uefi_properties_of(&WANT, skipped)
    }

    fn uefi_properties() -> Vec<u8> {
        uefi_properties_but(None)
    }

    const WANT: UefiFdtParams = UefiFdtParams {
        mmap_start: 0x7c75_1000,
        mmap_size: 0x1e00,
        mmap_desc_size: 48,
        mmap_desc_ver: 1,
    };

    #[test]
    fn parse_reads_the_uefi_properties_of_chosen() {
        // The same properties in another node, before /chosen, must not count.
        let decoy = [
            property(
                name_offset("linux,uefi-mmap-start"),
                &0xdead_beefu64.to_be_bytes(),
            ),
            node("chosen", &[]),
        ]
        .concat();
        let structure = node(
            "",
            &[
                node("memory@40000000", &decoy),
                FDT_NOP.to_be_bytes().to_vec(),
                node("chosen", &uefi_properties()),
            ]
            .concat(),
        );

        let params = UefiFdtParams::parse(&fdt(&PARAM_NAMES, &structure)).expect("parse the FDT");

        assert_eq!(params, WANT);
    }

    #[test]
    fn parse_fails_without_a_property() {
        for name in &PARAM_NAMES {
            let structure = node("", &node("chosen", &uefi_properties_but(Some(name))));

            let error = UefiFdtParams::parse(&fdt(&PARAM_NAMES, &structure))
                .expect_err("parse an FDT without the property");

            assert_eq!(
                error.to_string(),
                format!("/chosen has no {name}"),
                "{name}"
            );
        }
    }

    /// The offset of `name` in the strings block of fdt(`names`, ...).
    fn offset_of(names: &[&str], name: &str) -> u32 {
        let index = names
            .iter()
            .position(|known| *known == name)
            .expect("a name of names");
        let offset: usize = names[..index].iter().map(|n| n.len() + 1).sum();
        u32::try_from(offset).expect("a u32 offset")
    }

    /// uefi_system_table reads linux,uefi-system-table, 64 bits big-endian, from /chosen only,
    /// and fails with another size; without it, it gives Xen only where /hypervisor/uefi holds
    /// xen,uefi-system-table, and Absent otherwise, also without /chosen, where Linux v6.11 finds
    /// no UEFI (drivers/firmware/efi/fdtparams.c:106-132).
    #[test]
    fn uefi_system_table_reads_its_property_of_chosen() {
        for (case, fdt, want) in [
            (
                "the property",
                uefi_fdt_with_system_table(&WANT, &0x7f9e_8018u64.to_be_bytes()),
                FdtSystemTable::At(0x7f9e_8018),
            ),
            ("no property", uefi_fdt(&WANT), FdtSystemTable::Absent),
            ("an empty /chosen", no_uefi_fdt(), FdtSystemTable::Absent),
            (
                "no /chosen",
                fdt(&PARAM_NAMES, &node("", &[])),
                FdtSystemTable::Absent,
            ),
            (
                "Xen's /hypervisor/uefi",
                xen_uefi_fdt(),
                FdtSystemTable::Xen,
            ),
            (
                "a /hypervisor without uefi, as a Xen guest's FDT has",
                fdt(
                    &PARAM_NAMES,
                    &node("", &[node("hypervisor", &[]), node("chosen", &[])].concat()),
                ),
                FdtSystemTable::Absent,
            ),
            (
                "/hypervisor/uefi without xen,uefi-system-table",
                hypervisor_uefi_fdt(&[]),
                FdtSystemTable::Absent,
            ),
            (
                "/hypervisor/uefi with xen,uefi-mmap-start only",
                hypervisor_uefi_fdt(&["xen,uefi-mmap-start"]),
                FdtSystemTable::Absent,
            ),
            (
                "linux,uefi-system-table in /chosen, xen,uefi-system-table in /hypervisor/uefi",
                {
                    let names = [
                        &PARAM_NAMES[..],
                        &["xen,uefi-system-table", "linux,uefi-system-table"],
                    ]
                    .concat();
                    let xen = offset_of(&names, "xen,uefi-system-table");
                    let linux = offset_of(&names, "linux,uefi-system-table");
                    let uefi = node("uefi", &property(xen, &0x7f9e_8018u64.to_be_bytes()));
                    let chosen = node("chosen", &property(linux, &0x7f9e_8018u64.to_be_bytes()));
                    fdt(
                        &names,
                        &node("", &[node("hypervisor", &uefi), chosen].concat()),
                    )
                },
                FdtSystemTable::At(0x7f9e_8018),
            ),
            (
                "a 4-byte xen,uefi-system-table, whose value is not read",
                {
                    let names = [&PARAM_NAMES[..], &["xen,uefi-system-table"]].concat();
                    let at = offset_of(&names, "xen,uefi-system-table");
                    let uefi = node("uefi", &property(at, &0x7f9e_8018u32.to_be_bytes()));
                    fdt(
                        &names,
                        &node(
                            "",
                            &[node("hypervisor", &uefi), node("chosen", &[])].concat(),
                        ),
                    )
                },
                FdtSystemTable::Xen,
            ),
        ] {
            let got = uefi_system_table(&fdt).unwrap_or_else(|error| panic!("{case}: {error:#}"));
            assert_eq!(got, want, "{case}");
        }

        let short = uefi_fdt_with_system_table(&WANT, &0x7f9e_8018u32.to_be_bytes());
        let error = uefi_system_table(&short).expect_err("read a 32-bit property");
        assert_eq!(
            error.to_string(),
            "linux,uefi-system-table has 4 bytes, not 8",
            "32 bits"
        );
    }

    #[test]
    fn parse_fails_on_a_bad_fdt() {
        let structure = node("", &node("chosen", &uefi_properties()));
        let good = fdt(&PARAM_NAMES, &structure);
        let mut bad_magic = good.clone();
        bad_magic[0] = 0;
        let no_chosen = fdt(&PARAM_NAMES, &node("", &[]));
        for (case, fdt, want) in [
            (
                "bad magic",
                bad_magic,
                "FDT magic 0xdfeed is not 0xd00dfeed",
            ),
            ("truncated", good[..60].to_vec(), "the FDT ends"),
            ("no /chosen", no_chosen, "the FDT has no /chosen"),
        ] {
            let error = UefiFdtParams::parse(&fdt)
                .expect_err("parse the bad FDT")
                .to_string();
            assert!(error.starts_with(want), "{case}: {error}");
        }
    }
}
