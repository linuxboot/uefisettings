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

//! JSON capsules (UEFI 2.11 §23.5): the caller's payload, unchanged, behind an EFI_CAPSULE_HEADER
//! (§8.5.3.1) and an EFI_JSON_CAPSULE_HEADER (§23.5.2), the bytes that UpdateCapsule() and Linux's
//! capsule loader take. The backends deliver them: capsule_loader.rs on Linux, capsule_services.rs
//! in the UEFI Shell. Also the EFI_JSON_CAPSULE_CONFIG_DATA (§23.5.2) of the firmware's JSON
//! configuration table, from a VendorTable of uefi_config_table.rs in the UEFI Shell.

#[cfg(configuration_tables)]
use anyhow::anyhow;
#[cfg(configuration_tables)]
use anyhow::Context;
#[cfg(configuration_tables)]
use anyhow::Result;
use thiserror::Error;

#[cfg(configuration_tables)]
use super::VendorTable;
use super::EFI_JSON_CAPSULE_ID_GUID;
#[cfg(configuration_tables)]
use crate::hii::package::Guid;

/// sizeof (EFI_CAPSULE_HEADER): CapsuleGuid, then the UINT32s HeaderSize, Flags and
/// CapsuleImageSize (UEFI 2.11 §8.5.3.1). A JSON capsule's HeaderSize, as its
/// EFI_JSON_CAPSULE_HEADER is "located at the lowest offset within the body" (§23.5.2).
const CAPSULE_HEADER_SIZE: u32 = 16 + 3 * 4;
/// sizeof (EFI_JSON_CAPSULE_HEADER) before its Payload: the UINT32s Version, CapsuleId and
/// PayloadLength (UEFI 2.11 §23.5.2).
const JSON_CAPSULE_HEADER_SIZE: u32 = 3 * 4;
/// EFI_JSON_CAPSULE_HEADER's Version, "initially 0x00000001" (UEFI 2.11 §23.5.2).
const JSON_CAPSULE_HEADER_VERSION: u32 = 1;
/// CAPSULE_FLAGS_PERSIST_ACROSS_RESET (UEFI 2.11 §8.5.3.1).
const CAPSULE_FLAGS_PERSIST_ACROSS_RESET: u32 = 0x0001_0000;
/// EFI_JSON_CONFIG_DATA_TABLE_GUID, the configuration table of the firmware's
/// EFI_JSON_CAPSULE_CONFIG_DATA (UEFI 2.11 §4.6.1.2, §23.5.2).
#[cfg(configuration_tables)]
pub(crate) const EFI_JSON_CONFIG_DATA_TABLE_GUID: Guid = Guid {
    data1: 0x8736_7f87,
    data2: 0x1119,
    data3: 0x41ce,
    data4: [0xaa, 0xec, 0x8b, 0xe0, 0x11, 0x1f, 0x55, 0x8a],
};
/// sizeof (EFI_JSON_CAPSULE_CONFIG_DATA) before its ConfigDataList: the UINT32s Version and
/// TotalLength (UEFI 2.11 §23.5.2).
#[cfg(configuration_tables)]
const CONFIG_DATA_HEADER_SIZE: usize = 2 * 4;
/// EFI_JSON_CAPSULE_CONFIG_DATA's Version, "initially 0x00000001" (UEFI 2.11 §23.5.2).
#[cfg(configuration_tables)]
const CONFIG_DATA_VERSION: u32 = 1;
/// sizeof (EFI_JSON_CONFIG_DATA_ITEM) before its ConfigData: the UINT32 ConfigDataLength (UEFI
/// 2.11 §23.5.2).
#[cfg(configuration_tables)]
const CONFIG_DATA_ITEM_HEADER_SIZE: usize = 4;

/// When the firmware processes a capsule: "If a capsule has the CAPSULE_FLAGS_PERSIST_ACROSS_RESET
/// Flag set in its header, the firmware will process the capsules after system reset. [...] If
/// this flag is not set, the firmware will process the capsules immediately." (UEFI 2.11
/// §8.5.3.1). A JSON capsule never has CAPSULE_FLAGS_POPULATE_SYSTEM_TABLE, which "must be 0"
/// (§23.5.3), nor CAPSULE_FLAGS_INITIATE_RESET, as uefisettings never resets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Processing {
    /// Before UpdateCapsule() returns, in boot services
    #[cfg_attr(
        all(target_os = "linux", not(test)),
        expect(
            dead_code,
            reason = "only the UEFI Shell build delivers for immediate processing"
        )
    )]
    Immediate,
    /// At the next reset: "firmware configuration and firmware update are not available in EFI
    /// runtime" (UEFI 2.11 §23.5.1)
    #[cfg_attr(
        all(target_os = "uefi", not(test)),
        expect(
            dead_code,
            reason = "only Linux's capsule loader delivers for after a reset"
        )
    )]
    AfterReset,
}

impl Processing {
    /// The Flags of an EFI_CAPSULE_HEADER that ask for this.
    fn flags(self) -> u32 {
        match self {
            Self::Immediate => 0,
            Self::AfterReset => CAPSULE_FLAGS_PERSIST_ACROSS_RESET,
        }
    }
}

/// A JSON capsule: an EFI_CAPSULE_HEADER, an EFI_JSON_CAPSULE_HEADER, then the payload as the
/// caller gave it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct JsonCapsule(Vec<u8>);

impl JsonCapsule {
    /// The capsule of `payload`, whose EFI_JSON_CAPSULE_HEADER carries `capsule_id`, for the
    /// firmware to process as `processing` says. An empty payload is refused: "A capsule in
    /// which PayloadLength is zero will not be processed." (UEFI 2.11 §23.5.3)
    pub(crate) fn new(
        payload: &[u8],
        capsule_id: u32,
        processing: Processing,
    ) -> Result<Self, PayloadError> {
        if payload.is_empty() {
            return Err(PayloadError::Empty);
        }
        let too_large = PayloadError::TooLarge(payload.len());
        let payload_length = u32::try_from(payload.len()).map_err(|_| too_large)?;
        let image_size = capsule_image_size(payload_length).ok_or(too_large)?;
        let fields = [
            CAPSULE_HEADER_SIZE,
            processing.flags(),
            image_size,
            JSON_CAPSULE_HEADER_VERSION,
            capsule_id,
            payload_length,
        ];

        let mut bytes = Vec::with_capacity(usize::try_from(image_size).map_err(|_| too_large)?);
        bytes.extend_from_slice(&<[u8; 16]>::from(EFI_JSON_CAPSULE_ID_GUID));
        bytes.extend(fields.iter().flat_map(|field| field.to_le_bytes()));
        bytes.extend_from_slice(payload);
        Ok(Self(bytes))
    }

    /// Its bytes, from its EFI_CAPSULE_HEADER on.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Its size, CapsuleImageSize: the bytes of its headers and payload.
    pub(crate) fn size(&self) -> usize {
        self.0.len()
    }
}

/// The CapsuleImageSize of a JSON capsule whose PayloadLength is `payload_length`, "Size in bytes
/// of the capsule (including capsule header)" (UEFI 2.11 §8.5.3.1), unless it overflows its
/// UINT32.
fn capsule_image_size(payload_length: u32) -> Option<u32> {
    payload_length.checked_add(CAPSULE_HEADER_SIZE + JSON_CAPSULE_HEADER_SIZE)
}

/// A payload that JsonCapsule::new refuses. The messages spell "section", as edk2's terminals
/// but VT-UTF8 show '?' for '§' (edk2-stable202508 TerminalDxe/TerminalConOut.c
/// TerminalConOutOutputString()).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum PayloadError {
    #[error(
        "the JSON payload is empty: \"A capsule in which PayloadLength is zero will not be \
         processed.\" (UEFI 2.11 section 23.5.3)"
    )]
    Empty,
    #[error(
        "a JSON payload of {0} bytes does not fit a capsule, whose size is a UINT32 (UEFI 2.11 \
         section 8.5.3.1)"
    )]
    TooLarge(usize),
}

/// EFI_RESET_TYPE (UEFI 2.11 §8.5.1.1), the reset that QueryCapsuleCapabilities() asks for: one
/// of the consts below, or a value that later specifications define.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResetType(pub u32);

impl ResetType {
    /// EfiResetCold
    pub const COLD: Self = Self(0);
    /// EfiResetWarm
    pub const WARM: Self = Self(1);
    /// EfiResetShutdown
    pub const SHUTDOWN: Self = Self(2);
    /// EfiResetPlatformSpecific
    pub const PLATFORM_SPECIFIC: Self = Self(3);
}

/// What QueryCapsuleCapabilities() tells of a capsule (UEFI 2.11 §8.5.3.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CapsuleCapabilities {
    /// MaximumCapsuleSize: the largest capsule that UpdateCapsule() takes, in bytes
    pub maximum_capsule_size: u64,
    /// ResetType: "the type of reset required for the capsule update"
    pub reset_type: ResetType,
}

/// The configuration data that the firmware reports in its JSON configuration table, an
/// EFI_JSON_CAPSULE_CONFIG_DATA (UEFI 2.11 §23.5.2).
#[cfg(configuration_tables)]
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct JsonConfigData {
    /// The ConfigData of each EFI_JSON_CONFIG_DATA_ITEM, in order: "the JSON payload that
    /// describes one group of configuration data", which uefisettings does not parse
    pub items: Vec<Vec<u8>>,
}

#[cfg(configuration_tables)]
impl JsonConfigData {
    /// The configuration data of `table`, an EFI_JSON_CAPSULE_CONFIG_DATA: it reads its Version
    /// and TotalLength, then its TotalLength bytes, which must hold its items whole.
    pub(crate) fn read(table: &impl VendorTable) -> Result<Self> {
        let header = table
            .read(CONFIG_DATA_HEADER_SIZE)
            .context("read the Version and TotalLength of the JSON configuration table")?;
        let [v0, v1, v2, v3, t0, t1, t2, t3] = <[u8; CONFIG_DATA_HEADER_SIZE]>::try_from(header)
            .map_err(|header| {
                anyhow!(
                    "read {} bytes of the JSON configuration table, not its Version and \
                     TotalLength",
                    header.len()
                )
            })?;
        let version = u32::from_le_bytes([v0, v1, v2, v3]);
        if version != CONFIG_DATA_VERSION {
            return Err(ConfigDataError::Version(version).into());
        }
        let total_length = u32::from_le_bytes([t0, t1, t2, t3]);
        let length = usize::try_from(total_length)?;
        if length < CONFIG_DATA_HEADER_SIZE {
            return Err(ConfigDataError::TotalLengthShort(total_length).into());
        }

        let table = table.read(length).with_context(|| {
            format!("read the TotalLength {total_length} bytes of the JSON configuration table")
        })?;
        Ok(Self {
            items: config_data_items(&table)?,
        })
    }
}

/// The ConfigData of the items of `table`, an EFI_JSON_CAPSULE_CONFIG_DATA of `table.len()`
/// bytes. UEFI 2.11 §23.5.2 packs only EFI_JSON_CAPSULE_CONFIG_DATA, but each item starts right
/// after the ConfigData of the one before, at any alignment, as edk2-stable202508 packs
/// EFI_JSON_CONFIG_DATA_ITEM too (MdePkg/Include/Guid/JsonCapsule.h).
#[cfg(configuration_tables)]
fn config_data_items(table: &[u8]) -> Result<Vec<Vec<u8>>, ConfigDataError> {
    let total_length = table.len();
    let mut items = Vec::new();
    let mut rest = table.get(CONFIG_DATA_HEADER_SIZE..).unwrap_or_default();
    while !rest.is_empty() {
        let offset = total_length - rest.len();
        let Some((length, data)) = rest.split_first_chunk::<CONFIG_DATA_ITEM_HEADER_SIZE>() else {
            return Err(ConfigDataError::TrailingBytes {
                total_length,
                count: rest.len(),
            });
        };
        let length = u32::from_le_bytes(*length);
        let (item, next) = usize::try_from(length)
            .ok()
            .and_then(|length| data.split_at_checked(length))
            .ok_or(ConfigDataError::ItemPastTotalLength {
                offset,
                length,
                total_length,
            })?;
        items.push(item.to_vec());
        rest = next;
    }
    Ok(items)
}

/// An EFI_JSON_CAPSULE_CONFIG_DATA that JsonConfigData::read refuses. The messages spell
/// "section", as PayloadError's do.
#[cfg(configuration_tables)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum ConfigDataError {
    #[error(
        "the JSON configuration table's Version is {0}, not the {CONFIG_DATA_VERSION} that \
         uefisettings reads: \"Version of the structure, initially 0x00000001\" (UEFI 2.11 \
         section 23.5.2)"
    )]
    Version(u32),
    #[error(
        "the JSON configuration table's TotalLength {0} is less than the {CONFIG_DATA_HEADER_SIZE} \
         bytes of its Version and TotalLength (UEFI 2.11 section 23.5.2)"
    )]
    TotalLengthShort(u32),
    #[error(
        "the item at offset {offset} of the JSON configuration table has a ConfigDataLength of \
         {length}, which runs its ConfigData past the table's TotalLength {total_length} (UEFI \
         2.11 section 23.5.2)"
    )]
    ItemPastTotalLength {
        offset: usize,
        length: u32,
        total_length: usize,
    },
    #[error(
        "the JSON configuration table's TotalLength {total_length} leaves {count} bytes after its \
         Version, TotalLength and items, too few for a ConfigDataLength (UEFI 2.11 section \
         23.5.2)"
    )]
    TrailingBytes { total_length: usize, count: usize },
}

/// VendorTables for the tests of the JSON configuration table.
#[cfg(all(configuration_tables, test))]
pub(super) mod fixture {
    use std::cell::RefCell;

    use anyhow::anyhow;
    use anyhow::Result;

    use crate::efi_variables::VendorTable;
    use crate::firmware_width::FirmwareWidth;

    /// A table at the start of a memory region of `region`, which records the length of each
    /// read and refuses reads past the region's end, listed by firmware of `width`.
    #[derive(Debug)]
    pub(in crate::efi_variables) struct TableInRegion {
        region: Vec<u8>,
        width: FirmwareWidth,
        pub(in crate::efi_variables) reads: RefCell<Vec<usize>>,
    }

    impl TableInRegion {
        /// The table `region` of 64-bit firmware.
        pub(in crate::efi_variables) fn new(region: Vec<u8>) -> Self {
            Self::of_width(region, FirmwareWidth::Bits64)
        }

        pub(in crate::efi_variables) fn of_width(region: Vec<u8>, width: FirmwareWidth) -> Self {
            Self {
                region,
                width,
                reads: RefCell::default(),
            }
        }
    }

    impl VendorTable for TableInRegion {
        fn read(&self, len: usize) -> Result<Vec<u8>> {
            self.reads.borrow_mut().push(len);
            self.region.get(..len).map(<[u8]>::to_vec).ok_or_else(|| {
                anyhow!(
                    "{len} bytes run past the region of {} bytes",
                    self.region.len()
                )
            })
        }

        fn firmware_width(&self) -> FirmwareWidth {
            self.width
        }
    }

    /// An EFI_JSON_CAPSULE_CONFIG_DATA of `version` and `total_length`, then `list`.
    pub(in crate::efi_variables) fn config_data(
        version: u32,
        total_length: u32,
        list: &[u8],
    ) -> Vec<u8> {
        [
            &version.to_le_bytes()[..],
            &total_length.to_le_bytes(),
            list,
        ]
        .concat()
    }

    /// The EFI_JSON_CONFIG_DATA_ITEM of `data`.
    pub(in crate::efi_variables) fn item(data: &[u8]) -> Vec<u8> {
        let length = u32::try_from(data.len()).expect("a UINT32 ConfigDataLength");
        [&length.to_le_bytes()[..], data].concat()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The capsule of the payload b"{}" with CapsuleId 0x01020304, without its Flags (bytes
    /// 20-23) and as the specification lays it out, field by field, little-endian.
    const CAPSULE_OF_BRACES: [u8; 42] = [
        // CapsuleGuid: 67D6F4CD-D6B8-4573-BF4A-DE5E252D61AE, Data1-Data3 little-endian
        0xcd, 0xf4, 0xd6, 0x67, 0xb8, 0xd6, 0x73, 0x45, 0xbf, 0x4a, 0xde, 0x5e, 0x25, 0x2d, 0x61,
        0xae, //
        // HeaderSize: 28
        28, 0, 0, 0, //
        // Flags: the test sets them
        0, 0, 0, 0, //
        // CapsuleImageSize: 28 + 12 + 2
        42, 0, 0, 0, //
        // Version: 1
        1, 0, 0, 0, //
        // CapsuleId
        0x04, 0x03, 0x02, 0x01, //
        // PayloadLength: 2
        2, 0, 0, 0, //
        // Payload
        b'{', b'}',
    ];

    /// Each processing has the header bytes of the specification, with only
    /// CAPSULE_FLAGS_PERSIST_ACROSS_RESET of the flags, and that only after a reset.
    #[test]
    fn json_capsules_have_the_header_bytes_of_the_specification() {
        for (processing, flags) in [
            (Processing::Immediate, [0, 0, 0, 0]),
            (Processing::AfterReset, [0, 0, 1, 0]),
        ] {
            let mut want = CAPSULE_OF_BRACES;
            want[20..24].copy_from_slice(&flags);

            let capsule = JsonCapsule::new(b"{}", 0x0102_0304, processing).expect("make a capsule");

            assert_eq!(capsule.as_bytes(), want, "{processing:?}");
            assert_eq!(capsule.size(), want.len(), "{processing:?}");
        }
    }

    /// No capsule has CAPSULE_FLAGS_POPULATE_SYSTEM_TABLE (0x00020000),
    /// CAPSULE_FLAGS_INITIATE_RESET (0x00040000) or a flag of its CapsuleGuid's (Flags[15:0]).
    #[test]
    fn json_capsules_never_populate_the_system_table_or_initiate_a_reset() {
        for processing in [Processing::Immediate, Processing::AfterReset] {
            let capsule = JsonCapsule::new(b"[]", 0, processing).expect("make a capsule");
            let flags = capsule
                .as_bytes()
                .get(20..24)
                .and_then(|flags| <[u8; 4]>::try_from(flags).ok())
                .map(u32::from_le_bytes)
                .expect("the Flags of the capsule");

            assert_eq!(
                flags & !CAPSULE_FLAGS_PERSIST_ACROSS_RESET,
                0,
                "{processing:?}: flags {flags:#010x}"
            );
        }
    }

    /// The payload follows the headers byte for byte, every byte value and a CapsuleId of
    /// u32::MAX included, and CapsuleImageSize and PayloadLength count it.
    #[test]
    fn json_capsules_carry_the_payload_unchanged() {
        let payload: Vec<u8> = (0..=255).cycle().take(5000).collect();

        let capsule =
            JsonCapsule::new(&payload, u32::MAX, Processing::AfterReset).expect("make a capsule");

        let bytes = capsule.as_bytes();
        assert_eq!(bytes.get(40..), Some(&payload[..]), "payload");
        assert_eq!(bytes.get(24..28), Some(&5040u32.to_le_bytes()[..]), "size");
        assert_eq!(bytes.get(32..36), Some(&[0xff; 4][..]), "CapsuleId");
        assert_eq!(
            bytes.get(36..40),
            Some(&5000u32.to_le_bytes()[..]),
            "length"
        );
    }

    /// An empty payload makes no capsule, while one of a single byte makes one.
    #[test]
    fn an_empty_payload_makes_no_capsule() {
        for processing in [Processing::Immediate, Processing::AfterReset] {
            assert_eq!(
                JsonCapsule::new(b"", 1, processing),
                Err(PayloadError::Empty),
                "{processing:?}"
            );
            assert_eq!(
                JsonCapsule::new(b"0", 1, processing).map(|capsule| capsule.size()),
                Ok(41),
                "{processing:?}: one byte"
            );
        }
        assert_eq!(
            PayloadError::Empty.to_string(),
            "the JSON payload is empty: \"A capsule in which PayloadLength is zero will not be \
             processed.\" (UEFI 2.11 section 23.5.3)",
            "message"
        );
    }

    /// CapsuleImageSize counts the 40 bytes of the headers, up to u32::MAX, past which there is
    /// none.
    #[test]
    fn capsule_image_size_is_a_uint32() {
        for (payload_length, want) in [
            (1, Some(41)),
            (u32::MAX - 40, Some(u32::MAX)),
            (u32::MAX - 39, None),
            (u32::MAX, None),
        ] {
            assert_eq!(capsule_image_size(payload_length), want, "{payload_length}");
        }
        assert_eq!(
            PayloadError::TooLarge(4_294_967_257).to_string(),
            "a JSON payload of 4294967257 bytes does not fit a capsule, whose size is a UINT32 \
             (UEFI 2.11 section 8.5.3.1)",
            "message"
        );
    }

    /// JsonConfigData reads the items of the ConfigDataList back to back, the next item right
    /// after the ConfigData of the one before, whatever their lengths: JSON text of 7 bytes, an
    /// empty item, then bytes that are no UTF-8.
    #[cfg(configuration_tables)]
    #[test]
    fn json_config_data_reads_its_items_back_to_back() {
        let list = [
            fixture::item(br#"{"a":1}"#),
            fixture::item(b""),
            fixture::item(&[0xff, 0x00, 0x80]),
        ]
        .concat();
        let table = fixture::TableInRegion::new(fixture::config_data(1, 30, &list));

        let data = JsonConfigData::read(&table).expect("read the table");

        assert_eq!(
            data.items,
            [br#"{"a":1}"#.to_vec(), Vec::new(), vec![0xff, 0x00, 0x80]],
            "items"
        );
        assert_eq!(table.reads.into_inner(), [8, 30], "reads");
    }

    /// JsonConfigData reads the Version and TotalLength, then the TotalLength bytes, and never
    /// what the region holds past them.
    #[cfg(configuration_tables)]
    #[test]
    fn json_config_data_reads_only_its_total_length() {
        for (case, region, want, total_length) in [
            ("no items", fixture::config_data(1, 8, &[]), Vec::new(), 8),
            (
                "an item, then one past TotalLength",
                fixture::config_data(
                    1,
                    15,
                    &[fixture::item(b"abc"), fixture::item(b"past")].concat(),
                ),
                vec![b"abc".to_vec()],
                15,
            ),
        ] {
            let table = fixture::TableInRegion::new(region);

            let data =
                JsonConfigData::read(&table).unwrap_or_else(|error| panic!("{case}: {error:#}"));

            assert_eq!(data.items, want, "{case}");
            assert_eq!(table.reads.into_inner(), [8, total_length], "{case}: reads");
        }
    }

    /// JsonConfigData refuses a Version but 1, a TotalLength short of its header, an item past
    /// TotalLength and 1-3 bytes after the last item, which hold no ConfigDataLength; it reads
    /// nothing past the header of a header that it refuses.
    #[cfg(configuration_tables)]
    #[test]
    fn json_config_data_refuses_what_the_specification_does_not_lay_out() {
        let past_item = [&5u32.to_le_bytes()[..], b"abcde"].concat();
        let past_second = [fixture::item(b"x"), u32::MAX.to_le_bytes().to_vec()].concat();
        for (case, region, want, reads) in [
            (
                "Version 2",
                fixture::config_data(2, 8, &[]),
                ConfigDataError::Version(2),
                &[8][..],
            ),
            (
                "Version 0",
                fixture::config_data(0, 8, &[]),
                ConfigDataError::Version(0),
                &[8],
            ),
            (
                "TotalLength 7",
                fixture::config_data(1, 7, &[]),
                ConfigDataError::TotalLengthShort(7),
                &[8],
            ),
            (
                "TotalLength 0",
                fixture::config_data(1, 0, &[]),
                ConfigDataError::TotalLengthShort(0),
                &[8],
            ),
            (
                "an item one byte past TotalLength, which the region holds",
                fixture::config_data(1, 16, &past_item),
                ConfigDataError::ItemPastTotalLength {
                    offset: 8,
                    length: 5,
                    total_length: 16,
                },
                &[8, 16],
            ),
            (
                "a second item of ConfigDataLength u32::MAX",
                fixture::config_data(1, 17, &past_second),
                ConfigDataError::ItemPastTotalLength {
                    offset: 13,
                    length: u32::MAX,
                    total_length: 17,
                },
                &[8, 17],
            ),
            (
                "1 byte after the last item",
                fixture::config_data(1, 14, &[fixture::item(b"x"), vec![0]].concat()),
                ConfigDataError::TrailingBytes {
                    total_length: 14,
                    count: 1,
                },
                &[8, 14],
            ),
            (
                "2 bytes after the last item",
                fixture::config_data(1, 15, &[fixture::item(b"x"), vec![0; 2]].concat()),
                ConfigDataError::TrailingBytes {
                    total_length: 15,
                    count: 2,
                },
                &[8, 15],
            ),
            (
                "3 bytes after the last item",
                fixture::config_data(1, 16, &[fixture::item(b"x"), vec![0; 3]].concat()),
                ConfigDataError::TrailingBytes {
                    total_length: 16,
                    count: 3,
                },
                &[8, 16],
            ),
        ] {
            let table = fixture::TableInRegion::new(region);

            let error = JsonConfigData::read(&table).expect_err(case);

            assert_eq!(
                error.downcast_ref::<ConfigDataError>(),
                Some(&want),
                "{case}: {error:#}"
            );
            assert_eq!(table.reads.into_inner(), reads, "{case}: reads");
        }
    }

    /// JsonConfigData refuses a header or a TotalLength past the region that holds the table,
    /// naming what it read.
    #[cfg(configuration_tables)]
    #[test]
    fn json_config_data_refuses_a_table_past_its_region() {
        for (case, region, want) in [
            (
                "a region of 4 bytes",
                vec![1, 0, 0, 0],
                "read the Version and TotalLength of the JSON configuration table: 8 bytes run \
                 past the region of 4 bytes",
            ),
            (
                "TotalLength 64 in a region of 13 bytes",
                fixture::config_data(1, 64, &fixture::item(b"x")),
                "read the TotalLength 64 bytes of the JSON configuration table: 64 bytes run past \
                 the region of 13 bytes",
            ),
        ] {
            let error = JsonConfigData::read(&fixture::TableInRegion::new(region)).expect_err(case);

            assert_eq!(format!("{error:#}"), want, "{case}");
        }
    }

    #[cfg(configuration_tables)]
    #[test]
    fn config_data_errors_name_the_field_and_the_section() {
        for (error, want) in [
            (
                ConfigDataError::Version(2),
                "the JSON configuration table's Version is 2, not the 1 that uefisettings reads: \
                 \"Version of the structure, initially 0x00000001\" (UEFI 2.11 section 23.5.2)",
            ),
            (
                ConfigDataError::TotalLengthShort(7),
                "the JSON configuration table's TotalLength 7 is less than the 8 bytes of its \
                 Version and TotalLength (UEFI 2.11 section 23.5.2)",
            ),
            (
                ConfigDataError::ItemPastTotalLength {
                    offset: 13,
                    length: 5,
                    total_length: 16,
                },
                "the item at offset 13 of the JSON configuration table has a ConfigDataLength of \
                 5, which runs its ConfigData past the table's TotalLength 16 (UEFI 2.11 section \
                 23.5.2)",
            ),
            (
                ConfigDataError::TrailingBytes {
                    total_length: 16,
                    count: 3,
                },
                "the JSON configuration table's TotalLength 16 leaves 3 bytes after its Version, \
                 TotalLength and items, too few for a ConfigDataLength (UEFI 2.11 section 23.5.2)",
            ),
        ] {
            assert_eq!(error.to_string(), want, "{error:?}");
        }
    }
}
