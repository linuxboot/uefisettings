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

//! The Messaging Device Path nodes of networks (UEFI 2.11 §10.3.4) of named forms in Table
//! 10.67: InfiniBand, MAC Address, IPv4, IPv6, VLAN, URI, Bluetooth, Wi-Fi, BluetoothLE, DNS and
//! REST Service.

use super::parameters::ascii_text;
use super::parameters::ipv4;
use super::parameters::ipv4_text;
use super::parameters::ipv6;
use super::parameters::ipv6_text;
use super::parameters::keyword_or_integer;
use super::parameters::upper_hex;
use super::parameters::Parameters;
use super::DevicePathTextError;
use super::Fields;

/// The Sub-Types of UEFI 2.11 §10.3.4
pub(super) const INFINIBAND: u8 = 0x09;
pub(super) const MAC_ADDRESS: u8 = 0x0B;
pub(super) const IPV4: u8 = 0x0C;
pub(super) const IPV6: u8 = 0x0D;
pub(super) const VLAN: u8 = 0x14;
pub(super) const URI: u8 = 0x18;
pub(super) const BLUETOOTH: u8 = 0x1B;
pub(super) const WIFI: u8 = 0x1C;
pub(super) const BLUETOOTH_LE: u8 = 0x1E;
pub(super) const DNS: u8 = 0x1F;
pub(super) const REST_SERVICE: u8 = 0x21;

/// The MAC Address field of a MAC Address node, padded with zeros (UEFI 2.11 §10.3.4.10)
const MAC_ADDRESS_SIZE: usize = 32;
/// The IfTypes whose MAC address is 6 bytes long (UEFI 2.11 Table 10.67)
const SIX_BYTE_IF_TYPES: [u8; 2] = [0, 1];
/// The data of the IPv4 and IPv6 nodes of UEFI 2.11, with their gateway fields; edk2's
/// DevPathToTextIPv4() and DevPathToTextIPv6() write those only for nodes this long
const IPV4_SIZE: usize = 23;
const IPV6_SIZE: usize = 56;
/// The Protocol keywords of RFC 1700 (UEFI 2.11 Table 10.67), UDP if omitted
const PROTOCOLS: [(&str, u16); 2] = [("UDP", 17), ("TCP", 6)];
const UDP: u16 = 17;
/// The IPv4 Type keywords, DHCP if omitted
const IPV4_TYPES: [(&str, u8); 2] = [("Static", 1), ("DHCP", 0)];
/// The IPv6 IPAddressOrigin keywords; edk2 writes StatefulAutoConfigure for any value above 1,
/// and reads an omitted one as it
const IPV6_ORIGINS: [(&str, u8); 3] = [
    ("Static", 0),
    ("StatelessAutoConfigure", 1),
    ("StatefulAutoConfigure", 2),
];
const STATEFUL_AUTO_CONFIGURE: u8 = 2;
/// An EFI_IP_ADDRESS of a DNS node, which holds an IPv4 address in its first 4 bytes
const IP_ADDRESS_SIZE: usize = 16;
/// The SSId of a Wi-Fi node
const SSID_SIZE: usize = 32;
/// The REST Service of a vendor-specific REST Service node (UEFI 2.11 Table 10.51)
const VENDOR_REST_SERVICE: u8 = 0xFF;

/// Infiniband(Flags,Guid,ServiceId,TargetId,DeviceId), the port GID written as a GUID.
pub(super) fn infiniband_text(data: &[u8]) -> Option<String> {
    let mut fields = Fields(data);
    let (flags, gid) = (fields.u32()?, fields.guid()?);
    let (service, target, device) = (fields.u64()?, fields.u64()?, fields.u64()?);
    Some(format!(
        "Infiniband(0x{flags:X},{gid},0x{service:X},0x{target:X},0x{device:X})"
    ))
}

pub(super) fn infiniband(p: &mut Parameters<'_>) -> Result<Vec<u8>, DevicePathTextError> {
    let flags: u32 = p.integer()?;
    let gid = p.guid()?;
    let ids: [u64; 3] = [p.integer()?, p.integer()?, p.integer()?];
    Ok([
        &flags.to_le_bytes()[..],
        &gid,
        &ids.map(u64::to_le_bytes).concat(),
    ]
    .concat())
}

/// MAC(MacAddr,IfType): the 6 bytes of the address for IfType 0 and 1, else all 32.
pub(super) fn mac_text(data: &[u8]) -> Option<String> {
    let mut fields = Fields(data);
    let address = fields.take::<MAC_ADDRESS_SIZE>()?;
    let if_type = fields.u8()?;
    let shown = match SIX_BYTE_IF_TYPES.contains(&if_type) {
        true => address.get(..6)?,
        false => &address[..],
    };
    Some(format!("MAC({},0x{if_type:X})", upper_hex(shown)))
}

/// MAC(MacAddr,IfType), IfType 0 if omitted; the address exactly as long as mac_text writes it.
pub(super) fn mac(p: &mut Parameters<'_>, text: &str) -> Result<Vec<u8>, DevicePathTextError> {
    let mut data = p.hex()?;
    let if_type: u8 = p.integer_or(0)?;
    let shown = match SIX_BYTE_IF_TYPES.contains(&if_type) {
        true => 6,
        false => MAC_ADDRESS_SIZE,
    };
    if data.len() != shown {
        return Err(DevicePathTextError::Value(text.to_owned()));
    }
    data.resize(MAC_ADDRESS_SIZE, 0);
    data.push(if_type);
    Ok(data)
}

/// The Protocol as edk2's CatNetworkProtocol() writes it.
fn protocol_text(protocol: u16) -> String {
    match PROTOCOLS.iter().find(|(_, value)| *value == protocol) {
        Some((name, _)) => (*name).to_owned(),
        None => format!("0x{protocol:X}"),
    }
}

/// The Protocol, UDP if omitted, as Table 10.67 gives it: edk2 reads an omitted one as 0.
fn protocol(p: &mut Parameters<'_>) -> Result<u16, DevicePathTextError> {
    p.optional()
        .map_or(Ok(UDP), |text| keyword_or_integer(text, &PROTOCOLS))
}

/// IPv4(RemoteIp,Protocol,Type,LocalIp,GatewayIPAddress,SubnetMask), of LocalIp, RemoteIp,
/// LocalPort, RemotePort, Protocol, StaticIpAddress, GatewayIpAddress and SubnetMask; the ports
/// have no text, and a node without the last two writes none of them, as edk2 writes it.
pub(super) fn ipv4_text_of(data: &[u8]) -> Option<String> {
    let mut fields = Fields(data);
    let (local, remote) = (fields.take::<4>()?, fields.take::<4>()?);
    let _ports = (fields.u16()?, fields.u16()?);
    let (protocol, static_address) = (fields.u16()?, fields.u8()?);
    let kind = if static_address != 0 {
        "Static"
    } else {
        "DHCP"
    };
    let mut text = format!(
        "IPv4({},{},{kind},{}",
        ipv4_text(remote),
        protocol_text(protocol),
        ipv4_text(local)
    );
    if data.len() == IPV4_SIZE {
        let (gateway, mask) = (fields.take::<4>()?, fields.take::<4>()?);
        text.push_str(&format!(",{},{}", ipv4_text(gateway), ipv4_text(mask)));
    }
    text.push(')');
    Some(text)
}

/// IPv4(…): the Protocol UDP, the Type DHCP and the other addresses all zeros if omitted, each
/// alone as Table 10.67 gives them, where edk2 zeros GatewayIPAddress and SubnetMask unless both
/// are given; RemoteIp and LocalIp may hold their port, as Table 10.66 writes an IPv4 Address.
pub(super) fn ipv4_node(p: &mut Parameters<'_>) -> Result<Vec<u8>, DevicePathTextError> {
    let remote = ipv4(p.next(), true)?;
    let protocol = protocol(p)?;
    let static_address = p.keyword_or(&IPV4_TYPES, 0)?;
    let local = p.ipv4_or_zero(true)?;
    let (gateway, mask) = (p.ipv4_or_zero(false)?, p.ipv4_or_zero(false)?);
    let data = [
        &local.address[..],
        &remote.address,
        &local.port.to_le_bytes(),
        &remote.port.to_le_bytes(),
        &protocol.to_le_bytes(),
        &[static_address],
        &gateway.address,
        &mask.address,
    ];
    Ok(data.concat())
}

/// IPv6(RemoteIp,Protocol,IPAddressOrigin,LocalIp,PrefixLength,GatewayIPAddress), of LocalIp,
/// RemoteIp, LocalPort, RemotePort, Protocol, IpAddressOrigin, PrefixLength and
/// GatewayIpAddress; the ports have no text, and a node without the last two writes none of
/// them, as edk2 writes it.
pub(super) fn ipv6_text_of(data: &[u8]) -> Option<String> {
    let mut fields = Fields(data);
    let (local, remote) = (fields.take::<16>()?, fields.take::<16>()?);
    let _ports = (fields.u16()?, fields.u16()?);
    let (protocol, origin) = (fields.u16()?, fields.u8()?);
    let origin = match origin {
        0 => "Static",
        1 => "StatelessAutoConfigure",
        _ => "StatefulAutoConfigure",
    };
    let mut text = format!(
        "IPv6({},{},{origin},{}",
        ipv6_text(remote),
        protocol_text(protocol),
        ipv6_text(local)
    );
    if data.len() == IPV6_SIZE {
        let (prefix, gateway) = (fields.u8()?, fields.take::<16>()?);
        text.push_str(&format!(",0x{prefix:X},{}", ipv6_text(gateway)));
    }
    text.push(')');
    Some(text)
}

/// IPv6(…): the Protocol UDP, the IPAddressOrigin StatefulAutoConfigure as edk2 reads it, the
/// PrefixLength 0 and the other addresses all zeros if omitted, each alone as Table 10.67 gives
/// them, where edk2 zeros PrefixLength and GatewayIPAddress unless both are given; RemoteIp and
/// LocalIp may hold their port, as Table 10.66 writes an IPv6 Address.
pub(super) fn ipv6_node(p: &mut Parameters<'_>) -> Result<Vec<u8>, DevicePathTextError> {
    let remote = ipv6(p.next(), true)?;
    let protocol = protocol(p)?;
    let origin = p.keyword_or(&IPV6_ORIGINS, STATEFUL_AUTO_CONFIGURE)?;
    let local = p.ipv6_or_zero(true)?;
    let prefix: u8 = p.integer_or(0)?;
    let gateway = p.ipv6_or_zero(false)?;
    let data = [
        &local.address[..],
        &remote.address,
        &local.port.to_le_bytes(),
        &remote.port.to_le_bytes(),
        &protocol.to_le_bytes(),
        &[origin, prefix],
        &gateway.address,
    ];
    Ok(data.concat())
}

/// Vlan(VlanId), in decimal as edk2 writes it.
pub(super) fn vlan_text(data: &[u8]) -> Option<String> {
    Some(format!("Vlan({})", Fields(data).u16()?))
}

pub(super) fn vlan(p: &mut Parameters<'_>) -> Result<Vec<u8>, DevicePathTextError> {
    Ok(p.integer::<u16>()?.to_le_bytes().to_vec())
}

/// Uri(Uri), of ASCII, as edk2 writes each byte as a character and reads each character back as
/// a byte.
pub(super) fn uri_text(data: &[u8]) -> Option<String> {
    Some(format!("Uri({})", ascii_text(data)?))
}

pub(super) fn uri(p: &mut Parameters<'_>) -> Result<Vec<u8>, DevicePathTextError> {
    Ok(p.ascii()?.as_bytes().to_vec())
}

pub(super) fn bluetooth_text(data: &[u8]) -> Option<String> {
    Some(format!(
        "Bluetooth({})",
        upper_hex(&Fields(data).take::<6>()?)
    ))
}

pub(super) fn bluetooth(p: &mut Parameters<'_>) -> Result<Vec<u8>, DevicePathTextError> {
    Ok(p.hex_array::<6>()?.to_vec())
}

/// Wi-Fi(SSID): the SSId up to its first Null, as edk2 writes it.
pub(super) fn wifi_text(data: &[u8]) -> Option<String> {
    let ssid = Fields(data).take::<SSID_SIZE>()?;
    let length = ssid.iter().position(|byte| *byte == 0).unwrap_or(SSID_SIZE);
    Some(format!("Wi-Fi({})", ascii_text(ssid.get(..length)?)?))
}

/// Wi-Fi(SSID): ASCII, padded with Null to its 32 bytes; a longer one, which edk2 cuts, is
/// refused.
pub(super) fn wifi(p: &mut Parameters<'_>) -> Result<Vec<u8>, DevicePathTextError> {
    let mut ssid = p.ascii_up_to(SSID_SIZE)?.as_bytes().to_vec();
    ssid.resize(SSID_SIZE, 0);
    Ok(ssid)
}

pub(super) fn bluetooth_le_text(data: &[u8]) -> Option<String> {
    let mut fields = Fields(data);
    let (address, address_type) = (fields.take::<6>()?, fields.u8()?);
    Some(format!(
        "BluetoothLE({},0x{address_type:02X})",
        upper_hex(&address)
    ))
}

pub(super) fn bluetooth_le(p: &mut Parameters<'_>) -> Result<Vec<u8>, DevicePathTextError> {
    let address = p.hex_array::<6>()?;
    Ok([&address[..], &[p.integer()?]].concat())
}

/// Dns(DnsServerIp,…), IPv4 addresses if IsIPv6 is 0, else IPv6 ones, as edk2 writes them.
pub(super) fn dns_text(data: &[u8]) -> Option<String> {
    let (&is_ipv6, addresses) = data.split_first()?;
    let (addresses, []) = addresses.as_chunks::<IP_ADDRESS_SIZE>() else {
        return None;
    };
    let addresses: Vec<String> = addresses
        .iter()
        .map(|address| match is_ipv6 {
            0 => address
                .first_chunk::<4>()
                .map(|address| ipv4_text(*address)),
            _ => Some(ipv6_text(*address)),
        })
        .collect::<Option<_>>()?;
    (!addresses.is_empty()).then(|| format!("Dns({})", addresses.join(",")))
}

/// Dns(DnsServerIp,…): one or more, all IPv4 if the first is, else all IPv6. edk2 writes no
/// node for none.
pub(super) fn dns(p: &mut Parameters<'_>, text: &str) -> Result<Vec<u8>, DevicePathTextError> {
    let addresses: Vec<&str> = p.rest().collect();
    let first = addresses
        .first()
        .ok_or_else(|| DevicePathTextError::EmptyList(text.to_owned()))?;
    let is_ipv6 = u8::from(ipv4(first, false).is_err());
    let addresses = addresses
        .iter()
        .map(|address| dns_address(address, is_ipv6))
        .collect::<Result<Vec<_>, _>>()?;
    Ok([vec![is_ipv6], addresses.concat()].concat())
}

/// A DNS server's EFI_IP_ADDRESS: an IPv6 address if `is_ipv6` is set, else an IPv4 one padded
/// with zeros.
fn dns_address(text: &str, is_ipv6: u8) -> Result<Vec<u8>, DevicePathTextError> {
    match is_ipv6 {
        0 => ipv4(text, false).map(|ip| [&ip.address[..], &[0; IP_ADDRESS_SIZE - 4]].concat()),
        _ => ipv6(text, false).map(|ip| ip.address.to_vec()),
    }
}

/// RestService(RestExServiceType,AccessMode), or for the vendor-specific 0xFF
/// RestService(RestExServiceType,AccessMode,VendorRestServiceGuid,VendorDefinedData), as Table
/// 10.67 gives them: edk2 has no form for them. The integers are decimal, as in the example of
/// UEFI 2.11 §10.3.4.31; the data is a Hex Dump, none if omitted, as a Vendor node's.
pub(super) fn rest_service_text(data: &[u8]) -> Option<String> {
    let mut fields = Fields(data);
    let (service, mode) = (fields.u8()?, fields.u8()?);
    match (service, fields.0) {
        (VENDOR_REST_SERVICE, _) => {
            let vendor = fields.guid()?;
            Some(match fields.0 {
                [] => format!("RestService({service},{mode},{vendor})"),
                defined => format!(
                    "RestService({service},{mode},{vendor},{})",
                    upper_hex(defined)
                ),
            })
        }
        (_, []) => Some(format!("RestService({service},{mode})")),
        (_, _) => None,
    }
}

pub(super) fn rest_service(p: &mut Parameters<'_>) -> Result<Vec<u8>, DevicePathTextError> {
    let (service, mode): (u8, u8) = (p.integer()?, p.integer()?);
    let vendor = match service {
        VENDOR_REST_SERVICE => [&p.guid()?[..], &p.hex()?].concat(),
        _ => Vec::new(),
    };
    Ok([&[service, mode][..], &vendor].concat())
}
