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

use std::ffi::CStr;
use std::ffi::CString;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use binrw::io::Cursor;
use binrw::BinRead;
use binrw::BinReaderExt;
use log::debug;
use rand::distributions::Alphanumeric;
use rand::thread_rng;
use rand::Rng;

use crate::ilorest::chif::IloRestChif;
use crate::ilorest::chif::IloRestChifInterface;

enum BlobStoreReturnCode {
    Success = 0,
    // BadParameter = 2,
    // NotFound = 12,
    NotModified = 20,
}

enum ResponseReceiveMode {
    ImmediateResponse = 0,
    FragmentedResponse = 1,
}

/// Transport uses the rust bindings to ilorest_chif.so to handle Blobstore2 logic
/// so the user can make requests without worrying about fragmented reads/writes, packet handling, etc.
/// Usage:
/// ```no_run
/// let lib = get_lib("/usr/lib64/ilorest_chif.so")?;
/// let ilo = IloRestChif::new(&lib)?;
/// let transport = Transport::new(&ilo)?;
/// let response = transport.make_request(request_bytes)?;
/// ```

pub struct Transport<'a> {
    ilo: &'a IloRestChif<'a>,
}

impl<'a> Transport<'a> {
    pub fn new(ilo: &'a IloRestChif) -> Result<Self> {
        Ok(Self { ilo })
    }

    /// make_request isn't really a REST request, it just receives some bytes,
    /// sends them to the ilo BMC using Blobstore2 transport logic
    /// and returns bytes
    pub fn make_request(&self, request: &[u8]) -> Result<Vec<u8>> {
        let request_key = CString::new(gen_random_str(10))?;
        let response_key = CString::new(gen_random_str(10))?;
        let namespace = CString::new("volatile")?;

        let rest_resp;

        if (request.len() as u32)
            < (self.ilo.get_max_write_size() + self.ilo.get_immediate_request_size())
        {
            // No need to create a keyval store entry, we can send it directly

            debug!("Sending request using a direct/single-packet write");

            let header_template =
                self.ilo
                    .prepare_immediate_request(request.len() as u32, &response_key, &namespace);

            let mut packet_to_send = Vec::from(header_template);
            packet_to_send.append(&mut request.to_owned());

            rest_resp = self
                .exchange_packet(&packet_to_send)
                .context("Failed to get rest response")?;
        } else {
            debug!("Sending request using a multi-packet write");

            self.create_blob_entry(&request_key, &namespace)?;

            self.write_multi_packet(request, &request_key, &namespace)?;

            self.finalize_multi_packet_write(&request_key, &namespace)?;

            let header_template =
                self.ilo
                    .prepare_blob_request(&request_key, &response_key, &namespace);

            let packet_to_send = Vec::from(header_template);

            rest_resp = self
                .exchange_packet(&packet_to_send)
                .context("Failed to get rest response")?;
        }

        let mut rest_resp_cursor = Cursor::new(&rest_resp);
        let parsed_rest_resp: IloFixedResponse = rest_resp_cursor.read_le()?;

        if parsed_rest_resp.receive_mode == ResponseReceiveMode::FragmentedResponse as u32 {
            debug!("Receive Mode is 1 - FragmentedResponse");
            // Receive Mode 1 means that the data will be saved in the key-val store and we should use rsp_key to fetch it

            let blobsize = self.get_blob_size(&response_key, &namespace)?;

            let read_bytes = self.read_multi_packet(blobsize, &response_key, &namespace)?;

            // HP's CLI tool deletes this response blob even though it is in the `volatile` blobs namespace.
            // Note that it only deletes the response blob and not the request blob.
            // We will emulate this behavior.
            self.delete_blob_entry(&response_key, &namespace)?;

            return Ok(read_bytes);
        } else if parsed_rest_resp.receive_mode == ResponseReceiveMode::ImmediateResponse as u32 {
            debug!("Receive Mode is 0 - ImmediateResponse");
            // Receive Mode 0 means the data is part of rest response itself

            let rest_response_fixed_size = self.ilo.get_rest_response_fixed_size();

            rest_resp_cursor.seek(SeekFrom::Start(rest_response_fixed_size.into()))?;

            let mut read_bytes =
                vec![0u8; rest_response_fixed_size as usize + parsed_rest_resp.data_len as usize];
            rest_resp_cursor.read_exact(&mut read_bytes)?;

            return Ok(read_bytes);
        }

        Err(anyhow!("Got invalid Receive Mode in RestResponseFixed"))
    }

    fn read_multi_packet(
        &self,

        data_length: u32,
        response_key: &CStr,
        namespace: &CStr,
    ) -> Result<Vec<u8>> {
        debug!("Starting multi-packet read");

        let max_read_size = self.ilo.get_max_read_size();
        let read_request_size = self.ilo.get_read_request_size();
        let response_header_blob_size = self.ilo.get_response_header_blob_size();
        let read_response_size = self.ilo.get_read_response_size();

        let mut bytes_read: u32 = 0;

        let mut read_data_buffer: Vec<u8> = Vec::new();

        while bytes_read < data_length {
            let count;
            if (max_read_size - read_request_size) < (data_length - bytes_read) {
                count = max_read_size - read_request_size;
            } else {
                count = data_length - bytes_read;
            }

            let read_block_size = bytes_read;

            debug!("Reading new fragment");

            let header_template =
                self.ilo
                    .prepare_read_fragment(read_block_size, count, &response_key, &namespace);

            let packet_to_send = Vec::from(header_template);

            let mut fragment_bytes = self
                .exchange_packet(&packet_to_send)
                .context("Failed to read fragment")?;

            // This is pointless and I don't understand why HP's lib is doing this.
            // I added this for consistency but I'm pretty sure this will never execute unless ilorest_chif.so decides to send us wrong sizes.
            // Even if it does execute it'll be useless and we aren't sending the result anywhere, just parsing it ourselves.

            if read_response_size as usize > fragment_bytes.len() {
                let num_more_zeros = read_response_size as usize - fragment_bytes.len();
                for _ in 0..num_more_zeros {
                    fragment_bytes.push(0u8);
                }
            }

            // For reasons we don't know, HPE's python ilorest cli tool increases the header size by 4
            // https://github.com/HewlettPackard/python-ilorest-library/blob/2028d9585a619f90ffb322d81197f793fdf45236/src/redfish/hpilo/risblobstore2.py#L287
            let new_read_size = response_header_blob_size + 4;

            let mut fragment_bytes_cursor = Cursor::new(&fragment_bytes);
            fragment_bytes_cursor.seek(SeekFrom::Start(response_header_blob_size.into()))?;
            let fragment_bytes_read: u32 = fragment_bytes_cursor.read_le()?;

            read_data_buffer.extend_from_slice(
                &fragment_bytes
                    [new_read_size as usize..new_read_size as usize + fragment_bytes_read as usize],
            );

            bytes_read += fragment_bytes_read;
        }

        Ok(read_data_buffer)
    }

    fn get_blob_size(&self, key: &CStr, namespace: &CStr) -> Result<u32> {
        debug!("Reading blob info/size. Key: {}", key.to_string_lossy());

        let header_template = self.ilo.get_key_info(key, namespace);

        let packet_to_send = Vec::from(header_template);
        let blob_info_bytes = self
            .exchange_packet(&packet_to_send)
            .context("Failed while getting blob info")?;

        let mut response_cursor =
            Cursor::new(&blob_info_bytes[self.ilo.get_response_header_blob_size() as usize..]);
        let blobsize: u32 = response_cursor.read_le()?;

        Ok(blobsize)
    }

    /// finalize_multi_packet_write has to be executed after you've written your data to your blobstore2 entry
    fn finalize_multi_packet_write(
        &self,

        request_key: &CStr,
        namespace: &CStr,
    ) -> Result<(), anyhow::Error> {
        debug!(
            "Finalizing write of new blob entry with key {}",
            request_key.to_string_lossy()
        );

        let header_template = self.ilo.finalize_blob_write(request_key, namespace);

        let packet_to_send = Vec::from(header_template);

        self.exchange_packet(&packet_to_send)
            .context("Failed while finalizing write of blob entry")?;

        Ok(())
    }

    /// create_blob_entry creates an entry in blobstore2 key-val store
    /// you have to write to the entry later
    fn create_blob_entry(&self, request_key: &CStr, namespace: &CStr) -> Result<()> {
        debug!(
            "Creating new blob entry with key {}",
            request_key.to_string_lossy()
        );

        let header_template = self.ilo.prepare_new_blob_entry(request_key, namespace);

        let packet_to_send = Vec::from(header_template);

        self.exchange_packet(&packet_to_send)
            .context("Failed while creating blob entry in key value store")?;

        Ok(())
    }

    fn delete_blob_entry(&self, key: &CStr, namespace: &CStr) -> Result<()> {
        debug!("Deleting blob entry with key {}", key.to_string_lossy());

        let header_template = self.ilo.prepare_delete_blob(key, namespace);

        let packet_to_send = Vec::from(header_template);

        self.exchange_packet(&packet_to_send)
            .context("Failed while deleting blob entry in key value store")?;

        Ok(())
    }

    /// write_multi_packet writes your data to blobstore2's key value store if you've created a blob entry already.
    /// Note that you still need to finalize your write after this function.
    fn write_multi_packet(&self, data: &[u8], request_key: &CStr, namespace: &CStr) -> Result<()> {
        let max_write_size = self.ilo.get_max_write_size();
        let write_request_size = self.ilo.get_write_request_size();

        let data_length: u32 = data.len() as u32;

        let mut bytes_written: u32 = 0;

        while bytes_written < data_length {
            let count: u32;
            if (max_write_size - write_request_size) < (data_length - bytes_written) {
                count = max_write_size - write_request_size;
            } else {
                count = data_length - bytes_written;
            }

            let write_blob_size = bytes_written;

            debug!("Writing new fragment");

            let header_template =
                self.ilo
                    .prepare_write_fragment(write_blob_size, count, request_key, namespace);

            let mut packet_to_send = Vec::from(header_template);
            packet_to_send.extend_from_slice(
                &data[write_blob_size as usize..write_blob_size as usize + count as usize],
            );

            self.exchange_packet(&packet_to_send)
                .context("Failed while writing fragment to key value store")?;

            debug!("Written fragment. bytes_written: {}", bytes_written);

            bytes_written += count;
        }

        Ok(())
    }

    fn exchange_packet(&self, send_buf: &[u8]) -> Result<Vec<u8>> {
        let mut send_buf_cursor = Cursor::new(send_buf);
        send_buf_cursor.seek(SeekFrom::Start(2))?;
        let sequence_number: u16 = send_buf_cursor.read_le()?;

        match self.ilo.exchange_packet(send_buf) {
            Ok(recv_buf) => {
                let mut recv_buf_cursor = Cursor::new(&recv_buf);
                let packet_exchange_resp: PacketExchangeResponse = recv_buf_cursor.read_le()?;

                if packet_exchange_resp.sequence_number != sequence_number {
                    return Err(anyhow!(
                        "Sequence number mismatch during packet exchange. Expected {}, got {}",
                        sequence_number,
                        packet_exchange_resp.sequence_number
                    ));
                }
                if !(packet_exchange_resp.error_code == BlobStoreReturnCode::Success as u32
                    || packet_exchange_resp.error_code == BlobStoreReturnCode::NotModified as u32)
                {
                    return Err(anyhow!(
                        "ilorest_chif returned error code {}",
                        packet_exchange_resp.error_code
                    ));
                }

                Ok(recv_buf)
            }
            Err(status_code) => {
                return Err(anyhow!("Unexpected Status code: {}", status_code));
            }
        }
    }
}

#[derive(BinRead, Debug, PartialEq)]
#[br(little)]
struct PacketExchangeResponse {
    #[br(seek_before = SeekFrom::Start(2))]
    sequence_number: u16,

    // It appears that ilorest_chif is returning a different struct based on the contents of send_buf.
    // send_buf is generated by making a call to ilorest_chif with our input data.
    // However every single call we make to packet_exchange has the error_code field at [8:12]
    #[br(seek_before = SeekFrom::Start(8))]
    error_code: u32,
}

#[derive(BinRead, Debug, PartialEq)]
#[br(little)]
struct IloFixedResponse {
    #[br(seek_before = SeekFrom::Start(2))]
    sequence_number: u16,
    #[br(seek_before = SeekFrom::Start(8))]
    error_code: u32,
    receive_mode: u32,
    data_len: u32,
}

fn gen_random_str(length: usize) -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}
