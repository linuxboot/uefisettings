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

use std::collections::HashMap;
use std::ffi::CString;

use anyhow::anyhow;
use anyhow::Result;
use httparse::Response;
use httparse::Status;
use log::debug;

use crate::ilorest::blobstore::Transport;
use crate::ilorest::chif::get_lib;
use crate::ilorest::chif::IloRestChif;
use crate::ilorest::chif::IloRestChifInterface;

const MAX_ALLOWED_REQUEST_ATTEMPTS: u32 = 10;

/// RestClient allows you to make GET/POST/PUT/PATCH requests to the ILO BMC's Redfish API over Blobstore2
pub struct RestClient {
    lib_path: String,
}

impl RestClient {
    pub fn new(lib_path: &str) -> Self {
        Self {
            lib_path: lib_path.to_string(),
        }
    }
    // get request to the endpoint. Returns HTTP status code and response body bytes.
    pub fn get(&self, endpoint: &str) -> Result<(u16, Vec<u8>)> {
        let response = self.exec("GET", endpoint, self.default_headers(), "")?;
        self.parse(response)
    }

    // post request to the endpoint with given JSON body. Returns HTTP status code and response body bytes.
    pub fn post(&self, endpoint: &str, body: &str) -> Result<(u16, Vec<u8>)> {
        let mut headers = self.default_headers();
        headers.insert(
            "Content-Type".to_string(),
            "application/json; charset=utf-8".to_string(),
        );
        let response = self.exec("POST", endpoint, headers, body)?;
        self.parse(response)
    }

    // patch request to the endpoint with given JSON body. Returns HTTP status code and response body bytes.
    pub fn patch(&self, endpoint: &str, body: &str) -> Result<(u16, Vec<u8>)> {
        let mut headers = self.default_headers();
        headers.insert(
            "Content-Type".to_string(),
            "application/json; charset=utf-8".to_string(),
        );
        let response = self.exec("PATCH", endpoint, headers, body)?;
        self.parse(response)
    }

    // put request to the endpoint with given JSON body. Returns HTTP status code and response body bytes.
    pub fn put(&self, endpoint: &str, body: &str) -> Result<(u16, Vec<u8>)> {
        let mut headers = self.default_headers();
        headers.insert(
            "Content-Type".to_string(),
            "application/json; charset=utf-8".to_string(),
        );
        let response = self.exec("PUT", endpoint, headers, body)?;
        self.parse(response)
    }

    // parse takes in the raw response bytes and parses the HTTP headers.
    // It returns (response HTTP status code, response body without the HTTP headers)
    fn parse(&self, raw_response: Vec<u8>) -> Result<(u16, Vec<u8>)> {
        // for perf reasons, httparse's API forces us to specify max number of headers
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut parsed_response = Response::new(&mut headers);

        let parse_status = parsed_response.parse(&raw_response)?;

        match parse_status {
            Status::Complete(body_offset) => {
                // Status::Complete means that the request was fully parsed.
                // So we know that these optional fields are not none and we
                // can use unwrap without worrying about panics.
                debug!(
                    "Request parsed. Status code: {} Reason: {}, HTTP Version: {}",
                    parsed_response.code.unwrap(),
                    parsed_response.reason.unwrap(),
                    parsed_response.version.unwrap()
                );
                debug!(
                    "Response body is {}",
                    String::from_utf8_lossy(&raw_response[body_offset..])
                );
                Ok((
                    parsed_response.code.unwrap(),
                    raw_response[body_offset..].to_vec(),
                ))
            }
            Status::Partial => Err(anyhow!("Failed to parse REST response")),
        }
    }

    // default_headers for creating a new REST request
    fn default_headers(&self) -> HashMap<String, String> {
        HashMap::from([
            ("Host".to_string(), "".to_string()),
            ("Accept-Encoding".to_string(), "identity".to_string()),
            (
                "Content-Type".to_string(),
                "application/json; charset=utf-8".to_string(),
            ),
            ("Accept".to_string(), "*/*".to_string()),
            ("Connection".to_string(), "Keep-Alive".to_string()),
        ])
    }

    fn exec(
        &self,
        method: &str,
        endpoint: &str,
        headers: HashMap<String, String>,
        body: &str,
    ) -> Result<Vec<u8>> {
        // HPE's ilorest CLI tool initializes a new lib instance for every request and since we have
        // no documentation of ilorest_chif.so we will try to replicate the python cli tool.
        // It may or may not be safe to use the same instance/connection for multiple requests.

        let lib = get_lib(&(self.lib_path))?;
        let ilo = IloRestChif::new(&lib)?;
        let transport = Transport::new(&ilo)?;

        ilo.ping()
            .map_err(|code| anyhow!(format!("Unexpected Status Code: {} during ping", code)))?;

        ilo.set_recv_timeout(60000).map_err(|code| {
            anyhow!(format!(
                "Unexpected Status Code: {} during set_recv_timeout",
                code
            ))
        })?;

        let request = self.generate_request_bytes(method, endpoint, body, headers)?;

        // HPE's ilorest CLI tool has a lot of retries spanning across multiple function calls during transport
        // however we will only have retries at one place, which makes it much simpler.

        let mut current_try = 0;

        let response = loop {
            debug!("Trying");

            let resp = transport.make_request(&request);
            if resp.is_ok() || current_try > MAX_ALLOWED_REQUEST_ATTEMPTS {
                break resp;
            }
            current_try += 1;
        };

        match response {
            Ok(resp) => {
                debug!(
                    "Final REST Response is {:?}",
                    String::from_utf8_lossy(&resp)
                );

                Ok(resp)
            }
            Err(why) => Err(anyhow!("Failed to make request {}", why)),
        }
        // TODO: another function for converting raw response (headers + body) into JSON
    }

    // generate_request_bytes generates the request headers + body and returns bytes
    fn generate_request_bytes(
        &self,
        method: &str,
        endpoint: &str,
        body: &str,
        mut headers: HashMap<String, String>,
    ) -> Result<Vec<u8>> {
        let mut request_contents = format!("{} {} HTTP/1.1\r\n", method, endpoint);
        headers.insert(
            "Content-Length".to_string(),
            body.as_bytes().len().to_string(),
        );

        for (header_key, header_value) in headers {
            request_contents.push_str(&format!("{}: {}\r\n", header_key, header_value));
        }
        request_contents.push_str(&format!("\r\n{}", body));

        debug!("Sending request \n{}", request_contents);

        let request = CString::new(request_contents)?.as_bytes_with_nul().to_vec();
        Ok(request)
    }
}
