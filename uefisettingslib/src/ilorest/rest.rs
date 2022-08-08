use std::collections::HashMap;
use std::ffi::CString;

use anyhow::anyhow;
use anyhow::Result;
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

    pub fn get(&self, endpoint: &str) -> Result<Vec<u8>> {
        self.exec("GET", endpoint, "")
    }

    pub fn post(&self, endpoint: &str, body: &str) -> Result<Vec<u8>> {
        self.exec("POST", endpoint, body)
    }

    pub fn patch(&self, endpoint: &str, body: &str) -> Result<Vec<u8>> {
        self.exec("PATCH", endpoint, body)
    }

    pub fn put(&self, endpoint: &str, body: &str) -> Result<Vec<u8>> {
        self.exec("PUT", endpoint, body)
    }

    fn default_headers(&self) -> HashMap<String, String> {
        HashMap::from([
            ("Host".to_string(), "".to_string()),
            ("Accept-Encoding".to_string(), "identity".to_string()),
            ("Accept".to_string(), "*/*".to_string()),
            ("Connection".to_string(), "Keep-Alive".to_string()),
        ])
    }

    fn exec(&self, method: &str, endpoint: &str, body: &str) -> Result<Vec<u8>> {
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

        let request =
            self.generate_request_bytes(method, endpoint, body, &(self.default_headers()))?;

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
        headers: &HashMap<String, String>,
    ) -> Result<Vec<u8>> {
        let mut request_contents = format!("{} {} HTTP/1.1\r\n", method, endpoint);
        for (header_key, header_value) in headers {
            request_contents.push_str(&format!("{}: {}\r\n", header_key, header_value));
        }
        request_contents.push_str(&format!("\r\n{}", body));

        debug!("Sending request \n{}", request_contents);

        let request = CString::new(request_contents)?.as_bytes_with_nul().to_vec();
        Ok(request)
    }
}
