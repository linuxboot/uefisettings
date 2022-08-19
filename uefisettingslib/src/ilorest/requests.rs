use std::collections::HashMap;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use log::debug;
use serde::Deserialize;
use serde::Serialize;
use serde_json::value::Value;

use crate::ilorest::chif::find_lib_location;
use crate::ilorest::rest::RestClient;

// HPE just dumps everything into one big key-val pair in some ilo4 endpoints
// including bios settings and excessive stuff. We want to ignore this excessive stuff.
const ILO4_IGNORED_KEYS: [&str; 7] = [
    "links",
    "Type",
    "SettingsResult",
    "Modified",
    "Description",
    "AttributeRegistry",
    "SettingsObject",
];

// The returned message should contain this if updating bios settings worked
const SUCCESS_MSG: &str = "SystemResetRequired";

#[derive(Debug, PartialEq)]
pub enum IloDevice {
    Ilo4,
    Ilo5,
    Ilo5Gen10Plus,
}

/// identify_hpe_machine_type tries to identify the kind of HPE machine.
/// However, this is just the best guess. Even if we can't correctly differenciate between
/// ilo5 with Gen10 vs ilo5 with Gen10+ or some other variant, we can still get/set bios settings.
pub fn identify_hpe_machine_type() -> Result<IloDevice> {
    let client = RestClient::new(&find_lib_location()?);

    let (status, body) = client.get("/redfish/v1/")?;
    if status != HTTPStatusCode::Ok as u16 {
        return Err(anyhow!(
            "Unexpected HTTP Status Code while fetching pending bios settings"
        ));
    }
    let deserialized: RedfishDetails = serde_json::from_str(&remove_null_bytes(&body))
        .context("failed while deserializing response json to RedfishDetails")?;

    if deserialized.redfish_version.contains("1.0.0") {
        return Ok(IloDevice::Ilo4);
    }
    if let Value::String(product) = deserialized.product {
        if product.contains("Gen10 Plus") {
            return Ok(IloDevice::Ilo5Gen10Plus);
        }
    }

    // since its running ilo we're gonna assume generic ilo5/gen 10
    Ok(IloDevice::Ilo5)
}

/// get_device_instance returns either Ilo4Dev{} or Ilo5Dev{} (both implement the IloDev trait)
/// based on ilo_machine_type
pub fn get_device_instance(ilo_machine_type: IloDevice) -> Box<dyn IloDev> {
    match ilo_machine_type {
        IloDevice::Ilo4 => Box::new(Ilo4Dev {}),
        _ => Box::new(Ilo5Dev {}), //ilo5 gen 10 and gen10+ should both return Ilo5Dev
    }
}

pub trait IloDev {
    fn update_setting(&self, attribute: &str, new_value: &str) -> Result<()>;
    fn get_pending_settings(&self) -> Result<RedfishAttributes>;
    fn get_current_settings(&self) -> Result<RedfishAttributes>;
    fn settings_selector(&self) -> String;
}

pub struct Ilo5Dev;

impl IloDev for Ilo5Dev {
    fn update_setting(&self, attribute: &str, new_value: &str) -> Result<()> {
        let client = RestClient::new(&find_lib_location()?);

        let update_struct = RedfishUpdateAttribute {
            attributes: HashMap::from([(
                attribute.to_string(),
                Value::String(new_value.to_string()),
            )]),
        };
        let serialized = serde_json::to_string(&update_struct)
            .context("failed while serializing RedfishUpdateAttribute to json")?;
        debug!("Serialized RedfishUpdateAttribute is {} ", serialized);

        let (status, body) = client.patch("/redfish/v1/systems/1/bios/settings/", &serialized)?;
        if status != HTTPStatusCode::Ok as u16 {
            return Err(anyhow!(
                "Unexpected HTTP Status Code while fetching current bios settings"
            ));
        }

        let deserialized: RedfishPatchResult = serde_json::from_str(&remove_null_bytes(&body))
            .context("failed while deserializing response json to RedfishPatchResult")?;
        debug!("Deserialized RedfishPatchResult = {:?}", deserialized);

        // It worked if the error's message_extended_info field is [RedfishMessage { message_id: "iLO.2.14.SystemResetRequired" }]
        for msg in deserialized.error.message_extended_info {
            debug!("msg is = {:?}", msg.message_id_ilo5);
            if msg.message_id_ilo5.contains(SUCCESS_MSG) {
                return Ok(());
            }
        }

        Err(anyhow!(
            "message_extended_info field does not have expected message after updating ilo5 settings"
        ))
    }

    fn get_pending_settings(&self) -> Result<RedfishAttributes> {
        let client = RestClient::new(&find_lib_location()?);

        let (status, body) = client.get("/redfish/v1/systems/1/bios/settings/")?;
        if status != HTTPStatusCode::Ok as u16 {
            return Err(anyhow!(
                "Unexpected HTTP Status Code while fetching pending bios settings"
            ));
        }

        let deserialized: RedfishPendingSettings = serde_json::from_str(&remove_null_bytes(&body))
            .context("failed while deserializing response json to RedfishPendingSettings")?;
        debug!("Browsing {:?}", deserialized.name);

        Ok(deserialized.attributes)
    }

    fn get_current_settings(&self) -> Result<RedfishAttributes> {
        let client = RestClient::new(&find_lib_location()?);

        let (status, body) = client.get("/redfish/v1/systems/1/bios/")?;
        if status != HTTPStatusCode::Ok as u16 {
            return Err(anyhow!(
                "Unexpected HTTP Status Code while fetching current bios settings"
            ));
        }

        let deserialized: RedfishCurrentSettings = serde_json::from_str(&remove_null_bytes(&body))
            .context("failed while deserializing response json to RedfishCurrentSettings")?;
        debug!("Browsing {:?}", deserialized.name);

        Ok(deserialized.attributes)
    }

    fn settings_selector(&self) -> String {
        "ilo5-bios".to_owned()
    }
}

pub struct Ilo4Dev;

impl IloDev for Ilo4Dev {
    fn update_setting(&self, attribute: &str, new_value: &str) -> Result<()> {
        let client = RestClient::new(&find_lib_location()?);

        let update_struct =
            HashMap::from([(attribute.to_string(), Value::String(new_value.to_string()))]);

        let serialized = serde_json::to_string(&update_struct)
            .context("failed while serializing Hashmap to json")?;
        debug!("Serialized Hashmap to patch ilo4 is {} ", serialized);

        // NOTE: trailing slashes are necessary in ilo4 because otherwise it returns HTTP 308 Moved Permanently
        let (status, body) = client.patch("/redfish/v1/systems/1/bios/settings/", &serialized)?;
        if status != HTTPStatusCode::Ok as u16 {
            return Err(anyhow!(
                "Unexpected HTTP Status Code while fetching current bios settings"
            ));
        }

        let deserialized: RedfishPatchResult = serde_json::from_str(&remove_null_bytes(&body))
            .context("failed while deserializing response json to RedfishPatchResult")?;
        debug!("Deserialized RedfishPatchResult = {:?}", deserialized);

        // It worked if the error's message_extended_info field is [RedfishMessage { message_id_ilo4: "iLO.0.10.SystemResetRequired" }]
        for msg in deserialized.error.message_extended_info {
            debug!("msg is = {:?}", msg.message_id_ilo4);
            if msg.message_id_ilo4.contains(SUCCESS_MSG) {
                return Ok(());
            }
        }

        Err(anyhow!(
            "message_extended_info field does not have expected message after updating ilo4 settings"
        ))
    }

    fn get_pending_settings(&self) -> Result<RedfishAttributes> {
        let client = RestClient::new(&find_lib_location()?);

        let (status, body) = client.get("/redfish/v1/systems/1/bios/settings/")?;
        if status != HTTPStatusCode::Ok as u16 {
            return Err(anyhow!(
                "Unexpected HTTP Status Code while fetching pending bios settings"
            ));
        }

        let mut deserialized: RedfishAttributes =
            serde_json::from_str(&remove_null_bytes(&body))
                .context("failed while deserializing response json to Ilo4 PendingSettings")?;

        for key in ILO4_IGNORED_KEYS {
            deserialized.remove(key);
        }

        Ok(deserialized)
    }

    fn get_current_settings(&self) -> Result<RedfishAttributes> {
        let client = RestClient::new(&find_lib_location()?);

        let (status, body) = client.get("/redfish/v1/systems/1/bios/")?;
        if status != HTTPStatusCode::Ok as u16 {
            return Err(anyhow!(
                "Unexpected HTTP Status Code while fetching current bios settings"
            ));
        }

        let mut deserialized: RedfishAttributes =
            serde_json::from_str(&remove_null_bytes(&body))
                .context("failed while deserializing response json to Ilo4 CurrentSettings")?;

        for key in ILO4_IGNORED_KEYS {
            deserialized.remove(key);
        }

        Ok(deserialized)
    }

    fn settings_selector(&self) -> String {
        "ilo4-bios".to_owned()
    }
}

fn remove_null_bytes(body: &[u8]) -> String {
    // serde_json::from_str and serde_json::from_slice both fail if they see null-terminators/null-bytes.
    // CStr::from_bytes_with_nul fails if there are interior null bytes before the final one.
    // CStr::from_bytes_until_nul exists but its a nightly feature.

    // Can't do body_str = body_str.trim_matches(char::from(0)).to_owned() either because apparantly
    // the C lib is doing a buffer over-read and there are some random strings after the null bytes in ilo4.

    let body = String::from_utf8_lossy(body);
    if let Some(null_index) = body.find(char::from(0)) {
        let body_str = &body[..null_index];
        return body_str.to_owned();
    }
    body.to_string()
}

// TODO: move this to rest.rs and implement error_for_status kind of like
// https://docs.rs/reqwest/latest/reqwest/struct.Response.html#method.error_for_status
#[derive(PartialEq)]
enum HTTPStatusCode {
    Ok = 200,
    // MovedPermanently = 308,
    // Forbidden = 403,
    // NotFound = 404,
    // MethodNotAllowed = 405,
    // UnsupportedMediaType = 415,
}

// NOTE: Unless Ilo4 is explicitly mentioned, Redfish in these structs means standardized Redfish i.e. Redfish > 1.6
// * ilo4 uses Redfish 1.0.0 (present in HPE Gen 9)
// * ilo5 uses Redfish 1.6 and above (present in HPE Gen10 and Gen10+)
// HPE's Gen10 and Gen10+ have different OEM specific hidden routes but the way to change/view bios settings is the same

// RedfishAttribute is used in both ilo4 and ilo5
type RedfishAttributes = HashMap<String, Value>;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct RedfishPendingSettings {
    #[serde(rename = "@odata.context")]
    pub odata_context: String,
    #[serde(rename = "@odata.etag")]
    pub odata_etag: String,
    #[serde(rename = "@odata.id")]
    pub odata_id: String,
    #[serde(rename = "@odata.type")]
    pub odata_type: String,
    pub attribute_registry: String,
    pub attributes: RedfishAttributes,
    pub id: String,
    pub name: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct RedfishCurrentSettings {
    #[serde(rename = "@Redfish.Settings")]
    pub redfish_settings: RedfishSettingsInfo,
    #[serde(rename = "@odata.context")]
    pub odata_context: String,
    #[serde(rename = "@odata.etag")]
    pub odata_etag: String,
    #[serde(rename = "@odata.id")]
    pub odata_id: String,
    #[serde(rename = "@odata.type")]
    pub odata_type: String,
    pub attribute_registry: String,
    pub attributes: RedfishAttributes,
    pub id: String,
    pub name: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct RedfishSettingsInfo {
    #[serde(rename = "@odata.type")]
    pub odata_type: String,
    pub etag: String,
    pub messages: Vec<RedfishMessage>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct RedfishMessage {
    #[serde(rename = "MessageId")]
    pub message_id_ilo5: String,
    #[serde(rename = "MessageID")]
    pub message_id_ilo4: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct RedfishUpdateAttribute {
    pub attributes: RedfishAttributes,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RedfishPatchResult {
    pub error: RedfishError,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RedfishError {
    pub code: String,
    pub message: String,
    #[serde(rename = "@Message.ExtendedInfo")]
    pub message_extended_info: Vec<RedfishMessage>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct RedfishDetails {
    pub product: Value,
    pub redfish_version: String,
    pub vendor: Value,
}
