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

//! Delivering capsules to this machine's firmware (UEFI 2.11 §8.5.3): the JSON capsules that
//! capsule.rs builds, through a CapsuleDelivery: Linux's capsule loader (capsule_loader.rs), or
//! UpdateCapsule() in the UEFI Shell (capsule_services.rs).

#[cfg(any(target_os = "uefi", test))]
use anyhow::Context;
use anyhow::Result;
#[cfg(any(target_os = "uefi", test))]
use thiserror::Error;

use crate::efi_variables::CapsuleCapabilities;
use crate::efi_variables::JsonCapsule;
use crate::efi_variables::Processing;

/// A way to this machine's firmware for capsules: Linux's capsule loader, or UpdateCapsule() in
/// the UEFI Shell (UEFI 2.11 §8.5.3).
pub(crate) trait CapsuleDelivery {
    /// When the firmware processes the capsules that these deliver
    const PROCESSING: Processing;

    /// Delivers `capsule`, and tells what QueryCapsuleCapabilities() told of it where these see
    /// that.
    fn deliver(&self, capsule: &JsonCapsule) -> Result<Option<CapsuleCapabilities>>;
}

/// What delivering a capsule told.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CapsuleDelivered {
    /// The size of the capsule, CapsuleImageSize: the bytes delivered, headers included
    pub capsule_size: usize,
    /// What QueryCapsuleCapabilities() told of it, where the backend sees that: the UEFI Shell's
    /// does, while Linux's capsule loader tells its writer neither MaximumCapsuleSize nor
    /// ResetType: a refusal is the write's errno (EINVAL for EFI_UNSUPPORTED, ENOSPC for
    /// EFI_OUT_OF_RESOURCES or a capsule over MaximumCapsuleSize), and the reset type appears only
    /// in the kernel record of a successful upload
    pub capabilities: Option<CapsuleCapabilities>,
}

/// Delivers `payload`, unchanged, through `delivery`, as a JSON capsule whose
/// EFI_JSON_CAPSULE_HEADER carries `capsule_id` (UEFI 2.11 §23.5.2). An empty payload is refused
/// before `delivery` is called.
pub(crate) fn deliver_json_capsule<D: CapsuleDelivery>(
    delivery: &D,
    payload: &[u8],
    capsule_id: u32,
) -> Result<CapsuleDelivered> {
    let capsule = JsonCapsule::new(payload, capsule_id, D::PROCESSING)?;
    let capabilities = delivery.deliver(&capsule)?;
    Ok(CapsuleDelivered {
        capsule_size: capsule.size(),
        capabilities,
    })
}

/// The Capsule Services of EFI_RUNTIME_SERVICES (UEFI 2.11 §4.5.1, §8.5.3) that
/// UpdateCapsuleDelivery calls: those of the UEFI Shell build's firmware, and the tests' fakes on
/// every host.
#[cfg(any(target_os = "uefi", test))]
pub(crate) trait CapsuleServices {
    /// QueryCapsuleCapabilities() of `capsule` alone (UEFI 2.11 §8.5.3.4).
    fn query_capsule_capabilities(&self, capsule: &JsonCapsule) -> Result<CapsuleCapabilities>;

    /// UpdateCapsule() of `capsule` alone (UEFI 2.11 §8.5.3.1).
    fn update_capsule(&self, capsule: &JsonCapsule) -> Result<()>;
}

/// Delivery through `services` in boot services: QueryCapsuleCapabilities(), then UpdateCapsule()
/// of a capsule no larger than it takes, for the firmware to process before that returns. Never
/// ResetSystem(); the caller reports QueryCapsuleCapabilities()'s ResetType.
#[cfg(any(target_os = "uefi", test))]
pub(crate) struct UpdateCapsuleDelivery<S>(pub(crate) S);

#[cfg(any(target_os = "uefi", test))]
impl<S: CapsuleServices> CapsuleDelivery for UpdateCapsuleDelivery<S> {
    const PROCESSING: Processing = Processing::Immediate;

    fn deliver(&self, capsule: &JsonCapsule) -> Result<Option<CapsuleCapabilities>> {
        let capabilities = self
            .0
            .query_capsule_capabilities(capsule)
            .with_context(|| format!("deliver a JSON capsule of {} bytes", capsule.size()))?;
        let size = u64::try_from(capsule.size())?;
        if size > capabilities.maximum_capsule_size {
            return Err(CapsuleTooLarge {
                size,
                maximum: capabilities.maximum_capsule_size,
            }
            .into());
        }
        self.0
            .update_capsule(capsule)
            .with_context(|| format!("deliver a JSON capsule of {} bytes", capsule.size()))?;
        Ok(Some(capabilities))
    }
}

/// A capsule larger than the MaximumCapsuleSize of QueryCapsuleCapabilities(), "the maximum size
/// in bytes that UpdateCapsule() can support as an argument" (UEFI 2.11 §8.5.3.4).
#[cfg(any(target_os = "uefi", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error(
    "the capsule is {size} bytes, more than the {maximum} that QueryCapsuleCapabilities() says \
     UpdateCapsule() takes"
)]
struct CapsuleTooLarge {
    size: u64,
    maximum: u64,
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use anyhow::anyhow;

    use super::*;
    use crate::efi_variables::capsule::PayloadError;
    use crate::efi_variables::ResetType;

    /// CapsuleDelivery that delivers capsules for after a reset, records them, and fails naming
    /// `error` if given.
    #[derive(Default)]
    struct RecordedDelivery {
        delivered: RefCell<Vec<Vec<u8>>>,
        error: Option<&'static str>,
    }

    impl CapsuleDelivery for RecordedDelivery {
        const PROCESSING: Processing = Processing::AfterReset;

        fn deliver(&self, capsule: &JsonCapsule) -> Result<Option<CapsuleCapabilities>> {
            self.delivered
                .borrow_mut()
                .push(capsule.as_bytes().to_vec());
            match self.error {
                Some(error) => Err(anyhow!(error)),
                None => Ok(None),
            }
        }
    }

    /// deliver_json_capsule delivers a payload as the capsule of the delivery's processing, and
    /// refuses an empty one without delivering anything.
    #[test]
    fn deliver_json_capsule_refuses_an_empty_payload_before_delivering() {
        let delivery = RecordedDelivery::default();

        let error = deliver_json_capsule(&delivery, b"", 7).expect_err("deliver an empty payload");

        assert_eq!(
            error.downcast_ref::<PayloadError>(),
            Some(&PayloadError::Empty),
            "{error:#}"
        );
        assert_eq!(delivery.delivered.borrow().len(), 0, "delivered");

        let delivered = deliver_json_capsule(&delivery, b"{}", 7).expect("deliver a payload");

        let capsule = JsonCapsule::new(b"{}", 7, Processing::AfterReset).expect("make a capsule");
        assert_eq!(
            delivered,
            CapsuleDelivered {
                capsule_size: 42,
                capabilities: None,
            },
            "report"
        );
        assert_eq!(
            delivery.delivered.into_inner(),
            [capsule.as_bytes().to_vec()],
            "delivered"
        );
    }

    /// deliver_json_capsule fails as its delivery does, naming why.
    #[test]
    fn deliver_json_capsule_fails_as_the_delivery_fails() {
        let delivery = RecordedDelivery {
            error: Some("the loader refused it"),
            ..RecordedDelivery::default()
        };

        let error = deliver_json_capsule(&delivery, b"{}", 7).expect_err("deliver a payload");

        assert_eq!(format!("{error:#}"), "the loader refused it", "error");
        assert_eq!(delivery.delivered.borrow().len(), 1, "delivered");
    }

    /// A call of FakeCapsuleServices: QueryCapsuleCapabilities() or UpdateCapsule(), and the
    /// capsule's bytes.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum CapsuleCall {
        Query(Vec<u8>),
        Update(Vec<u8>),
    }

    /// CapsuleServices whose QueryCapsuleCapabilities() tells `capabilities` or fails naming its
    /// error, whose UpdateCapsule() fails naming `update_error` if given, and which record their
    /// calls.
    struct FakeCapsuleServices {
        capabilities: Result<CapsuleCapabilities, &'static str>,
        update_error: Option<&'static str>,
        calls: RefCell<Vec<CapsuleCall>>,
    }

    impl FakeCapsuleServices {
        fn new(
            capabilities: Result<CapsuleCapabilities, &'static str>,
            update_error: Option<&'static str>,
        ) -> Self {
            Self {
                capabilities,
                update_error,
                calls: RefCell::default(),
            }
        }
    }

    impl CapsuleServices for FakeCapsuleServices {
        fn query_capsule_capabilities(&self, capsule: &JsonCapsule) -> Result<CapsuleCapabilities> {
            self.calls
                .borrow_mut()
                .push(CapsuleCall::Query(capsule.as_bytes().to_vec()));
            self.capabilities.map_err(|error| anyhow!(error))
        }

        fn update_capsule(&self, capsule: &JsonCapsule) -> Result<()> {
            self.calls
                .borrow_mut()
                .push(CapsuleCall::Update(capsule.as_bytes().to_vec()));
            match self.update_error {
                Some(error) => Err(anyhow!(error)),
                None => Ok(()),
            }
        }
    }

    /// The capabilities of a firmware that takes capsules up to `maximum_capsule_size` bytes and
    /// asks for a warm reset.
    fn warm_reset_capabilities(maximum_capsule_size: u64) -> CapsuleCapabilities {
        CapsuleCapabilities {
            maximum_capsule_size,
            reset_type: ResetType::WARM,
        }
    }

    /// UpdateCapsuleDelivery asks QueryCapsuleCapabilities() first, then passes a capsule up to
    /// its maximum size, for immediate processing, to UpdateCapsule(), and tells the capabilities,
    /// its reset type among them.
    #[test]
    fn update_capsule_delivery_queries_then_updates() {
        let capsule = JsonCapsule::new(b"{}", 7, Processing::Immediate).expect("make a capsule");
        let bytes = capsule.as_bytes().to_vec();
        for maximum in [42, 43, u64::MAX] {
            let delivery = UpdateCapsuleDelivery(FakeCapsuleServices::new(
                Ok(warm_reset_capabilities(maximum)),
                None,
            ));

            let delivered = deliver_json_capsule(&delivery, b"{}", 7).expect("deliver a payload");

            assert_eq!(
                delivered.capabilities,
                Some(warm_reset_capabilities(maximum)),
                "{maximum}"
            );
            assert_eq!(
                delivery.0.calls.into_inner(),
                [
                    CapsuleCall::Query(bytes.clone()),
                    CapsuleCall::Update(bytes.clone())
                ],
                "{maximum}"
            );
        }
    }

    /// UpdateCapsuleDelivery calls no UpdateCapsule() where QueryCapsuleCapabilities() fails or
    /// tells a smaller maximum size, and names why.
    #[test]
    fn update_capsule_delivery_updates_nothing_that_the_query_refuses() {
        let capsule = JsonCapsule::new(b"{}", 7, Processing::Immediate).expect("make a capsule");
        for (capabilities, want) in [
            (
                Err("QueryCapsuleCapabilities() of the JSON capsule: UNSUPPORTED"),
                "deliver a JSON capsule of 42 bytes: QueryCapsuleCapabilities() of the JSON \
                 capsule: UNSUPPORTED",
            ),
            (
                Ok(warm_reset_capabilities(41)),
                "the capsule is 42 bytes, more than the 41 that QueryCapsuleCapabilities() says \
                 UpdateCapsule() takes",
            ),
            (
                Ok(warm_reset_capabilities(0)),
                "the capsule is 42 bytes, more than the 0 that QueryCapsuleCapabilities() says \
                 UpdateCapsule() takes",
            ),
        ] {
            let delivery = UpdateCapsuleDelivery(FakeCapsuleServices::new(capabilities, None));

            let error = deliver_json_capsule(&delivery, b"{}", 7).expect_err("deliver a payload");

            assert_eq!(format!("{error:#}"), want, "{capabilities:?}");
            assert_eq!(
                delivery.0.calls.into_inner(),
                [CapsuleCall::Query(capsule.as_bytes().to_vec())],
                "{capabilities:?}"
            );
        }
    }

    /// UpdateCapsuleDelivery fails as UpdateCapsule() fails, naming why.
    #[test]
    fn update_capsule_delivery_fails_as_update_capsule_fails() {
        let delivery = UpdateCapsuleDelivery(FakeCapsuleServices::new(
            Ok(warm_reset_capabilities(4096)),
            Some("UpdateCapsule() of the JSON capsule: DEVICE_ERROR"),
        ));

        let error = deliver_json_capsule(&delivery, b"{}", 7).expect_err("deliver a payload");

        assert_eq!(
            format!("{error:#}"),
            "deliver a JSON capsule of 42 bytes: UpdateCapsule() of the JSON capsule: DEVICE_ERROR",
            "error"
        );
        assert_eq!(delivery.0.calls.borrow().len(), 2, "calls");
    }
}
