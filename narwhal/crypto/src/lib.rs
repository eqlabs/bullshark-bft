// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
#![warn(
    future_incompatible,
    nonstandard_style,
    rust_2018_idioms,
    rust_2021_compatibility
)]

use snarkvm_console::network::Testnet3;

// This re-export allows using the trait-defined APIs
use shared_crypto::intent::{Intent, IntentMessage, IntentScope};

mod hash;
mod keypair;
mod network_keypair;
mod signature;
mod traits;

pub use hash::*;
pub use keypair::*;
pub use network_keypair::*;
pub use signature::*;
pub use traits::*;

type CurrentNetwork = Testnet3;

/// Wrap a message in an intent message. Currently in Narwhal, the scope is always IntentScope::HeaderDigest and the app id is AppId::Narwhal.
pub fn to_intent_message<T>(value: T) -> IntentMessage<T> {
    IntentMessage::new(Intent::narwhal_app(IntentScope::HeaderDigest), value)
}

// pub type DefaultHashFunction = snarkvm_console::algorithms::BHP256<CurrentEnvironment>;
// pub const DIGEST_LENGTH: usize = snarkvm_console::types::Field::<CurrentEnvironment>::SIZE_IN_BYTES;

#[cfg(test)]
mod tests {
    use super::*;
    use base64ct::{Base64, Encoding};
    use snarkvm_console::program::ToBytes;

    #[test]
    fn test_public_key_default() {
        let pk = PublicKey::default();
        assert_eq!(
            pk.encode_base64(),
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        );
    }

    #[test]
    fn test_private_key_default() {
        let pk = PrivateKey::default();
        assert_eq!(
            pk.encode_base64(),
            "7uijHRAnvMWh4H7OC56fHehHBbR76oHmmD37dLYQLQg="
        );
    }

    #[tokio::test]
    async fn test_signature_service() {
        let pk = PrivateKey::default();
        let signature_service = SignatureService::new(pk);
        let sig = signature_service
            .request_signature(Digest::new([0u8; 32]))
            .await;
        let _b64 = Base64::encode_string(&sig.to_bytes_le().unwrap());
    }
}
