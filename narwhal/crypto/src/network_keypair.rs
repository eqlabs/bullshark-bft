use base64ct::Encoding;
use ed25519::SecretKey;
use ed25519_dalek as ed25519;
use serde::{Deserialize, Serialize};
use std::{
    fmt::{Debug, Display},
    hash::Hasher,
};

#[derive(PartialEq, Eq, Clone)]
pub struct NetworkPublicKey(pub ed25519::PublicKey);
#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkKeyPair(pub ed25519::Keypair);

impl std::hash::Hash for NetworkPublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.as_bytes().hash(state);
    }
}

impl Serialize for NetworkPublicKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let encoded = base64ct::Base64::encode_string(self.0.as_bytes());
        serializer.serialize_str(&encoded)
    }
}

impl<'de> Deserialize<'de> for NetworkPublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        let bytes = base64ct::Base64::decode_vec(&encoded).map_err(serde::de::Error::custom)?;
        Ok(Self(
            ed25519::PublicKey::from_bytes(&bytes).map_err(serde::de::Error::custom)?,
        ))
    }
}

impl core::fmt::Debug for NetworkPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?}",
            base64ct::Base64::encode_string(self.0.as_bytes())
        )
    }
}

impl Display for NetworkPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?}",
            base64ct::Base64::encode_string(self.0.as_bytes())
        )
    }
}

impl NetworkPublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, eyre::Report> {
        Ok(Self(ed25519::PublicKey::from_bytes(bytes)?))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

impl NetworkKeyPair {
    pub fn generate<R>(rng: &mut R) -> Self
    where
        R: rand_core::RngCore + rand_core::CryptoRng,
    {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        // HACK to get around the ed25519_dalek problem that it depends
        // on rand_core 0.5 and we are using 0.6
        let private: SecretKey = SecretKey::from_bytes(&bytes).unwrap();
        let public: ed25519::PublicKey = (&private).into();
        let kp = ed25519::Keypair {
            secret: private,
            public,
        };
        Self(kp)
    }

    pub fn public(&self) -> NetworkPublicKey {
        NetworkPublicKey(self.0.public)
    }

    pub fn private(&self) -> &SecretKey {
        &self.0.secret
    }

    pub fn copy(&self) -> Self {
        Self(ed25519::Keypair::from_bytes(&self.0.to_bytes()).unwrap())
    }

    pub fn encode_base64(&self) -> String {
        let bytes = self.0.to_bytes();
        base64ct::Base64::encode_string(&bytes)
    }

    pub fn decode_base64(string: &str) -> Result<Self, eyre::Report> {
        let bytes = base64ct::Base64::decode_vec(string).map_err(|e| eyre::eyre!(e.to_string()))?;
        let kp = ed25519::Keypair::from_bytes(&bytes)?;
        Ok(Self(kp))
    }
}
