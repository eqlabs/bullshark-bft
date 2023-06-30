use crate::{traits::EncodeDecodeBase64, CurrentNetwork, NetworkKeyPair};

use std::{
    cmp::Ordering, fmt::Display, fs::File, io, io::Write, ops::Deref, sync::atomic::AtomicU32,
};

use base64ct::{Base64, Encoding};
use eyre::eyre;
use rand::{rngs::StdRng, CryptoRng, Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use snarkvm_console::{
    account::Address,
    prelude::{Compare, Equal, FromBytes, ToBytes},
};

lazy_static::lazy_static! {
    static ref COUNTER: AtomicU32 = AtomicU32::new(0);
}

/// Convenience struct wrapping a BLS12377 key pair.
#[derive(Clone, Debug)]
pub struct KeyPair {
    public: PublicKey,
    private: PrivateKey,
}

impl EncodeDecodeBase64 for KeyPair {
    fn encode_base64(&self) -> String {
        self.private.encode_base64()
    }

    fn decode_base64(s: &str) -> Result<Self, eyre::Report> {
        let private = PrivateKey::decode_base64(s)?;
        let public = PublicKey(Address::try_from(private.0).map_err(|e| eyre!(e))?);

        Ok(Self { public, private })
    }
}

impl KeyPair {
    pub fn export(&self, path: &str) -> io::Result<()> {
        let ba64 = self.encode_base64();
        let mut file = File::create(path)?;
        file.write_all(ba64.as_bytes())?;
        Ok(())
    }
}

impl KeyPair {
    pub fn new<R: Rng + CryptoRng>(rng: &mut R) -> Result<Self, eyre::Report> {
        let private = snarkvm_console::account::PrivateKey::new(rng).map_err(|e| eyre!(e))?;
        let public = PublicKey(Address::try_from(private).map_err(|e| eyre!(e))?);
        let private = PrivateKey(private);

        Ok(Self { public, private })
    }

    pub fn public(&self) -> &PublicKey {
        &self.public
    }

    pub fn private(&self) -> &PrivateKey {
        &self.private
    }

    pub fn to_network_keypair(&self) -> NetworkKeyPair {
        let kp = self
            .private()
            .to_ed25519(COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst))
            .unwrap();
        NetworkKeyPair(kp)
    }
}

/// A BLS12377 public key.
#[derive(Eq, PartialEq, Clone, Serialize, Deserialize, Debug, Hash)]
pub struct PublicKey(Address<CurrentNetwork>);

impl Default for PublicKey {
    fn default() -> Self {
        #[allow(deprecated)] // this is only used in tests
        Self(snarkvm_console::account::Address::<CurrentNetwork>::zero())
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> Ordering {
        if *self.0.is_equal(&other.0) {
            Ordering::Equal
        } else if *self.0.is_less_than(&other.0) {
            Ordering::Less
        } else {
            Ordering::Greater
        }
    }
}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Deref for PublicKey {
    type Target = Address<CurrentNetwork>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl EncodeDecodeBase64 for PublicKey {
    fn encode_base64(&self) -> String {
        Base64::encode_string(&self.0.to_bytes_le().unwrap())
    }

    fn decode_base64(s: &str) -> Result<Self, eyre::Report> {
        let bytes = Base64::decode_vec(s).map_err(|e| eyre!(e))?;
        Ok(Self(Address::from_bytes_le(&bytes).map_err(|e| eyre!(e))?))
    }
}

impl PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, eyre::Report> {
        Ok(Self(Address::from_bytes_le(bytes).map_err(|e| eyre!(e))?))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes_le().unwrap()
    }
}

/// A BLS12377 private key.
#[derive(Clone, Copy, Debug)]
pub struct PrivateKey(snarkvm_console::account::PrivateKey<CurrentNetwork>);

impl Default for PrivateKey {
    fn default() -> Self {
        let mut rng = StdRng::seed_from_u64(1234567890);
        Self(snarkvm_console::account::PrivateKey::<CurrentNetwork>::new(&mut rng).unwrap())
    }
}

impl Deref for PrivateKey {
    type Target = snarkvm_console::account::PrivateKey<CurrentNetwork>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl EncodeDecodeBase64 for PrivateKey {
    fn encode_base64(&self) -> String {
        Base64::encode_string(&self.0.to_bytes_le().unwrap())
    }

    fn decode_base64(s: &str) -> Result<Self, eyre::Report> {
        let bytes = Base64::decode_vec(s).map_err(|e| eyre!(e))?;
        Ok(Self(
            snarkvm_console::account::PrivateKey::<CurrentNetwork>::from_bytes_le(&bytes)
                .map_err(|e| eyre!(e))?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
