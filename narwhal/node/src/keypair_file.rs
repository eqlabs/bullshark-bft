// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::anyhow;
use crypto::{EncodeDecodeBase64, KeyPair, NetworkKeyPair};
use rand::{CryptoRng, Rng};

pub type AuthorityKeyPair = KeyPair;

pub fn get_key_pair_from_rng<R: Rng + CryptoRng>(rng: &mut R) -> KeyPair {
    KeyPair::new(rng).unwrap()
}

/// Write Base64 encoded `flag || privkey` to file.
pub fn write_keypair_to_file<P: AsRef<std::path::Path>>(
    keypair: &NetworkKeyPair,
    path: P,
) -> anyhow::Result<()> {
    let contents = keypair.encode_base64();
    std::fs::write(path, contents)?;
    Ok(())
}

/// Write Base64 encoded `privkey` to file.
pub fn write_authority_keypair_to_file<P: AsRef<std::path::Path>>(
    keypair: &AuthorityKeyPair,
    path: P,
) -> anyhow::Result<()> {
    let contents = keypair.encode_base64();
    std::fs::write(path, contents)?;
    Ok(())
}

/// Read from file as Base64 encoded `privkey` and return a AuthorityKeyPair.
pub fn read_authority_keypair_from_file<P: AsRef<std::path::Path>>(
    path: P,
) -> anyhow::Result<AuthorityKeyPair> {
    let contents = std::fs::read_to_string(path)?;
    AuthorityKeyPair::decode_base64(contents.as_str().trim()).map_err(|e| anyhow!(e))
}

/// Read from file as Base64 encoded `flag || privkey` and return a SuiKeypair.
pub fn read_keypair_from_file<P: AsRef<std::path::Path>>(
    path: P,
) -> anyhow::Result<NetworkKeyPair> {
    let contents = std::fs::read_to_string(path)?;
    NetworkKeyPair::decode_base64(contents.as_str().trim()).map_err(|e| anyhow!(e))
}

/// Read from file as Base64 encoded `flag || privkey` and return a NetworkKeyPair.
pub fn read_network_keypair_from_file<P: AsRef<std::path::Path>>(
    path: P,
) -> anyhow::Result<NetworkKeyPair> {
    read_keypair_from_file(path)
}

/// Generate a keypair from the specified RNG (useful for testing with seedable rngs).
pub fn get_network_key_pair_from_rng<R>(csprng: &mut R) -> NetworkKeyPair
where
    R: rand_core::CryptoRng + rand_core::RngCore,
{
    NetworkKeyPair::generate(csprng)
}
