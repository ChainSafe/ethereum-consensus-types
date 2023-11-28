#![cfg_attr(not(feature = "serde"), no_std)]

pub mod beacon_block_header;
pub mod light_client;
pub mod presets;
pub mod primitives;
pub mod signing;
pub mod sync_committee;
pub mod bls;

extern crate alloc;

pub use beacon_block_header::BeaconBlockHeader;
pub use light_client::{
    LightClientBootstrap, LightClientFinalityUpdate, LightClientHeader, LightClientUpdate,
    LightClientUpdateCapella,
};
pub use primitives::*;
pub use signing::ForkData;
pub use sync_committee::{SyncAggregate, SyncCommittee};
pub use bls::{BlsPublicKey, BlsSignature};

#[derive(Debug)]
pub enum VerificationError {
    BlsError(bls::BlsError),
    MerklizationError(ssz_rs::MerkleizationError),
    NoSigners,
    InsufficientParticipation,
}

impl From<bls::BlsError> for VerificationError {
    fn from(e: bls::BlsError) -> Self {
        Self::BlsError(e)
    }
}

impl From<ssz_rs::MerkleizationError> for VerificationError {
    fn from(e: ssz_rs::MerkleizationError) -> Self {
        Self::MerklizationError(e)
    }
}

#[cfg(feature = "serde")]
pub mod as_str {
    use core::fmt::Display;
    use core::str::FromStr;
    use serde::Deserialize;

    pub fn serialize<S, T: Display>(data: T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(&data.to_string())
    }

    pub fn deserialize<'de, D, T, E>(deserializer: D) -> Result<T, D::Error>
    where
        D: serde::Deserializer<'de>,
        T: FromStr<Err = E>,
        E: Display,
    {
        let s = String::deserialize(deserializer)?;
        T::from_str(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(feature = "serde")]
pub mod as_hex {

    use serde::Deserialize;

    const HEX_ENCODING_PREFIX: &str = "0x";

    pub fn try_bytes_from_hex_str(s: &str) -> Result<Vec<u8>, hex::FromHexError> {
        let target = s.strip_prefix(HEX_ENCODING_PREFIX).unwrap_or(s);
        let data = hex::decode(target)?;
        Ok(data)
    }

    pub fn serialize<S, T: AsRef<[u8]>>(data: T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let encoding = hex::encode(data.as_ref());
        let output = format!("{HEX_ENCODING_PREFIX}{encoding}");
        serializer.collect_str(&output)
    }

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
    where
        D: serde::Deserializer<'de>,
        T: for<'a> TryFrom<Vec<u8>>,
    {
        let str = String::deserialize(deserializer)?;

        let data = try_bytes_from_hex_str(&str).map_err(serde::de::Error::custom)?;

        T::try_from(data)
            .map_err(|_| serde::de::Error::custom("type failed to parse bytes from hex data"))
    }
}
