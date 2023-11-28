//! A thin wrapper around BLST with a more more idiomatic and ergonomic API
use alloc::string::{String, ToString};
use alloc::{vec, vec::Vec};
use ssz_rs::prelude::*;

use blst::min_pk as bls;
use blst::BLST_ERROR;

// domain string, must match what is used in signing. This one should be good for beacon chain
const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

pub const BLS_SIGNATURE_BYTES_LEN: usize = 96;
pub const BLS_PUBLIC_KEY_BYTES_LEN: usize = 48;

#[derive(Debug, Clone, Default, Eq, PartialEq, SimpleSerialize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "String"))]
pub struct BlsPublicKey(Vector<u8, BLS_PUBLIC_KEY_BYTES_LEN>);

#[derive(Debug, Clone, Default, Eq, PartialEq, SimpleSerialize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "String"))]
pub struct BlsSignature(Vector<u8, BLS_SIGNATURE_BYTES_LEN>);

impl BlsPublicKey {
    pub fn aggregate(self, other: Self) -> Result<Self, BlsError> {
        let self_ = bls::PublicKey::from_bytes(&self.0)?;
        let other = bls::PublicKey::from_bytes(&other.0)?;

        let mut aggkey: bls::AggregatePublicKey = bls::AggregatePublicKey::from_public_key(&self_);
        aggkey.add_public_key(&other, false)?;

        let result_bytes = aggkey.to_public_key().to_bytes();
        // can unwrap here as we know the signature will always be a valid length byte array
        Ok(Self(result_bytes.to_vec().try_into().unwrap()))
    }

    pub fn verify_signature(&self, msg: &[u8], signature: &BlsSignature) -> Result<(), BlsError> {
        let signature = bls::Signature::from_bytes(&signature.0)?;
        let public_key = bls::PublicKey::from_bytes(&self.0)?;

        let res = signature.verify(true, msg, DST, &[], &public_key, true);
        if res == BLST_ERROR::BLST_SUCCESS {
            Ok(())
        } else {
            Err(BlsError::InvalidSignature)
        }
    }
    pub fn decompressed_bytes(&self) -> Vec<u8> {
        let pk_uncomp = bls::PublicKey::uncompress(&self.0).unwrap();
        pk_uncomp.serialize().to_vec()
    }

    pub fn to_bytes(&self) -> &[u8] {
        &self.0
    }
}
impl BlsSignature {
    pub fn to_bytes(&self) -> &[u8] {
        &self.0
    }
}
#[cfg(feature = "serde")]
impl TryFrom<String> for BlsSignature {
    type Error = String;
    fn try_from(hex_string: String) -> Result<Self, Self::Error> {
        // convert a hex-encoded String into a Vec<u8> array.
        let mut iter = hex_string.chars();
        let hex_string: String = if hex_string.starts_with("0x") {
            iter.next();
            iter.next();
            iter.collect()
        } else {
            hex_string
        };

        let bytes: Vec<u8> = hex::decode(hex_string).unwrap();

        // FIXME: How do I return the Vector<u8, 96>` type?
        match Vector::<u8, BLS_SIGNATURE_BYTES_LEN>::try_from(bytes) {
            Ok(v) => Ok(BlsSignature(v)),
            Err(e) => Err(alloc::format!("{e:?}")),
        }
    }
}

#[cfg(feature = "serde")]
impl TryFrom<String> for BlsPublicKey {
    type Error = String;
    fn try_from(hex_string: String) -> Result<Self, Self::Error> {
        let mut iter = hex_string.chars();
        let hex_string: String = if hex_string.starts_with("0x") {
            iter.next();
            iter.next();
            iter.collect()
        } else {
            hex_string
        };
        let bytes: Vec<u8> = hex::decode(hex_string).unwrap();
        match Vector::<u8, BLS_PUBLIC_KEY_BYTES_LEN>::try_from(bytes) {
            Ok(v) => Ok(BlsPublicKey(v)),
            Err(e) => Err(alloc::format!("{e:?}")),
        }
    }
}

#[derive(Debug)]
pub enum BlsError {
    InvalidSignature,
    Other(String),
}

impl From<BLST_ERROR> for BlsError {
    fn from(value: BLST_ERROR) -> Self {
        assert!(value != BLST_ERROR::BLST_SUCCESS);
        Self::Other(format_args!("{:?}", value).to_string())
    }
}

impl From<String> for BlsError {
    fn from(value: String) -> Self {
        Self::Other(value)
    }
}
