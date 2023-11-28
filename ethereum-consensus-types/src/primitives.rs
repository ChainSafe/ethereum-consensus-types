use alloc::{vec, vec::Vec};
pub use ssz_rs::prelude::U256;
use ssz_rs::prelude::*;

#[derive(Debug, Default, Clone, PartialEq, SimpleSerialize, Eq)]
pub struct ByteVector<const N: usize>(pub Vector<u8, N>);
#[derive(Default, Debug, Clone, PartialEq, Eq, SimpleSerialize)]
pub struct ByteList<const N: usize>(pub List<u8, N>);

pub type Bytes32 = ByteVector<32>;

pub type Root = Node;
pub type Slot = u64;
pub type Epoch = u64;

pub type CommitteeIndex = usize;
pub type ValidatorIndex = usize;
pub type WithdrawalIndex = usize;
pub type BlobIndex = u64;
pub type Gwei = u64;
pub type Hash32 = Bytes32;

pub type Version = [u8; 4];
pub type ForkDigest = [u8; 4];
pub type Domain = [u8; 32];

pub type ExecutionAddress = ByteVector<20>;

pub type ChainId = usize;
pub type NetworkId = usize;

pub type ParticipationFlags = u8;

impl<const N: usize> AsRef<[u8]> for ByteVector<N> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<const N: usize> AsRef<[u8]> for ByteList<N> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[cfg(feature = "serde")]
impl<const N: usize> serde::Serialize for ByteVector<N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        crate::as_hex::serialize(&self.0, serializer)
    }
}
#[cfg(feature = "serde")]
impl<const N: usize> serde::Serialize for ByteList<N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        crate::as_hex::serialize(&self.0, serializer)
    }
}
#[cfg(feature = "serde")]
impl<'de, const N: usize> serde::Deserialize<'de> for ByteVector<N> {
    fn deserialize<D>(deserializer: D) -> Result<ByteVector<N>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let v: Vector<u8, N> = crate::as_hex::deserialize::<D, Vector<u8, N>>(deserializer)
            .map_err(|_| {
                serde::de::Error::custom("ByteVector failed to parse bytes from hex data")
            })?;
        Ok(ByteVector(v))
    }
}
#[cfg(feature = "serde")]
impl<'de, const N: usize> serde::Deserialize<'de> for ByteList<N> {
    fn deserialize<D>(deserializer: D) -> Result<ByteList<N>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let v: List<u8, N> =
            crate::as_hex::deserialize::<D, List<u8, N>>(deserializer).map_err(|_| {
                serde::de::Error::custom("ByteList failed to parse bytes from hex data")
            })?;
        Ok(ByteList(v))
    }
}
