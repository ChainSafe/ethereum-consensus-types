use alloc::{vec, vec::Vec};
use ssz_rs::prelude::*;

use crate::primitives::{Root, Slot, ValidatorIndex};

/// The header of a block on the beacon chain
///
/// See https://github.com/ethereum/annotated-spec/blob/master/phase0/beacon-chain.md#beaconblockheader
#[derive(Default, Debug, SimpleSerialize, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BeaconBlockHeader {
    #[cfg_attr(feature = "serde", serde(with = "crate::as_str"))]
    pub slot: Slot,
    #[cfg_attr(feature = "serde", serde(with = "crate::as_str"))]
    pub proposer_index: ValidatorIndex,
    pub parent_root: Root,
    pub state_root: Root,
    pub body_root: Root,
}
