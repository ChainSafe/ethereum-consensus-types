use crate::bls::{BlsPublicKey, BlsSignature};
use crate::VerificationError;
use alloc::{vec, vec::Vec};
use ssz_rs::prelude::*;

/// A sync aggregate is an aggregate signature from a subset of members of a sync
/// committee plus a bitvec indicating which members signed.
#[derive(Clone, Debug, Eq, PartialEq, Default, SimpleSerialize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SyncAggregate<const SYNC_COMMITTEE_SIZE: usize> {
    pub sync_committee_bits: Bitvector<SYNC_COMMITTEE_SIZE>,
    pub sync_committee_signature: BlsSignature,
}

impl<const SYNC_COMMITTEE_SIZE: usize> SyncAggregate<SYNC_COMMITTEE_SIZE> {
    /// Verify that enough sync committee members have contributed their signature to the sync aggregate
    pub fn verify_participation(&self) -> Result<(), VerificationError> {
        let participation = self.sync_committee_bits.iter().filter(|b| **b).count();
        if participation * 3 >= SYNC_COMMITTEE_SIZE * 2 {
            Ok(())
        } else {
            Err(VerificationError::InsufficientParticipation)
        }
    }
}

/// The sync committee is a list of validators that are responsible for
/// signing off finalized blocks during their sync period.
/// It is fully defined by the list of the public keys and an aggregate public key
#[derive(Clone, Debug, Default, Eq, PartialEq, SimpleSerialize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SyncCommittee<const SYNC_COMMITTEE_SIZE: usize> {
    pub pubkeys: Vector<BlsPublicKey, SYNC_COMMITTEE_SIZE>,
    pub aggregate_pubkey: BlsPublicKey,
}

impl<const SYNC_COMMITTEE_SIZE: usize> SyncCommittee<SYNC_COMMITTEE_SIZE> {
    /// Given a bitvec indication participation compute the aggregate public key.
    /// Returns None if no members participated and aggregation is impossible
    pub fn aggregate_pubkey(
        &self,
        participation: &Bitvector<SYNC_COMMITTEE_SIZE>,
    ) -> Option<BlsPublicKey> {
        participation
            .iter()
            .zip(self.pubkeys.iter().cloned())
            .filter_map(
                |(partipated, key)| {
                    if *partipated {
                        Some(key)
                    } else {
                        None
                    }
                },
            )
            .reduce(|agg, key| agg.aggregate(key).unwrap())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_participation() {
        const SYNC_COMMITTEE_SIZE: usize = 12;
        let mut aggregate = SyncAggregate::<SYNC_COMMITTEE_SIZE>::default();
        for i in 0..SYNC_COMMITTEE_SIZE {
            aggregate.sync_committee_bits.set(i, true);
            if (i + 1) * 3 >= SYNC_COMMITTEE_SIZE * 2 {
                assert!(aggregate.verify_participation().is_ok());
            } else {
                assert!(aggregate.verify_participation().is_err());
            }
        }
    }
}
