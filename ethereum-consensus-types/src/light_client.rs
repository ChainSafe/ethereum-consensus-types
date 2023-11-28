use core::ops::Deref;

use crate::signing::{compute_domain, compute_signing_root, DomainType, ForkData};
use crate::{BeaconBlockHeader, SyncAggregate, SyncCommittee, VerificationError};
use crate::{ByteList, ByteVector, Bytes32, ExecutionAddress, Root, Slot};
use alloc::{vec, vec::Vec};
use ssz_rs::prelude::*;
use ssz_rs::Merkleized;

/// Captures all data needed to prove a new sync committee is valid given a prior trusted sync committee
/// for the previous sync period.
///
/// See https://github.com/ethereum/annotated-spec/blob/master/altair/sync-protocol.md#lightclientupdate
#[derive(Clone, Default, Debug, Eq, PartialEq, SimpleSerialize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LightClientUpdate<
    const SYNC_COMMITTEE_SIZE: usize,
    const NEXT_SYNC_COMMITTEE_GINDEX: usize,
    const NEXT_SYNC_COMMITTEE_PROOF_SIZE: usize,
    const FINALIZED_ROOT_GINDEX: usize,
    const FINALIZED_ROOT_PROOF_SIZE: usize,
> {
    pub attested_header: BeaconBlockHeader,
    pub next_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
    pub next_sync_committee_branch: Vector<Node, NEXT_SYNC_COMMITTEE_PROOF_SIZE>,
    pub finalized_header: BeaconBlockHeader,
    pub finality_branch: Vector<Node, FINALIZED_ROOT_PROOF_SIZE>,
    pub sync_aggregate: SyncAggregate<SYNC_COMMITTEE_SIZE>,
    #[cfg_attr(feature = "serde", serde(with = "crate::as_str"))]
    pub signature_slot: Slot,
}

#[derive(Clone, Default, Debug, Eq, PartialEq, SimpleSerialize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LightClientUpdateCapella<
    const SYNC_COMMITTEE_SIZE: usize,
    const NEXT_SYNC_COMMITTEE_GINDEX: usize,
    const NEXT_SYNC_COMMITTEE_PROOF_SIZE: usize,
    const FINALIZED_ROOT_GINDEX: usize,
    const FINALIZED_ROOT_PROOF_SIZE: usize,
    const BYTES_PER_LOGS_BLOOM: usize,
    const MAX_EXTRA_DATA_BYTES: usize,
> {
    pub attested_header: LightClientHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
    pub next_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
    pub next_sync_committee_branch: Vector<Node, NEXT_SYNC_COMMITTEE_PROOF_SIZE>,
    pub finalized_header: LightClientHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
    pub finality_branch: Vector<Node, FINALIZED_ROOT_PROOF_SIZE>,
    pub sync_aggregate: SyncAggregate<SYNC_COMMITTEE_SIZE>,
    #[cfg_attr(feature = "serde", serde(with = "crate::as_str"))]
    pub signature_slot: Slot,
}

impl<
        const SYNC_COMMITTEE_SIZE: usize,
        const NEXT_SYNC_COMMITTEE_GINDEX: usize,
        const NEXT_SYNC_COMMITTEE_PROOF_SIZE: usize,
        const FINALIZED_ROOT_GINDEX: usize,
        const FINALIZED_ROOT_PROOF_SIZE: usize,
    >
    LightClientUpdate<
        SYNC_COMMITTEE_SIZE,
        NEXT_SYNC_COMMITTEE_GINDEX,
        NEXT_SYNC_COMMITTEE_PROOF_SIZE,
        FINALIZED_ROOT_GINDEX,
        FINALIZED_ROOT_PROOF_SIZE,
    >
{
    pub fn verify(
        &self,
        fork_data: &ForkData,
        committee: &SyncCommittee<SYNC_COMMITTEE_SIZE>,
    ) -> Result<bool, VerificationError> {
        self.sync_aggregate.verify_participation()?;
        self.verify_signature(fork_data, committee)?;
        Ok(
            self.verify_proofs()?
                && self.verify_next_sync_committee()?
                && self.verify_finality()?,
        )
    }

    /// Verify that the signature included in sync_aggregate is valid for the given sync committee.
    /// This is done by aggregating the committee public keys according to the sync committee bits and using this
    /// to check the signature over the finalized_header.
    pub fn verify_signature(
        &self,
        fork_data: &ForkData,
        committee: &SyncCommittee<SYNC_COMMITTEE_SIZE>,
    ) -> Result<(), VerificationError> {
        let aggregate_sig = committee
            .aggregate_pubkey(&self.sync_aggregate.sync_committee_bits)
            .ok_or(VerificationError::NoSigners)?;

        let signing_domain = compute_domain(DomainType::SyncCommittee, fork_data)?;
        aggregate_sig.verify_signature(
            compute_signing_root(
                self.attested_header.clone().hash_tree_root()?,
                signing_domain,
            )?
            .as_ref(),
            &self.sync_aggregate.sync_committee_signature,
        )?;

        Ok(())
    }

    /// Verifies that this data structure is consistent with itself by
    /// checking both included Merkle proofs against its fields
    pub fn verify_proofs(&self) -> Result<bool, VerificationError> {
        Ok(self.verify_next_sync_committee()? && self.verify_finality()?)
    }

    /// Verifies the `next_sync_committee` field of this struct is valid by
    /// checking a merkle proof that the committee is contained in the state which is
    /// rooted in the` attested_header`.
    pub fn verify_next_sync_committee(&self) -> Result<bool, VerificationError> {
        let next_sync_committee_root = self.next_sync_committee.clone().hash_tree_root().unwrap();
        Ok(is_valid_merkle_branch(
            next_sync_committee_root,
            &self
                .next_sync_committee_branch
                .iter()
                .map(|node| node.deref())
                .collect::<Vec<_>>(),
            NEXT_SYNC_COMMITTEE_PROOF_SIZE,
            NEXT_SYNC_COMMITTEE_GINDEX,
            self.attested_header.state_root,
        )
        .is_ok())
    }

    /// Verifies the given attested_header has been finalized by checking a merkle proof
    /// that it is contained in the `finalized_checkpoint` field in the state rooted
    /// in the given `finalized_header`.
    pub fn verify_finality(&self) -> Result<bool, VerificationError> {
        let finalized_block_root = self.finalized_header.clone().hash_tree_root().unwrap();
        Ok(is_valid_merkle_branch(
            finalized_block_root,
            &self
                .finality_branch
                .iter()
                .map(|node| node.deref())
                .collect::<Vec<_>>(),
            FINALIZED_ROOT_PROOF_SIZE,
            FINALIZED_ROOT_GINDEX,
            self.attested_header.state_root,
        )
        .is_ok())
    }
}

#[derive(Default, Debug, Clone, SimpleSerialize, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExecutionPayloadHeader<
    const BYTES_PER_LOGS_BLOOM: usize,
    const MAX_EXTRA_DATA_BYTES: usize,
> {
    pub parent_hash: Root,
    pub fee_recipient: ExecutionAddress,
    pub state_root: Root,
    pub receipts_root: Root,
    pub logs_bloom: ByteVector<BYTES_PER_LOGS_BLOOM>,
    pub prev_randao: Root,
    #[cfg_attr(feature = "serde", serde(with = "crate::as_str"))]
    pub block_number: u64,
    #[cfg_attr(feature = "serde", serde(with = "crate::as_str"))]
    pub gas_limit: u64,
    #[cfg_attr(feature = "serde", serde(with = "crate::as_str"))]
    pub gas_used: u64,
    #[cfg_attr(feature = "serde", serde(with = "crate::as_str"))]
    pub timestamp: u64,
    pub extra_data: ByteList<MAX_EXTRA_DATA_BYTES>,
    pub base_fee_per_gas: U256,
    pub block_hash: Root,
    pub transactions_root: Root,
    pub withdrawals_root: Root,
}

#[derive(Clone, Default, Debug, Eq, PartialEq, SimpleSerialize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LightClientHeader<const BYTES_PER_LOGS_BLOOM: usize, const MAX_EXTRA_DATA_BYTES: usize> {
    pub beacon: BeaconBlockHeader,
    pub execution: ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
    pub execution_branch: Vector<Bytes32, 4>,
}

#[derive(Clone, Default, Debug, Eq, PartialEq, SimpleSerialize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LightClientBootstrap<
    const SYNC_COMMITTEE_SIZE: usize,
    const NEXT_SYNC_COMMITTEE_PROOF_SIZE: usize,
    const BYTES_PER_LOGS_BLOOM: usize,
    const MAX_EXTRA_DATA_BYTES: usize,
> {
    pub header: LightClientHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
    pub current_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
    pub current_sync_committee_branch: Vector<Node, NEXT_SYNC_COMMITTEE_PROOF_SIZE>,
}

#[derive(Default, Debug, Eq, PartialEq, Clone, SimpleSerialize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LightClientFinalityUpdate<
    const SYNC_COMMITTEE_SIZE: usize,
    const FINALIZED_ROOT_PROOF_SIZE: usize,
    const BYTES_PER_LOGS_BLOOM: usize,
    const MAX_EXTRA_DATA_BYTES: usize,
> {
    pub attested_header: LightClientHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
    pub finalized_header: LightClientHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
    pub finality_branch: Vector<Bytes32, FINALIZED_ROOT_PROOF_SIZE>,
    pub sync_aggregate: SyncAggregate<SYNC_COMMITTEE_SIZE>,
    #[cfg_attr(feature = "serde", serde(with = "crate::as_str"))]
    pub signature_slot: Slot,
}
