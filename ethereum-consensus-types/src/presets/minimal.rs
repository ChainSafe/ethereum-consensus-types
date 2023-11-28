pub const SYNC_COMMITTEE_SIZE: usize = 32;
pub const NEXT_SYNC_COMMITTEE_GINDEX: usize = 55;
pub const NEXT_SYNC_COMMITTEE_PROOF_SIZE: usize = 5;
pub const FINALIZED_ROOT_GINDEX: usize = 105;
pub const FINALIZED_ROOT_PROOF_SIZE: usize = 6;
pub const BYTES_PER_LOGS_BLOOM: usize = 256;
pub const MAX_EXTRA_DATA_BYTES: usize = 32;

pub type SyncAggregate = crate::SyncAggregate<SYNC_COMMITTEE_SIZE>;

pub type SyncCommittee = crate::SyncCommittee<SYNC_COMMITTEE_SIZE>;

pub type LightClientUpdate = crate::LightClientUpdate<
    SYNC_COMMITTEE_SIZE,
    NEXT_SYNC_COMMITTEE_GINDEX,
    NEXT_SYNC_COMMITTEE_PROOF_SIZE,
    FINALIZED_ROOT_GINDEX,
    FINALIZED_ROOT_PROOF_SIZE,
>;
pub type LightClientUpdateCapella = crate::LightClientUpdateCapella<
    SYNC_COMMITTEE_SIZE,
    NEXT_SYNC_COMMITTEE_GINDEX,
    NEXT_SYNC_COMMITTEE_PROOF_SIZE,
    FINALIZED_ROOT_GINDEX,
    FINALIZED_ROOT_PROOF_SIZE,
    BYTES_PER_LOGS_BLOOM,
    MAX_EXTRA_DATA_BYTES,
>;

pub type LightClientBootstrap = crate::LightClientBootstrap<
    SYNC_COMMITTEE_SIZE,
    NEXT_SYNC_COMMITTEE_PROOF_SIZE,
    BYTES_PER_LOGS_BLOOM,
    MAX_EXTRA_DATA_BYTES,
>;
