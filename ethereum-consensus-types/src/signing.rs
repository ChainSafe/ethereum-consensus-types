use alloc::{vec, vec::Vec};
use ssz_rs::prelude::*;

use crate::primitives::{Domain, Root, Version};

#[derive(Default, Debug, SimpleSerialize)]
pub struct SigningData {
    pub object_root: Root,
    pub domain: Domain,
}

pub fn compute_signing_root(
    object_root: Node,
    domain: Domain,
) -> Result<Root, ssz_rs::MerkleizationError> {
    let mut s = SigningData {
        object_root,
        domain,
    };
    s.hash_tree_root()
}

#[derive(Clone, Copy)]
pub enum DomainType {
    SyncCommittee = 7,
}

impl DomainType {
    pub fn as_bytes(&self) -> [u8; 4] {
        let data = *self as u32;
        data.to_le_bytes()
    }
}

pub fn compute_domain(
    domain_type: DomainType,
    fork_data: &ForkData,
) -> Result<Domain, ssz_rs::MerkleizationError> {
    let fork_data_root = fork_data.clone().hash_tree_root()?;
    let mut domain = Domain::default();
    domain[..4].copy_from_slice(&domain_type.as_bytes());
    domain[4..].copy_from_slice(&fork_data_root.as_ref()[..28]);
    Ok(domain)
}

#[derive(Default, Debug, SimpleSerialize, Clone)]
pub struct ForkData {
    pub fork_version: Version,
    pub genesis_validators_root: Root,
}

impl ForkData {
    pub fn fork_digest(&self) -> [u8; 4] {
        let root = self.clone().hash_tree_root().unwrap();
        let mut digest = [0; 4];
        digest.copy_from_slice(&root.as_ref()[0..4]);
        digest
    }
}
