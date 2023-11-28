#![cfg(test)]
#![allow(unused, unused_variables)]
use ethereum_consensus::crypto::{PublicKey, Signature};
use ethereum_consensus::ssz;
use ethereum_consensus_types::bls::BlsSignature;
use ethereum_consensus_types::{
    BeaconBlockHeader, LightClientUpdate, SyncAggregate, SyncCommittee,
};
use rstest::rstest;
use serde::Deserialize;
use ssz_rs::prelude::*;
use ssz_rs::{deserialize, serialize, Bitvector, DeserializeError};
use std::path::PathBuf;
use test_utils::loader::{load_snappy_ssz, load_yaml, TestCase};

#[derive(Debug, Deserialize)]
struct RootYaml {
    pub root: Node,
}

#[rstest]
#[cfg(feature = "serde")]
fn test_sync_aggregate(
    #[files("../consensus-spec-tests/tests/minimal/altair/ssz_static/SyncAggregate/**/case_*/")]
    case: PathBuf,
) {
    ssz_static_test_with_yaml::<SyncAggregate<32>>(&case);
}

#[rstest]
#[cfg(feature = "serde")]
fn test_sync_commitee(
    #[files("../consensus-spec-tests/tests/minimal/altair/ssz_static/SyncCommittee/**/case_*/")]
    case: PathBuf,
) {
    ssz_static_test_with_yaml::<SyncCommittee<32>>(&case);
}

#[rstest]
#[cfg(feature = "serde")]
fn test_beacon_block_header(
    #[files(
        "../consensus-spec-tests/tests/minimal/altair/ssz_static/BeaconBlockHeader/**/case_*/"
    )]
    case: PathBuf,
) {
    ssz_static_test_with_yaml::<BeaconBlockHeader>(&case);
}

#[rstest]
#[cfg(feature = "serde")]
fn test_light_client_update(
    #[files(
        "../consensus-spec-tests/tests/minimal/altair/ssz_static/LightClientUpdate/**/case_*/"
    )]
    case: PathBuf,
) {
    ssz_static_test_no_yaml::<LightClientUpdate<32, 23, 5, 41, 6>>(&case);
}

#[allow(clippy::ptr_arg)]
/// This is a test for when the container does not support deserialization from YAML
/// It deserialized from SSZ bytes and checks the Merkle root matches the one defined by the test
fn ssz_static_test_no_yaml<
    T: SimpleSerialize + PartialEq + core::fmt::Debug + Clone + Sized,
>(
    case: &PathBuf,
) {
    // next read the ssz snappy file
    let mut ssz_snappy_path = case.clone();
    ssz_snappy_path.push("serialized.ssz_snappy");
    let ssz_snappy_path = ssz_snappy_path.to_str().unwrap();
    let container_ssz_snappy: T = load_snappy_ssz(ssz_snappy_path).unwrap();

    // now read the `roots.yaml` file
    let mut root_yaml_path = case.clone();
    root_yaml_path.push("roots.yaml");
    let root_yaml_path = root_yaml_path.to_str().unwrap();
    let root_yaml: RootYaml = load_yaml(root_yaml_path);

    // check the merkle root matches
    let merkle_root = container_ssz_snappy.clone().hash_tree_root().unwrap();
    assert_eq!(root_yaml.root, merkle_root);
}

/// Test for when the container does support deserialization from YAML
/// It deserialized from YAML and from SSZ and checks the two types match
fn ssz_static_test_with_yaml<
    'a,
    T: SimpleSerialize
        + for<'de> serde::Deserialize<'de>
        + PartialEq
        + core::fmt::Debug
        + Clone
        + Sized,
>(
    case: &PathBuf,
) {
    // do the no yaml test as well for good measure
    ssz_static_test_no_yaml::<T>(case);

    // first, read the value.yaml
    let mut values_yaml_path = case.clone();
    values_yaml_path.push("value.yaml");
    let values_yaml_path = values_yaml_path.to_str().unwrap();

    // next read the ssz snappy file
    let container: T = load_yaml(values_yaml_path);
    let mut ssz_snappy_path = case.clone();
    ssz_snappy_path.push("serialized.ssz_snappy");
    let ssz_snappy_path = ssz_snappy_path.to_str().unwrap();
    let container_ssz_snappy: T = load_snappy_ssz(ssz_snappy_path).unwrap();

    // check that both these are identical
    assert_eq!(container, container_ssz_snappy);
}
