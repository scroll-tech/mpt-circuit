use crate::{serde::SMTTrace, types::Proof, MPTProofType};
use ethers_core::types::{Address, U256};
use mpt_zktrie::state::{builder::HASH_SCHEME_DONE, witness::WitnessGenerator, ZktrieState};

fn initial_generator() -> WitnessGenerator {
    assert!(*HASH_SCHEME_DONE);
    let mut generator = WitnessGenerator::from(&ZktrieState::default());
    for i in 1..10 {
        generator.handle_new_state(
            mpt_zktrie::mpt_circuits::MPTProofType::BalanceChanged,
            Address::repeat_byte(i),
            U256::one(),
            U256::zero(),
            None,
        );
    }
    generator
}

fn initial_storage_generator() -> WitnessGenerator {
    let mut generator = initial_generator();
    for i in 40..60 {
        generator.handle_new_state(
            mpt_zktrie::mpt_circuits::MPTProofType::StorageChanged,
            Address::repeat_byte(1),
            U256::one(),
            U256::zero(),
            Some(U256::from(i)),
        );
    }
    generator
}

// Produce a trace where old and new have been swapped.
fn reverse(trace: SMTTrace) -> SMTTrace {
    let mut reversed = trace;
    reversed.account_path.reverse();
    reversed.account_update.reverse();
    reversed.state_path.reverse();
    if let Some(update) = reversed.state_update.as_mut() {
        update.reverse()
    }
    reversed
}

#[test]
fn empty_account_type_1() {
    let mut generator = initial_generator();
    let trace = generator.handle_new_state(
        mpt_zktrie::mpt_circuits::MPTProofType::AccountDoesNotExist,
        Address::zero(),
        U256::zero(),
        U256::zero(),
        None,
    );

    let json = serde_json::to_string_pretty(&trace).unwrap();
    assert_eq!(
        format!("{}\n", json),
        include_str!("traces/empty_account_type_1.json"),
        "{}",
        json
    );
    let trace: SMTTrace = serde_json::from_str(&json).unwrap();

    for path in &trace.account_path {
        assert!(path.leaf.is_some(), "account is not type 1");
    }

    let proof = Proof::from((MPTProofType::AccountDoesNotExist, trace));
    proof.check();
}

#[test]
fn existing_account_balance_update() {
    let mut generator = initial_generator();
    let trace = generator.handle_new_state(
        mpt_zktrie::mpt_circuits::MPTProofType::BalanceChanged,
        Address::repeat_byte(2),
        U256::from(1231412),
        U256::one(),
        None,
    );

    let json = serde_json::to_string_pretty(&trace).unwrap();
    assert_eq!(
        format!("{}\n", json),
        include_str!("traces/existing_account_balance_update.json"),
        "{}",
        json
    );
    let trace: SMTTrace = serde_json::from_str(&json).unwrap();
    let proof = Proof::from((MPTProofType::BalanceChanged, trace));
    proof.check();
}

#[test]
fn empty_account_type_1_balance_update() {
    let mut generator = initial_generator();
    let trace = generator.handle_new_state(
        mpt_zktrie::mpt_circuits::MPTProofType::BalanceChanged,
        Address::zero(),
        U256::from(200),
        U256::zero(),
        None,
    );

    assert!(
        trace.account_update[0].is_none() && trace.account_path[0].leaf.is_some(),
        "old account is not type 1"
    );

    let json = serde_json::to_string_pretty(&trace).unwrap();
    assert_eq!(
        format!("{}\n", json),
        include_str!("traces/empty_account_type_1_balance_update.json"),
        "{}",
        json
    );

    let trace: SMTTrace = serde_json::from_str(&json).unwrap();
    let proof = Proof::from((MPTProofType::BalanceChanged, trace));
    proof.check();
}

#[test]
fn existing_account_nonce_update() {
    let mut generator = initial_generator();
    let trace = generator.handle_new_state(
        mpt_zktrie::mpt_circuits::MPTProofType::NonceChanged,
        Address::repeat_byte(4),
        U256::one(),
        U256::zero(),
        None,
    );

    let json = serde_json::to_string_pretty(&trace).unwrap();
    assert_eq!(
        format!("{}\n", json),
        include_str!("traces/existing_account_nonce_update.json"),
        "{}",
        json
    );
    let trace: SMTTrace = serde_json::from_str(&json).unwrap();
    let proof = Proof::from((MPTProofType::NonceChanged, trace));
    proof.check();
}

#[test]
fn empty_account_type_1_nonce_update() {
    let mut generator = initial_generator();
    let trace = generator.handle_new_state(
        mpt_zktrie::mpt_circuits::MPTProofType::BalanceChanged,
        Address::repeat_byte(11),
        U256::from(200),
        U256::zero(),
        None,
    );

    assert!(
        trace.account_update[0].is_none() && trace.account_path[0].leaf.is_some(),
        "old account is not type 1"
    );

    let json = serde_json::to_string_pretty(&trace).unwrap();
    assert_eq!(
        format!("{}\n", json),
        include_str!("traces/empty_account_type_1_nonce_update.json"),
        "{}",
        json
    );

    let trace: SMTTrace = serde_json::from_str(&json).unwrap();
    let proof = Proof::from((MPTProofType::BalanceChanged, trace));
    proof.check();
}

#[test]
fn existing_account_code_size_update() {
    let mut generator = initial_generator();
    let trace = generator.handle_new_state(
        mpt_zktrie::mpt_circuits::MPTProofType::CodeSizeExists,
        Address::repeat_byte(4),
        U256::from(2342114),
        U256::zero(),
        None,
    );

    assert!(
        trace.account_update[0].is_some(),
        "old account does not exist"
    );

    let json = serde_json::to_string_pretty(&trace).unwrap();
    assert_eq!(
        format!("{}\n", json),
        include_str!("traces/existing_account_code_size_update.json"),
        "{}",
        json
    );
    let trace: SMTTrace = serde_json::from_str(&json).unwrap();
    let proof = Proof::from((MPTProofType::CodeSizeExists, trace));
    proof.check();
}

#[test]
fn existing_account_keccak_codehash_update() {
    let mut generator = initial_generator();
    let trace = generator.handle_new_state(
        mpt_zktrie::mpt_circuits::MPTProofType::CodeHashExists,
        Address::repeat_byte(8),
        U256([1111, u64::MAX, 444, 555]),
        U256::zero(),
        None,
    );

    let json = serde_json::to_string_pretty(&trace).unwrap();
    assert_eq!(
        format!("{}\n", json),
        include_str!("traces/existing_account_keccak_codehash_update.json"),
        "{}",
        json
    );
    let trace: SMTTrace = serde_json::from_str(&json).unwrap();
    let proof = Proof::from((MPTProofType::CodeHashExists, trace));
    proof.check();
}

#[test]
fn existing_account_poseidon_codehash_update() {
    let mut generator = initial_generator();
    let trace = generator.handle_new_state(
        mpt_zktrie::mpt_circuits::MPTProofType::PoseidonCodeHashExists,
        Address::repeat_byte(4),
        U256([u64::MAX, u64::MAX, u64::MAX, 2342]),
        U256::zero(),
        None,
    );

    let json = serde_json::to_string_pretty(&trace).unwrap();
    assert_eq!(
        format!("{}\n", json),
        include_str!("traces/existing_account_poseidon_codehash_update.json"),
        "{}",
        json
    );
    let trace: SMTTrace = serde_json::from_str(&json).unwrap();
    let proof = Proof::from((MPTProofType::PoseidonCodeHashExists, trace));
    proof.check();
}

#[test]
fn existing_storage_update() {
    let mut generator = initial_generator();

    for i in 40..60 {
        generator.handle_new_state(
            mpt_zktrie::mpt_circuits::MPTProofType::StorageChanged,
            Address::repeat_byte(1),
            U256::one(),
            U256::zero(),
            Some(U256::from(i)),
        );
    }

    let trace = generator.handle_new_state(
        mpt_zktrie::mpt_circuits::MPTProofType::StorageChanged,
        Address::repeat_byte(1),
        U256::from(20),
        U256::one(),
        Some(U256::from(40)),
    );

    let json = serde_json::to_string_pretty(&trace).unwrap();
    assert_eq!(
        format!("{}\n", json),
        include_str!("traces/existing_storage_update.json"),
        "{}",
        json
    );
    let trace: SMTTrace = serde_json::from_str(&json).unwrap();
    let proof = Proof::from((MPTProofType::StorageChanged, trace));
    proof.check();
}

#[test]
fn empty_storage_type_1_update_a() {
    let mut generator = initial_storage_generator();
    let trace = generator.handle_new_state(
        mpt_zktrie::mpt_circuits::MPTProofType::StorageChanged,
        Address::repeat_byte(1),
        U256::from(307),
        U256::zero(),
        Some(U256::from(23412321)),
    );
    assert!(
        trace.state_path[0].clone().unwrap().leaf.is_some(),
        "old storage entry is not type 1"
    );

    let json = serde_json::to_string_pretty(&trace).unwrap();
    assert_eq!(
        format!("{}\n", json),
        include_str!("traces/empty_storage_type_1_update_a.json"),
        "{}",
        json
    );
    let trace: SMTTrace = serde_json::from_str(&json).unwrap();
    assert_eq!(
        trace.state_path[0]
            .clone()
            .unwrap()
            .path
            .last()
            .unwrap()
            .node_type,
        7
    );

    let insertion_proof = Proof::from((MPTProofType::StorageChanged, trace.clone()));
    insertion_proof.check();

    let deletion_proof = Proof::from((MPTProofType::StorageChanged, reverse(trace)));
    deletion_proof.check();
}

#[test]
fn empty_storage_type_1_update_b() {
    let mut generator = initial_storage_generator();
    let trace = generator.handle_new_state(
        mpt_zktrie::mpt_circuits::MPTProofType::StorageChanged,
        Address::repeat_byte(1),
        U256::from(307),
        U256::zero(),
        Some(U256::from(1)),
    );
    assert!(
        trace.state_path[0].clone().unwrap().leaf.is_some(),
        "old storage entry is not type 1"
    );

    let json = serde_json::to_string_pretty(&trace).unwrap();
    assert_eq!(
        format!("{}\n", json),
        include_str!("traces/empty_storage_type_1_update_b.json"),
        "{}",
        json
    );
    let trace: SMTTrace = serde_json::from_str(&json).unwrap();
    assert_eq!(
        trace.state_path[0]
            .clone()
            .unwrap()
            .path
            .last()
            .unwrap()
            .node_type,
        8
    );

    let insertion_proof = Proof::from((MPTProofType::StorageChanged, trace.clone()));
    insertion_proof.check();

    let deletion_proof = Proof::from((MPTProofType::StorageChanged, reverse(trace)));
    deletion_proof.check();
}

#[test]
fn empty_storage_type_1_update_c() {
    let mut generator = initial_storage_generator();
    let trace = generator.handle_new_state(
        mpt_zktrie::mpt_circuits::MPTProofType::StorageChanged,
        Address::repeat_byte(1),
        U256::from(307),
        U256::zero(),
        Some(U256::from(3)),
    );
    assert!(
        trace.state_path[0].clone().unwrap().leaf.is_some(),
        "old storage entry is not type 1"
    );

    let json = serde_json::to_string_pretty(&trace).unwrap();
    assert_eq!(
        format!("{}\n", json),
        include_str!("traces/empty_storage_type_1_update_c.json"),
        "{}",
        json
    );
    let trace: SMTTrace = serde_json::from_str(&json).unwrap();
    assert_eq!(
        trace.state_path[0]
            .clone()
            .unwrap()
            .path
            .last()
            .unwrap()
            .node_type,
        6
    );

    let insertion_proof = Proof::from((MPTProofType::StorageChanged, trace.clone()));
    insertion_proof.check();

    let deletion_proof = Proof::from((MPTProofType::StorageChanged, reverse(trace)));
    deletion_proof.check();
}

#[test]
fn insert_into_singleton_storage_trie() {
    let mut generator = initial_generator();
    generator.handle_new_state(
        mpt_zktrie::mpt_circuits::MPTProofType::StorageChanged,
        Address::repeat_byte(1),
        U256([1, 2, 3, 4]),
        U256::zero(),
        Some(U256([10, 20, 30, 40])),
    );

    let trace = generator.handle_new_state(
        mpt_zktrie::mpt_circuits::MPTProofType::StorageChanged,
        Address::repeat_byte(1),
        U256([5, 6, 7, 8]),
        U256::zero(),
        Some(U256([50, 60, 70, 80])),
    );

    let json = serde_json::to_string_pretty(&trace).unwrap();
    assert_eq!(
        format!("{}\n", json),
        include_str!("traces/insert_into_singleton_storage_trie.json"),
        "{}",
        json
    );
    let trace: SMTTrace = serde_json::from_str(&json).unwrap();
    let proof = Proof::from((MPTProofType::StorageChanged, trace));
    proof.check();
}

#[ignore = "type 2 empty account proofs are incomplete"]
#[test]
fn empty_account_type_2() {
    // i = 20 should be type 2?
    for i in 104..255 {
        dbg!(i);
        let mut generator = initial_generator();
        let trace = generator.handle_new_state(
            mpt_zktrie::mpt_circuits::MPTProofType::BalanceChanged,
            Address::repeat_byte(i),
            U256::one(),
            U256::zero(),
            None,
        );
        // 0xb3e9ff02c109b1d6aefa774523aaf5bef1207226e85a3726ecb505227ad1e621

        let json = serde_json::to_string_pretty(&trace).unwrap();
        let trace: SMTTrace = serde_json::from_str(&json).unwrap();

        dbg!(trace.clone());

        // for path in &trace.account_path {
        //     assert!(path.leaf.is_some() || path.path.is_empty())
        // }
        panic!();
    }

    // dbg!(trace.clone());

    // let proof = Proof::from((MPTProofType::AccountDoesNotExist, trace));
    panic!();
}
