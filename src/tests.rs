use crate::{serde::SMTTrace, types::Proof, MPTProofType};
use ethers_core::types::{Address, U256};
use mpt_zktrie::state::{builder::HASH_SCHEME_DONE, witness::WitnessGenerator, ZktrieState};

fn intital_generator() -> WitnessGenerator {
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

#[test]
fn empty_account_type_1() {
    let mut generator = intital_generator();
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
    let mut generator = intital_generator();
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
    let mut generator = intital_generator();
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
    let mut generator = intital_generator();
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
    let mut generator = intital_generator();
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
    let mut generator = intital_generator();
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
    let mut generator = intital_generator();
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
    let mut generator = intital_generator();
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

#[ignore = "type 2 empty account proofs are incomplete"]
#[test]
fn empty_account_type_2() {
    // i = 20 should be type 2?
    for i in 104..255 {
        dbg!(i);
        let mut generator = intital_generator();
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
