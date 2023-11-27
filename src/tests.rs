use crate::{circuit::TestCircuit, serde::SMTTrace, types::Proof, MPTProofType, MptCircuitConfig};
use ethers_core::types::{Address, U256};
use halo2_proofs::{
    dev::MockProver,
    halo2curves::bn256::{Bn256, Fr},
    plonk::{keygen_vk, Circuit, ConstraintSystem},
    poly::kzg::commitment::ParamsKZG,
};
use mpt_zktrie::state::{builder::HASH_SCHEME_DONE, witness::WitnessGenerator, ZktrieState};
use rand_chacha::rand_core::SeedableRng;

const N_ROWS: usize = 8 * 256 + 1;
const STORAGE_ADDRESS: Address = Address::repeat_byte(1);

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
            STORAGE_ADDRESS,
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

fn mock_prove(witness: Vec<(MPTProofType, SMTTrace)>) {
    let circuit = TestCircuit::new(N_ROWS, witness);
    let prover = MockProver::<Fr>::run(14, &circuit, vec![]).unwrap();
    assert_eq!(prover.verify(), Ok(()),);
}

#[test]
fn degree() {
    let mut meta = ConstraintSystem::<Fr>::default();
    TestCircuit::configure(&mut meta);
    assert_eq!(meta.degree(), 9);
}

#[test]
fn verifying_key_constant() {
    let params = ParamsKZG::<Bn256>::setup(17, rand_chacha::ChaCha20Rng::seed_from_u64(2));

    let no_updates = TestCircuit::new(N_ROWS, vec![]);
    let one_update = TestCircuit::new(
        N_ROWS,
        vec![(
            MPTProofType::BalanceChanged,
            serde_json::from_str(&include_str!(
                "traces/empty_account_type_1_balance_update.json"
            ))
            .unwrap(),
        )],
    );
    let vk_no_updates = keygen_vk(&params, &no_updates).unwrap();
    let vk_one_update = keygen_vk(&params, &one_update).unwrap();

    assert_eq!(
        vk_no_updates.fixed_commitments(),
        vk_one_update.fixed_commitments()
    );
    assert_eq!(
        vk_no_updates.permutation().commitments(),
        vk_one_update.permutation().commitments()
    );
}

#[test]
fn all_padding() {
    mock_prove(vec![]);
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

    assert_eq!(trace.account_update, [None, None], "account is not empty");
    for path in &trace.account_path {
        assert!(path.leaf.is_some(), "account is not type 1");
    }

    let proof = Proof::from((MPTProofType::AccountDoesNotExist, trace.clone()));
    proof.check();

    mock_prove(vec![(MPTProofType::AccountDoesNotExist, trace)]);
}

#[test]
fn empty_account_type_2() {
    let mut generator = initial_generator();
    let trace = generator.handle_new_state(
        mpt_zktrie::mpt_circuits::MPTProofType::AccountDoesNotExist,
        Address::repeat_byte(20),
        U256::zero(),
        U256::zero(),
        None,
    );

    let json = serde_json::to_string_pretty(&trace).unwrap();
    assert_eq!(
        format!("{}\n", json),
        include_str!("traces/empty_account_type_2.json"),
        "{}",
        json
    );
    let trace: SMTTrace = serde_json::from_str(&json).unwrap();

    assert_eq!(trace.account_update, [None, None], "account is not empty");
    for path in &trace.account_path {
        assert!(path.leaf.is_none(), "account is not type 2");
    }

    let proof = Proof::from((MPTProofType::AccountDoesNotExist, trace.clone()));
    proof.check();

    mock_prove(vec![(MPTProofType::AccountDoesNotExist, trace)]);
}

#[test]
fn empty_account_proofs_for_zero_value_updates() {
    let traces: [SMTTrace; 2] = [
        serde_json::from_str(&include_str!("traces/empty_account_type_1.json")).unwrap(),
        serde_json::from_str(&include_str!("traces/empty_account_type_2.json")).unwrap(),
    ];
    for trace in traces {
        for proof_type in [
            MPTProofType::BalanceChanged,
            MPTProofType::NonceChanged,
            MPTProofType::CodeSizeExists,
            MPTProofType::CodeHashExists,
            // poseidon code hash is not in this list because the state (rw) circuit will
            // translate mpt lookups where the old and new poseidon code hash = 0 in account
            // nonexistence proof lookups.
        ] {
            mock_prove(vec![(proof_type, trace.clone())]);
        }
    }
}

#[test]
fn empty_mpt_empty_account_proofs_for_zero_value_updates() {
    assert!(*HASH_SCHEME_DONE);
    let mut generator = WitnessGenerator::from(&ZktrieState::default());
    let trace = generator.handle_new_state(
        mpt_zktrie::mpt_circuits::MPTProofType::AccountDoesNotExist,
        Address::repeat_byte(232),
        U256::zero(),
        U256::zero(),
        None,
    );
    let json = serde_json::to_string_pretty(&trace).unwrap();
    let type_1_trace: SMTTrace = serde_json::from_str(&json).unwrap();

    let mut generator = WitnessGenerator::from(&ZktrieState::default());
    generator.handle_new_state(
        mpt_zktrie::mpt_circuits::MPTProofType::BalanceChanged,
        Address::repeat_byte(1),
        U256::from(23),
        U256::zero(),
        None,
    );

    let trace = generator.handle_new_state(
        mpt_zktrie::mpt_circuits::MPTProofType::AccountDoesNotExist,
        Address::repeat_byte(2),
        U256::zero(),
        U256::zero(),
        None,
    );
    let json = serde_json::to_string_pretty(&trace).unwrap();
    let type_2_trace: SMTTrace = serde_json::from_str(&json).unwrap();

    for proof_type in [
        MPTProofType::BalanceChanged,
        MPTProofType::NonceChanged,
        MPTProofType::CodeSizeExists,
        MPTProofType::CodeHashExists,
    ] {
        mock_prove(vec![(proof_type, type_1_trace.clone())]);
        mock_prove(vec![(proof_type, type_2_trace.clone())]);
    }
}

#[test]
fn empty_account_proofs_for_empty_storage_updates() {
    let type_1_address = Address::zero();
    let type_2_address = Address::repeat_byte(20);

    for address in [type_1_address, type_2_address] {
        let mut generator = initial_generator();
        let trace = generator.handle_new_state(
            mpt_zktrie::mpt_circuits::MPTProofType::StorageDoesNotExist,
            address,
            U256::zero(),
            U256::zero(),
            Some(U256::MAX),
        );

        let json = serde_json::to_string_pretty(&trace).unwrap();
        let trace: SMTTrace = serde_json::from_str(&json).unwrap();

        assert_eq!(trace.account_update, [None, None], "account is not empty");
        for path in &trace.account_path {
            assert!(
                if address == type_1_address {
                    path.leaf.is_some()
                } else {
                    path.leaf.is_none()
                },
                "account type incorrect"
            );
        }

        let proof = Proof::from((MPTProofType::StorageDoesNotExist, trace.clone()));
        proof.check();
        mock_prove(vec![(MPTProofType::StorageDoesNotExist, trace)]);
    }
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
    let proof = Proof::from((MPTProofType::BalanceChanged, trace.clone()));
    proof.check();

    mock_prove(vec![(MPTProofType::BalanceChanged, trace)]);
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
    let proof = Proof::from((MPTProofType::BalanceChanged, trace.clone()));
    proof.check();

    mock_prove(vec![(MPTProofType::BalanceChanged, trace)]);
}

#[test]
fn empty_account_type_2_balance_update() {
    let mut generator = initial_generator();
    let trace = generator.handle_new_state(
        mpt_zktrie::mpt_circuits::MPTProofType::BalanceChanged,
        Address::repeat_byte(20),
        U256::from(123124128387u64),
        U256::zero(),
        None,
    );

    let json = serde_json::to_string_pretty(&trace).unwrap();
    assert_eq!(
        format!("{}\n", json),
        include_str!("traces/empty_account_type_2_balance_update.json"),
        "{}",
        json
    );
    let trace: SMTTrace = serde_json::from_str(&json).unwrap();

    assert!(
        trace.account_update[0].is_none() && trace.account_path[0].leaf.is_none(),
        "old account is not type 2"
    );

    let proof = Proof::from((MPTProofType::BalanceChanged, trace.clone()));
    proof.check();

    mock_prove(vec![(MPTProofType::BalanceChanged, trace)]);
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
    let proof = Proof::from((MPTProofType::NonceChanged, trace.clone()));
    proof.check();

    mock_prove(vec![(MPTProofType::NonceChanged, trace)]);
}

#[test]
fn empty_account_type_1_nonce_update() {
    let mut generator = initial_generator();
    let trace = generator.handle_new_state(
        mpt_zktrie::mpt_circuits::MPTProofType::NonceChanged,
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
    let proof = Proof::from((MPTProofType::NonceChanged, trace.clone()));
    proof.check();

    mock_prove(vec![(MPTProofType::NonceChanged, trace)]);
}

#[test]
fn empty_account_type_2_nonce_update() {
    let mut generator = initial_generator();
    let trace = generator.handle_new_state(
        mpt_zktrie::mpt_circuits::MPTProofType::NonceChanged,
        Address::repeat_byte(20),
        U256::from(123124128387u64),
        U256::zero(),
        None,
    );

    let json = serde_json::to_string_pretty(&trace).unwrap();
    assert_eq!(
        format!("{}\n", json),
        include_str!("traces/empty_account_type_2_nonce_update.json"),
        "{}",
        json
    );
    let trace: SMTTrace = serde_json::from_str(&json).unwrap();

    assert!(
        trace.account_update[0].is_none() && trace.account_path[0].leaf.is_none(),
        "old account is not type 2"
    );

    let proof = Proof::from((MPTProofType::NonceChanged, trace.clone()));
    proof.check();

    mock_prove(vec![(MPTProofType::NonceChanged, trace)]);
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
    let proof = Proof::from((MPTProofType::CodeSizeExists, trace.clone()));
    proof.check();

    mock_prove(vec![(MPTProofType::CodeSizeExists, trace)]);
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
    let proof = Proof::from((MPTProofType::CodeHashExists, trace.clone()));
    proof.check();

    mock_prove(vec![(MPTProofType::CodeHashExists, trace)]);
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
    let proof = Proof::from((MPTProofType::PoseidonCodeHashExists, trace.clone()));
    proof.check();

    mock_prove(vec![(MPTProofType::PoseidonCodeHashExists, trace)]);
}

#[test]
fn existing_storage_update() {
    let mut generator = initial_storage_generator();
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
    let proof = Proof::from((MPTProofType::StorageChanged, trace.clone()));
    proof.check();

    mock_prove(vec![(MPTProofType::StorageChanged, trace)]);
}

#[test]
fn empty_storage_type_1_update_a() {
    let mut generator = initial_storage_generator();
    let trace = generator.handle_new_state(
        mpt_zktrie::mpt_circuits::MPTProofType::StorageChanged,
        STORAGE_ADDRESS,
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
    mock_prove(vec![(MPTProofType::StorageChanged, trace.clone())]);

    let deletion_proof = Proof::from((MPTProofType::StorageChanged, reverse(trace.clone())));
    deletion_proof.check();
    mock_prove(vec![(MPTProofType::StorageChanged, reverse(trace))]);
}

#[test]
fn empty_storage_type_2_update_a() {
    let mut generator = initial_storage_generator();
    let trace = generator.handle_new_state(
        mpt_zktrie::mpt_circuits::MPTProofType::StorageChanged,
        STORAGE_ADDRESS,
        U256::from(307),
        U256::zero(),
        Some(U256::from(502)),
    );
    assert!(
        trace.state_path[0].clone().unwrap().leaf.is_none(),
        "old storage entry is not type 2"
    );

    let json = serde_json::to_string_pretty(&trace).unwrap();
    assert_eq!(
        format!("{}\n", json),
        include_str!("traces/empty_storage_type_2_update_a.json"),
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
    mock_prove(vec![(MPTProofType::StorageChanged, trace.clone())]);

    let deletion_proof = Proof::from((MPTProofType::StorageChanged, reverse(trace.clone())));
    deletion_proof.check();
    mock_prove(vec![(MPTProofType::StorageChanged, reverse(trace))]);
}

#[test]
fn empty_storage_type_2_update_b() {
    let mut generator = initial_storage_generator();
    let trace = generator.handle_new_state(
        mpt_zktrie::mpt_circuits::MPTProofType::StorageChanged,
        STORAGE_ADDRESS,
        U256::from(307),
        U256::zero(),
        Some(U256::from(500)),
    );
    assert!(
        trace.state_path[0].clone().unwrap().leaf.is_none(),
        "old storage entry is not type 2"
    );

    let json = serde_json::to_string_pretty(&trace).unwrap();
    assert_eq!(
        format!("{}\n", json),
        include_str!("traces/empty_storage_type_2_update_b.json"),
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
    mock_prove(vec![(MPTProofType::StorageChanged, trace.clone())]);

    let deletion_proof = Proof::from((MPTProofType::StorageChanged, reverse(trace.clone())));
    deletion_proof.check();
    mock_prove(vec![(MPTProofType::StorageChanged, reverse(trace))]);
}

// Note: it's not possible to have a final node type == 6 for a type 2 empty leaf
// proof. This would be inconsistent because node type == 6 requires that neither
// child node the branch node is itself a branch node, while the leaf node being
// type 2 empty would require that one of the child nodes of the branch node is empty.
// The zktrie construction rules forbid the existence of a subtrie containing only
// one leaf.

#[test]
fn empty_storage_type_1_update_b() {
    let mut generator = initial_storage_generator();
    let trace = generator.handle_new_state(
        mpt_zktrie::mpt_circuits::MPTProofType::StorageChanged,
        STORAGE_ADDRESS,
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
    mock_prove(vec![(MPTProofType::StorageChanged, trace.clone())]);

    let deletion_proof = Proof::from((MPTProofType::StorageChanged, reverse(trace.clone())));
    deletion_proof.check();
    mock_prove(vec![(MPTProofType::StorageChanged, reverse(trace))]);
}

#[test]
fn empty_storage_type_1_update_c() {
    let mut generator = initial_storage_generator();
    let trace = generator.handle_new_state(
        mpt_zktrie::mpt_circuits::MPTProofType::StorageChanged,
        STORAGE_ADDRESS,
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
    mock_prove(vec![(MPTProofType::StorageChanged, trace.clone())]);

    let deletion_proof = Proof::from((MPTProofType::StorageChanged, reverse(trace.clone())));
    deletion_proof.check();
    mock_prove(vec![(MPTProofType::StorageChanged, reverse(trace))]);
}

#[test]
fn multiple_updates() {
    let witness = vec![
        (
            MPTProofType::StorageChanged,
            serde_json::from_str(&include_str!("traces/empty_storage_type_1_update_c.json"))
                .unwrap(),
        ),
        (
            MPTProofType::CodeHashExists,
            serde_json::from_str(&include_str!(
                "traces/existing_account_keccak_codehash_update.json"
            ))
            .unwrap(),
        ),
        (
            MPTProofType::BalanceChanged,
            serde_json::from_str(&include_str!(
                "traces/empty_account_type_2_balance_update.json"
            ))
            .unwrap(),
        ),
        (
            MPTProofType::AccountDoesNotExist,
            serde_json::from_str(&include_str!("traces/empty_account_type_1.json")).unwrap(),
        ),
    ];
    mock_prove(witness);
}

#[test]
fn empty_storage_trie() {
    let mut generator = initial_generator();
    let trace = generator.handle_new_state(
        mpt_zktrie::mpt_circuits::MPTProofType::StorageChanged,
        STORAGE_ADDRESS,
        U256::from(324123123u64),
        U256::zero(),
        Some(U256::from(3)),
    );

    let json = serde_json::to_string_pretty(&trace).unwrap();
    let trace: SMTTrace = serde_json::from_str(&json).unwrap();

    let insertion_proof = Proof::from((MPTProofType::StorageChanged, trace.clone()));
    insertion_proof.check();
    mock_prove(vec![(MPTProofType::StorageChanged, trace.clone())]);

    let deletion_proof = Proof::from((MPTProofType::StorageChanged, reverse(trace.clone())));
    deletion_proof.check();
    mock_prove(vec![(MPTProofType::StorageChanged, reverse(trace))]);
}

#[test]
fn singleton_storage_trie() {
    let mut generator = initial_generator();
    generator.handle_new_state(
        mpt_zktrie::mpt_circuits::MPTProofType::StorageChanged,
        Address::repeat_byte(2),
        U256::from(7),
        U256::zero(),
        Some(U256::from(2)),
    );
    let trace = generator.handle_new_state(
        mpt_zktrie::mpt_circuits::MPTProofType::StorageChanged,
        Address::repeat_byte(2),
        U256::from(4),
        U256::zero(),
        Some(U256::from(3)),
    );

    let json = serde_json::to_string_pretty(&trace).unwrap();
    let trace: SMTTrace = serde_json::from_str(&json).unwrap();

    let insertion_proof = Proof::from((MPTProofType::StorageChanged, trace.clone()));
    insertion_proof.check();
    mock_prove(vec![(MPTProofType::StorageChanged, trace.clone())]);

    let deletion_proof = Proof::from((MPTProofType::StorageChanged, reverse(trace.clone())));
    deletion_proof.check();
    mock_prove(vec![(MPTProofType::StorageChanged, reverse(trace))]);
}

#[test]
fn depth_1_type_1_storage() {
    // This tests the case where the hash domain for calculating the storage root changes
    // because of an insertion or deletion.

    let trace: SMTTrace =
        serde_json::from_str(&include_str!("traces/depth_1_type_1_storage.json")).unwrap();
    mock_prove(vec![(MPTProofType::StorageChanged, trace.clone())]);
    mock_prove(vec![(MPTProofType::StorageChanged, reverse(trace))]);
}

#[test]
fn depth_1_type_1_empty_storage() {
    let mut generator = initial_generator();
    for key in [2, 10] {
        generator.handle_new_state(
            mpt_zktrie::mpt_circuits::MPTProofType::StorageChanged,
            Address::repeat_byte(2),
            U256::from(7),
            U256::zero(),
            Some(U256::from(key)),
        );
    }
    let trace = generator.handle_new_state(
        mpt_zktrie::mpt_circuits::MPTProofType::StorageChanged,
        Address::repeat_byte(2),
        U256::zero(),
        U256::zero(),
        Some(U256::from(3)),
    );

    let json = serde_json::to_string_pretty(&trace).unwrap();
    let trace: SMTTrace = serde_json::from_str(&json).unwrap();

    let proof = Proof::from((MPTProofType::StorageDoesNotExist, trace.clone()));
    proof.check();
    mock_prove(vec![(MPTProofType::StorageDoesNotExist, trace)]);
}

#[test]
fn empty_storage_type_1() {
    let mut generator = initial_storage_generator();

    let trace = generator.handle_new_state(
        mpt_zktrie::mpt_circuits::MPTProofType::StorageChanged,
        STORAGE_ADDRESS,
        U256::zero(),
        U256::zero(),
        Some(U256::from(3)),
    );
    dbg!(trace.clone());
    assert!(
        trace.state_path[0].clone().unwrap().leaf.is_some(),
        "storage key = 3 is not type 1"
    );

    let json = serde_json::to_string_pretty(&trace).unwrap();
    let trace: SMTTrace = serde_json::from_str(&json).unwrap();

    mock_prove(vec![(MPTProofType::StorageDoesNotExist, trace)]);
}

#[test]
fn empty_storage_type_2() {
    let mut generator = initial_storage_generator();

    let trace = generator.handle_new_state(
        mpt_zktrie::mpt_circuits::MPTProofType::StorageChanged,
        STORAGE_ADDRESS,
        U256::zero(),
        U256::zero(),
        Some(U256::from(500)),
    );
    assert!(
        trace.state_path[0].clone().unwrap().leaf.is_none(),
        "storage key = 500 is not type 2"
    );

    let json = serde_json::to_string_pretty(&trace).unwrap();
    let trace: SMTTrace = serde_json::from_str(&json).unwrap();

    mock_prove(vec![(MPTProofType::StorageDoesNotExist, trace)]);
}

#[test]
fn empty_mpt() {
    assert!(*HASH_SCHEME_DONE);
    let mut generator = WitnessGenerator::from(&ZktrieState::default());
    let trace = generator.handle_new_state(
        mpt_zktrie::mpt_circuits::MPTProofType::BalanceChanged,
        Address::repeat_byte(2),
        U256::from(1231412),
        U256::zero(),
        None,
    );
    let json = serde_json::to_string_pretty(&trace).unwrap();
    let trace: SMTTrace = serde_json::from_str(&json).unwrap();

    mock_prove(vec![(MPTProofType::BalanceChanged, trace)]);
}

#[test]
fn empty_mpt_empty_account() {
    assert!(*HASH_SCHEME_DONE);
    let mut generator = WitnessGenerator::from(&ZktrieState::default());
    let trace = generator.handle_new_state(
        mpt_zktrie::mpt_circuits::MPTProofType::AccountDoesNotExist,
        Address::repeat_byte(232),
        U256::zero(),
        U256::zero(),
        None,
    );
    let json = serde_json::to_string_pretty(&trace).unwrap();
    let trace: SMTTrace = serde_json::from_str(&json).unwrap();

    mock_prove(vec![(MPTProofType::AccountDoesNotExist, trace)]);
}

#[test]
fn singleton_mpt() {
    assert!(*HASH_SCHEME_DONE);
    let mut generator = WitnessGenerator::from(&ZktrieState::default());
    generator.handle_new_state(
        mpt_zktrie::mpt_circuits::MPTProofType::BalanceChanged,
        Address::repeat_byte(1),
        U256::from(23),
        U256::zero(),
        None,
    );

    let trace = generator.handle_new_state(
        mpt_zktrie::mpt_circuits::MPTProofType::BalanceChanged,
        Address::repeat_byte(2),
        U256::from(15),
        U256::zero(),
        None,
    );
    let json = serde_json::to_string_pretty(&trace).unwrap();
    let trace: SMTTrace = serde_json::from_str(&json).unwrap();

    mock_prove(vec![(MPTProofType::BalanceChanged, trace)]);
}

#[test]
fn singleton_mpt_empty_account() {
    assert!(*HASH_SCHEME_DONE);
    let mut generator = WitnessGenerator::from(&ZktrieState::default());
    generator.handle_new_state(
        mpt_zktrie::mpt_circuits::MPTProofType::BalanceChanged,
        Address::repeat_byte(1),
        U256::from(23),
        U256::zero(),
        None,
    );

    let trace = generator.handle_new_state(
        mpt_zktrie::mpt_circuits::MPTProofType::AccountDoesNotExist,
        Address::repeat_byte(2),
        U256::zero(),
        U256::zero(),
        None,
    );
    let json = serde_json::to_string_pretty(&trace).unwrap();
    let trace: SMTTrace = serde_json::from_str(&json).unwrap();

    mock_prove(vec![(MPTProofType::AccountDoesNotExist, trace)]);
}

#[test]
fn create_name_registrator_per_txs_not_enough_gas_d0_g0_v0() {
    // These mpt updates are by the test case at
    // https://github.com/ethereum/tests/blob/747a4828f36c5fc8ab4f288d1cf4f1fe6662f3d6/src/GeneralStateTestsFiller/stCallCreateCallCodeTest/createNameRegistratorPerTxsNotEnoughGasFiller.json
    mock_prove(
        serde_json::from_str(&include_str!(
            "traces/createNameRegistratorPerTxsNotEnoughGas_d0_g0_v0.json"
        ))
        .unwrap(),
    );
}

#[test]
fn test_n_rows_required() {
    assert!(*HASH_SCHEME_DONE);
    let mut generator = WitnessGenerator::from(&ZktrieState::default());
    generator.handle_new_state(
        mpt_zktrie::mpt_circuits::MPTProofType::BalanceChanged,
        Address::repeat_byte(1),
        U256::from(23),
        U256::zero(),
        None,
    );

    let trace = generator.handle_new_state(
        mpt_zktrie::mpt_circuits::MPTProofType::AccountDoesNotExist,
        Address::repeat_byte(2),
        U256::zero(),
        U256::zero(),
        None,
    );
    let json = serde_json::to_string_pretty(&trace).unwrap();
    let trace: SMTTrace = serde_json::from_str(&json).unwrap();

    let witness = vec![(MPTProofType::AccountDoesNotExist, trace); 3000];
    let proofs: Vec<_> = witness.clone().into_iter().map(Proof::from).collect();

    let n_rows_required = MptCircuitConfig::n_rows_required(&proofs);

    let circuit = TestCircuit::new(n_rows_required, witness);
    let prover = MockProver::<Fr>::run(14, &circuit, vec![]).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn verify_benchmark_trace() {
    let witness: Vec<(MPTProofType, SMTTrace)> =
        serde_json::from_str(&include_str!("../benches/traces.json")).unwrap();
    let proofs: Vec<_> = witness.clone().into_iter().map(Proof::from).collect();

    let n_rows_required = MptCircuitConfig::n_rows_required(&proofs);

    let circuit = TestCircuit::new(n_rows_required, witness);
    let prover = MockProver::<Fr>::run(14, &circuit, vec![]).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}
