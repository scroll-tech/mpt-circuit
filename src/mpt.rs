use crate::{
    constraint_builder::{ConstraintBuilder, SelectorColumn},
    gadgets::{
        byte_bit::ByteBitGadget,
        byte_representation::ByteRepresentationConfig,
        canonical_representation::CanonicalRepresentationConfig,
        key_bit::KeyBitConfig,
        mpt_update::{
            byte_representations, key_bit_lookups, mpt_update_keys, MptUpdateConfig,
            MptUpdateLookup,
        },
        poseidon::PoseidonLookup,
        rlc_randomness::RlcRandomness,
    },
    types::Proof,
};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::Layouter,
    halo2curves::bn256::Fr,
    plonk::{Challenge, ConstraintSystem, Error, Expression, VirtualCells},
};

/// Config for MptCircuit
#[derive(Clone)]
pub struct MptCircuitConfig {
    selector: SelectorColumn,
    rlc_randomness: RlcRandomness,
    mpt_update: MptUpdateConfig,
    canonical_representation: CanonicalRepresentationConfig,
    key_bit: KeyBitConfig,
    byte_bit: ByteBitGadget,
    byte_representation: ByteRepresentationConfig,
}

impl MptCircuitConfig {
    pub fn configure(
        cs: &mut ConstraintSystem<Fr>,
        evm_word_challenge: Challenge,
        poseidon: &impl PoseidonLookup,
    ) -> Self {
        let selector = SelectorColumn(cs.fixed_column());
        let rlc_randomness = RlcRandomness(evm_word_challenge);
        let mut cb = ConstraintBuilder::new(selector);

        let byte_bit = ByteBitGadget::configure(cs, &mut cb);
        let byte_representation =
            ByteRepresentationConfig::configure(cs, &mut cb, &byte_bit, &rlc_randomness);
        let canonical_representation =
            CanonicalRepresentationConfig::configure(cs, &mut cb, &byte_bit, &rlc_randomness);
        let key_bit = KeyBitConfig::configure(
            cs,
            &mut cb,
            &canonical_representation,
            &byte_bit,
            &byte_bit,
            &byte_bit,
        );

        let mpt_update = MptUpdateConfig::configure(
            cs,
            &mut cb,
            poseidon,
            &key_bit,
            &byte_representation,
            &byte_representation,
            &rlc_randomness,
            &canonical_representation,
        );

        cb.build(cs);

        Self {
            selector,
            rlc_randomness,
            mpt_update,
            key_bit,
            byte_bit,
            canonical_representation,
            byte_representation,
        }
    }

    pub fn assign(
        &self,
        layouter: &mut impl Layouter<Fr>,
        proofs: &[Proof],
        n_rows: usize,
    ) -> Result<(), Error> {
        let randomness = self.rlc_randomness.value(layouter);
        let (u64s, u128s, frs) = byte_representations(proofs);

        layouter.assign_region(
            || "mpt circuit",
            |mut region| {
                for offset in 0..n_rows {
                    self.selector.enable(&mut region, offset);
                }

                // pad canonical_representation to fixed count
                // notice each input cost 32 rows in canonical_representation, and inside
                // assign one extra input is added
                let keys = mpt_update_keys(proofs);
                let total_rep_size = n_rows / 32 - 1;
                assert!(
                    total_rep_size >= keys.len(),
                    "no enough space for canonical representation of all keys (need {})",
                    keys.len()
                );

                self.canonical_representation.assign(
                    &mut region,
                    randomness,
                    keys.iter()
                        .chain(std::iter::repeat(&Fr::zero()))
                        .take(total_rep_size),
                );
                self.key_bit.assign(&mut region, &key_bit_lookups(proofs));
                self.byte_bit.assign(&mut region);
                self.byte_representation
                    .assign(&mut region, &u64s, &u128s, &frs, randomness);

                let n_assigned_rows = self.mpt_update.assign(&mut region, proofs, randomness);

                assert!(
                    n_assigned_rows <= n_rows,
                    "mpt circuit requires {n_assigned_rows} rows > limit of {n_rows} rows"
                );

                for offset in n_assigned_rows..n_rows {
                    self.mpt_update.assign_padding_row(&mut region, offset);
                }

                Ok(())
            },
        )
    }

    pub fn lookup_exprs<F: FieldExt>(&self, meta: &mut VirtualCells<'_, F>) -> [Expression<F>; 8] {
        self.mpt_update.lookup().map(|q| q.run(meta))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{gadgets::poseidon::PoseidonTable, hash_traces, serde::SMTTrace, MPTProofType};
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        dev::MockProver,
        halo2curves::bn256::Fr,
        plonk::{Circuit, Error, FirstPhase},
    };
    use lazy_static::lazy_static;

    const N_ROWS: usize = 1024;

    lazy_static! {
        static ref EMPTY_STORAGE_PROOF_TYPE_2: (MPTProofType, SMTTrace) = (
            MPTProofType::StorageDoesNotExist,
            serde_json::from_str(include_str!(
                "../tests/generated/storage/empty_storage_proof_type_2.json"
            ))
            .unwrap(),
        );
        static ref NONCE_WRITE_TYPE_2_EMPTY_ACCOUNT: (MPTProofType, SMTTrace) = (
            MPTProofType::NonceChanged,
            serde_json::from_str(include_str!(
                "../tests/dual_code_hash/nonce_write_type_2_empty_account.json"
            ))
            .unwrap(),
        );
        static ref EMPTY_ACCOUNT_PROOF_TYPE_2: (MPTProofType, SMTTrace) = (
            MPTProofType::AccountDoesNotExist,
            serde_json::from_str(include_str!(
                "../tests/dual_code_hash/type_2_empty_account.json"
            ))
            .unwrap(),
        );
        static ref EMPTY_STORAGE_PROOF_SINGLETON_TRIE: (MPTProofType, SMTTrace) = (
            MPTProofType::StorageDoesNotExist,
            serde_json::from_str(include_str!(
                "../tests/generated/storage/empty_storage_proof_singleton_trie.json"
            ))
            .unwrap(),
        );
    }

    #[derive(Clone, Debug, Default)]
    struct TestCircuit {
        n_rows: usize,
        proofs: Vec<Proof>,
    }

    impl TestCircuit {
        fn new(n_rows: usize, traces: Vec<(MPTProofType, SMTTrace)>) -> Self {
            Self {
                n_rows,
                proofs: traces.into_iter().map(Proof::from).collect(),
            }
        }
    }

    impl Circuit<Fr> for TestCircuit {
        type Config = (PoseidonTable, MptCircuitConfig);
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(cs: &mut ConstraintSystem<Fr>) -> Self::Config {
            let poseidon = PoseidonTable::configure(cs);
            let challenge = cs.challenge_usable_after(FirstPhase);
            let mpt_circuit_config = MptCircuitConfig::configure(cs, challenge, &poseidon);
            (poseidon, mpt_circuit_config)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            let (poseidon, mpt_circuit_config) = config;
            mpt_circuit_config.assign(&mut layouter, &self.proofs, self.n_rows)?;
            layouter.assign_region(
                || "load poseidon table",
                |mut region| Ok(poseidon.load(&mut region, &hash_traces(&self.proofs))),
            )
        }
    }

    fn mock_prove(proof_type: MPTProofType, trace: &str) {
        let circuit = TestCircuit::new(
            N_ROWS,
            vec![(proof_type, serde_json::from_str(trace).unwrap())],
        );
        let prover = MockProver::<Fr>::run(14, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_empty() {
        let circuit = TestCircuit {
            n_rows: N_ROWS,
            proofs: vec![],
        };
        let prover = MockProver::<Fr>::run(14, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn nonce_write_existing_account() {
        mock_prove(
            MPTProofType::NonceChanged,
            include_str!("../tests/dual_code_hash/nonce_write_existing_account.json"),
        );
    }

    #[test]
    fn nonce_write_type_1_empty_account() {
        mock_prove(
            MPTProofType::NonceChanged,
            include_str!("../tests/dual_code_hash/nonce_write_type_1_empty_account.json"),
        );
    }

    #[test]
    fn nonce_write_type_2_empty_account() {
        mock_prove(
            MPTProofType::NonceChanged,
            include_str!("../tests/dual_code_hash/nonce_write_type_2_empty_account.json"),
        );
    }

    #[test]
    fn nonce_update_existing() {
        mock_prove(
            MPTProofType::NonceChanged,
            include_str!("../tests/generated/nonce_update_existing.json"),
        );
    }

    #[test]
    fn nonce_update_type_1() {
        mock_prove(
            MPTProofType::NonceChanged,
            include_str!("../tests/generated/nonce_update_type_1.json"),
        );
    }

    #[test]
    fn nonce_update_type_2() {
        mock_prove(
            MPTProofType::NonceChanged,
            include_str!("../tests/generated/nonce_update_type_2.json"),
        );
    }

    #[test]
    fn balance_update_existing() {
        mock_prove(
            MPTProofType::BalanceChanged,
            include_str!("../tests/generated/balance_update_existing.json"),
        );
    }

    #[test]
    fn balance_update_type_1() {
        mock_prove(
            MPTProofType::BalanceChanged,
            include_str!("../tests/generated/balance_update_type_1.json"),
        );
    }

    #[test]
    fn balance_update_type_2() {
        mock_prove(
            MPTProofType::BalanceChanged,
            include_str!("../tests/generated/balance_update_type_2.json"),
        );
    }

    #[test]
    fn code_size_update_existing() {
        mock_prove(
            MPTProofType::CodeSizeExists,
            include_str!("../tests/generated/code_size_update_existing.json"),
        );
    }

    #[test]
    fn code_hash_update_existing() {
        mock_prove(
            MPTProofType::PoseidonCodeHashExists,
            include_str!("../tests/generated/code_hash_update_existing.json"),
        );
    }

    #[test]
    fn keccak_code_hash_update_existing() {
        mock_prove(
            MPTProofType::CodeHashExists, // yes, the naming is very confusing :/
            include_str!("../tests/generated/keccak_code_hash_update_existing.json"),
        );
    }

    #[test]
    fn keccak_code_hash_read_existing() {
        mock_prove(
            MPTProofType::CodeHashExists, // yes, the naming is very confusing :/
            include_str!("../tests/generated/keccak_code_hash_read_existing.json"),
        );
    }

    #[test]
    fn update_storage_existing_to_existing() {
        mock_prove(
            MPTProofType::StorageChanged,
            include_str!("../tests/generated/storage/update_storage_existing_to_existing.json"),
        );
    }

    #[test]
    fn nonexisting_type_1() {
        mock_prove(
            MPTProofType::AccountDoesNotExist,
            include_str!("../tests/dual_code_hash/type_1_empty_account.json"),
        );
    }

    #[test]
    fn write_empty_storage_trie() {
        mock_prove(
            MPTProofType::StorageChanged,
            include_str!("../tests/generated/storage/write_empty_storage_trie.json"),
        );
    }

    #[test]
    fn nonexisting_type_2() {
        mock_prove(
            MPTProofType::AccountDoesNotExist,
            include_str!("../tests/dual_code_hash/type_2_empty_account.json"),
        );
    }

    #[test]
    fn write_singleton_storage_trie() {
        mock_prove(
            MPTProofType::StorageChanged,
            include_str!("../tests/generated/storage/write_singleton_storage_trie.json"),
        );
    }

    #[test]
    fn write_zero_singleton_storage_trie() {
        mock_prove(
            MPTProofType::StorageChanged,
            include_str!("../tests/generated/storage/write_zero_singleton_storage_trie.json"),
        );
    }

    #[test]
    fn write_zero_doubleton_storage_trie() {
        mock_prove(
            MPTProofType::StorageChanged,
            include_str!("../tests/generated/storage/write_zero_doubleton_storage_trie.json"),
        );
    }

    #[test]
    fn write_zero_storage_trie() {
        mock_prove(
            MPTProofType::StorageChanged,
            include_str!("../tests/generated/storage/write_zero_storage_trie.json"),
        );
    }

    #[test]
    fn empty_storage_proof_empty_trie() {
        mock_prove(
            MPTProofType::StorageDoesNotExist,
            include_str!("../tests/generated/storage/empty_storage_proof_empty_trie.json"),
        );
    }

    #[test]
    fn empty_storage_proof_singleton_trie() {
        mock_prove(
            MPTProofType::StorageDoesNotExist,
            include_str!("../tests/generated/storage/empty_storage_proof_singleton_trie.json"),
        );
    }

    #[test]
    fn empty_storage_proof_type_1() {
        mock_prove(
            MPTProofType::StorageDoesNotExist,
            include_str!("../tests/generated/storage/empty_storage_proof_type_1.json"),
        );
    }

    #[test]
    fn empty_storage_proof_type_2() {
        mock_prove(
            MPTProofType::StorageDoesNotExist,
            include_str!("../tests/generated/storage/empty_storage_proof_type_2.json"),
        );
    }

    #[test]
    fn prove_updates() {
        let updates = vec![
            EMPTY_STORAGE_PROOF_TYPE_2.clone(),
            EMPTY_STORAGE_PROOF_SINGLETON_TRIE.clone(),
            EMPTY_ACCOUNT_PROOF_TYPE_2.clone(),
            NONCE_WRITE_TYPE_2_EMPTY_ACCOUNT.clone(),
        ];

        let circuit = TestCircuit::new(N_ROWS, updates);
        let prover = MockProver::<Fr>::run(14, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn empty_account_empty_storage() {
        mock_prove(
            MPTProofType::StorageDoesNotExist,
            include_str!("../tests/generated/storage/empty_account_empty_storage_proof.json"),
        );
    }

    #[test]
    fn degree() {
        let mut meta = ConstraintSystem::<Fr>::default();
        TestCircuit::configure(&mut meta);
        assert_eq!(meta.degree(), 9);
    }

    /*
    #[test]
    fn uniswapv2_factory_create_pair() {
        let updates = serde_json::from_str(include_str!(
            "../../tests/mock_test_traces/uniswapv2_factory-createPair.json"
        ))
        .unwrap();
        let circuit = TestCircuit::new(4096, updates);
        let prover = MockProver::<Fr>::run(16, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
    */
}
