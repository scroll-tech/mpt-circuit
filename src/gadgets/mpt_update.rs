use super::{
    byte_representation::{BytesLookup, RlcLookup},
    is_zero::IsZeroGadget,
    key_bit::KeyBitLookup,
    poseidon::PoseidonLookup,
};
use crate::{
    constraint_builder::{AdviceColumn, BinaryColumn, ConstraintBuilder, Query, SelectorColumn},
    serde::SMTTrace,
    types::Proof,
};
use halo2_proofs::{
    arithmetic::FieldExt, circuit::Region, halo2curves::bn256::Fr, plonk::ConstraintSystem,
};

pub trait MptUpdateLookup {
    fn lookup<F: FieldExt>(&self) -> [Query<F>; 7];
}

#[derive(Clone)]
struct MptUpdateConfig {
    selector: SelectorColumn,

    old_hash: AdviceColumn, // when depth = 0 and is_account_path, old_hash = old_root
    new_hash: AdviceColumn, // when depth = 0 and is_account_path, new_hash = new_root

    old_value_rlc: AdviceColumn,
    new_value_rlc: AdviceColumn,

    proof_type: [BinaryColumn; 5],

    address: AdviceColumn,
    storage_key_rlc: AdviceColumn,

    // exactly one of these is 1.
    is_common_path: BinaryColumn,
    old_hash_is_unchanged: BinaryColumn,
    new_hash_is_unchanged: BinaryColumn,

    // exactly one of these is 1.
    is_account_path: BinaryColumn,
    is_account_leaf: BinaryColumn,
    is_storage_path: BinaryColumn,

    key: AdviceColumn,
    depth: AdviceColumn,
    depth_is_zero: IsZeroGadget,
    direction: AdviceColumn, // this actually must be binary because of a KeyBitLookup

    sibling: AdviceColumn,
}

impl MptUpdateLookup for MptUpdateConfig {
    fn lookup<F: FieldExt>(&self) -> [Query<F>; 7] {
        let is_root = || {
            self.depth_is_zero
                .current()
                .and(self.is_account_path.current())
        };
        let old_root = self.old_hash.current() * is_root();
        let new_root = self.new_hash.current() * is_root();
        // let proof_type = self
        //     .proof_type
        //     .iter()
        //     .enumerate()
        //     .map(|(i, column)| column.current() * i)
        //     .sum();
        let proof_type = Query::one();
        let old_value_rlc = self.new_value_rlc.current() * is_root();
        let new_value_rlc = self.old_value_rlc.current() * is_root();
        let address = self.address.current();
        let storage_key_rlc = self.storage_key_rlc.current();

        [
            old_root,
            new_root,
            old_value_rlc,
            new_value_rlc,
            proof_type,
            address,
            storage_key_rlc,
        ]
    }
}

impl MptUpdateConfig {
    fn configure<F: FieldExt>(
        cs: &mut ConstraintSystem<F>,
        cb: &mut ConstraintBuilder<F>,
        poseidon: &impl PoseidonLookup,
        key_bit: &impl KeyBitLookup,
        rlc: &impl RlcLookup,
        bytes: &impl BytesLookup,
    ) -> Self {
        let ([selector], [], [old_hash, new_hash]) = cb.build_columns(cs);

        let proof_type = cb.binary_columns(cs);
        let [address, storage_key_rlc] = cb.advice_columns(cs);

        let [old_value_rlc, new_value_rlc] = cb.advice_columns(cs);

        let [is_common_path, old_hash_is_unchanged, new_hash_is_unchanged] = cb.binary_columns(cs);
        let [is_account_path, is_account_leaf, is_storage_path] = cb.binary_columns(cs);

        let [depth, key, direction, sibling] = cb.advice_columns(cs);
        let depth_is_zero = IsZeroGadget::configure(cs, cb, selector.current(), depth);

        // constrain that exactly one of proof type is 1.

        cb.add_constraint(
            "exactly one of is_common_path, old_hash_is_unchanged, and new_hash_is_unchanged is 1",
            selector.current(),
            Query::from(is_common_path.current())
                + old_hash_is_unchanged.current()
                + new_hash_is_unchanged.current(),
        );

        cb.add_constraint(
            "exactly one of is_account_path, is_account_leaf, and is_storage_path is 1",
            selector.current(),
            Query::from(is_account_path.current())
                + is_account_leaf.current()
                + is_storage_path.current(),
        );

        // should be if path segment changes, then depth is 0. if not, it increases by 1.
        cb.add_constraint(
            "depth is 0 or depth increased by 1",
            selector.current(),
            depth.current() * (depth.current() - depth.previous() - 1),
        );
        cb.add_lookup(
            "direction is correct for key and depth",
            [key.current(), depth.current(), direction.current()],
            key_bit.lookup(),
        );
        let old_left = direction.current() * old_hash.previous()
            + (Query::one() - direction.current()) * sibling.previous();
        let old_right = direction.current() * sibling.previous()
            + (Query::one() - direction.current()) * old_hash.previous();
        cb.add_lookup(
            "poseidon hash correct for old path",
            [old_left, old_right, old_hash.current()],
            poseidon.lookup(),
        );
        // cb.add_lookup("poseidon hash correct for new path", [], poseidon.lookup());

        // Constraints for when proof_type = MPTProofType::NonceChanged
        // Constraints for when proof_type = MPTProofType::BalanceChanged
        // Constraints for when proof_type = MPTProofType::CodeHashExists
        // Constraints for when proof_type = MPTProofType::AccountDoesNotExist
        // Constraints for when proof_type = MPTProofType::AccountDestructed
        // Constraints for when proof_type = MPTProofType::StorageChanged
        // Constraints for when proof_type = MPTProofType::StorageDoesNotExist

        Self {
            selector,
            old_hash,
            new_hash,
            proof_type,
            old_value_rlc,
            new_value_rlc,
            address,
            storage_key_rlc,
            is_common_path,
            old_hash_is_unchanged,
            new_hash_is_unchanged,
            is_account_path,
            is_account_leaf,
            is_storage_path,
            key,
            depth,
            depth_is_zero,
            direction,
            sibling,
        }
    }

    fn assign(&self, region: &mut Region<'_, Fr>, updates: &[SMTTrace]) {
        let randomness = Fr::from(123123u64); // TODOOOOOOO

        let mut offset = 0;
        for update in updates {
            let proof = Proof::from(update.clone());

            for (direction, old_hash, new_hash, sibling, is_padding_open, is_padding_close) in
                &proof.address_hash_traces
            {
                self.selector.enable(region, offset);
                // self.address.assign(region, offset, proof.claim.address);
                // self.storage_key_rlc.assign(region, offset, rlc(proof.claim.storage_key, randomness));
                // self.new_value_rlc.assign(region, offset, ...)
                // self.old_value_rlc.assign(region, offset, ...)

                self.is_common_path.assign(
                    region,
                    offset,
                    !(*is_padding_open || *is_padding_close),
                );
                self.old_hash_is_unchanged
                    .assign(region, offset, *is_padding_open);
                self.new_hash_is_unchanged
                    .assign(region, offset, *is_padding_close);

                self.sibling.assign(region, offset, *sibling);
                self.new_hash.assign(region, offset, *new_hash);
                self.old_hash.assign(region, offset, *old_hash);

                offset += 1;
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::super::{
        byte_bit::ByteBitGadget, byte_representation::ByteRepresentationConfig,
        canonical_representation::CanonicalRepresentationConfig, key_bit::KeyBitConfig,
        poseidon::PoseidonConfig,
    };
    use super::*;
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        dev::MockProver,
        halo2curves::bn256::Fr,
        plonk::{Circuit, Error},
    };

    #[derive(Clone, Debug)]
    struct TestCircuit {
        updates: Vec<SMTTrace>,
    }

    impl TestCircuit {
        fn hash_traces(&self) -> Vec<(Fr, Fr, Fr)> {
            vec![]
        }

        fn keys(&self) -> Vec<Fr> {
            vec![]
        }
    }

    impl Circuit<Fr> for TestCircuit {
        type Config = (
            MptUpdateConfig,
            PoseidonConfig,
            CanonicalRepresentationConfig,
            KeyBitConfig,
            ByteBitGadget,
            ByteRepresentationConfig,
        );
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self { updates: vec![] }
        }

        fn configure(cs: &mut ConstraintSystem<Fr>) -> Self::Config {
            let mut cb = ConstraintBuilder::new();
            let poseidon = PoseidonConfig::configure(cs, &mut cb);
            let byte_bit = ByteBitGadget::configure(cs, &mut cb);
            let byte_representation = ByteRepresentationConfig::configure(cs, &mut cb, &byte_bit);
            let canonical_representation =
                CanonicalRepresentationConfig::configure(cs, &mut cb, &byte_bit);
            let key_bit = KeyBitConfig::configure(
                cs,
                &mut cb,
                &canonical_representation,
                &byte_bit,
                &byte_bit,
                &byte_bit,
            );

            let byte_representation = ByteRepresentationConfig::configure(cs, &mut cb, &byte_bit);

            let mpt_update = MptUpdateConfig::configure(
                cs,
                &mut cb,
                &poseidon,
                &key_bit,
                &byte_representation,
                &byte_representation,
            );

            cb.build(cs);
            (
                mpt_update,
                poseidon,
                canonical_representation,
                key_bit,
                byte_bit,
                byte_representation,
            )
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            let (
                mpt_update,
                poseidon,
                canonical_representation,
                key_bit,
                byte_bit,
                byte_representation,
            ) = config;

            layouter.assign_region(
                || "",
                |mut region| {
                    mpt_update.assign(&mut region, &self.updates);
                    poseidon.assign(&mut region, &self.hash_traces());
                    canonical_representation.assign(&mut region, &self.keys());
                    // key_bit.assign(region, &[]); // self.
                    byte_bit.assign(&mut region);
                    // byte_representation.assign(&mut region, &self.byte_representations())
                    Ok(())
                },
            )
        }
    }

    #[test]
    fn test_mpt_updates() {
        let circuit = TestCircuit { updates: vec![] };
        let prover = MockProver::<Fr>::run(14, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
