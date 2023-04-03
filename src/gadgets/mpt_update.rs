use super::{
    byte_representation::{BytesLookup, RlcLookup},
    is_zero::IsZeroGadget,
    key_bit::KeyBitLookup,
    one_hot::OneHot,
    poseidon::PoseidonLookup,
};
use crate::{
    constraint_builder::{AdviceColumn, BinaryColumn, ConstraintBuilder, Query, SelectorColumn},
    serde::SMTTrace,
    types::Proof,
    MPTProofType,
};
use ethers_core::k256::elliptic_curve::PrimeField;
use ethers_core::types::{Address, H256, U256};
use halo2_proofs::{
    arithmetic::FieldExt, circuit::Region, halo2curves::bn256::Fr, plonk::ConstraintSystem,
};
use strum_macros::EnumIter;

/// Each row of an mpt update belongs to one of four segments.
#[derive(Clone, Copy, Debug, PartialEq, Eq, EnumIter)]
enum SegmentType {
    AccountTrie,
    AccountLeaf,
    StorageTrie,
    StorageLeaf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, EnumIter)]
enum PathType {
    Common, // Hashes for both the old and new path are being updated
    Old,    // the new hash is not changed. I.e. the new path ends in an non-existence proof.
    New,    // the old hash is not changed. I.e. the old path ends in an non-existence proof.
}

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

    proof_type: OneHot<MPTProofType>,

    address: AdviceColumn,
    storage_key_rlc: AdviceColumn,

    path_type: OneHot<PathType>,

    segment_type: OneHot<SegmentType>,
    depth: AdviceColumn, // depth of the current segment
    depth_is_zero: IsZeroGadget,

    key: AdviceColumn,
    direction: AdviceColumn, // this actually must be binary because of a KeyBitLookup

    sibling: AdviceColumn,
}

impl MptUpdateLookup for MptUpdateConfig {
    fn lookup<F: FieldExt>(&self) -> [Query<F>; 7] {
        let is_root = || {
            self.depth_is_zero
                .current()
                .and(self.segment_type.matches(SegmentType::AccountTrie))
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

        let proof_type = OneHot::configure(cs, cb);
        let [address, storage_key_rlc] = cb.advice_columns(cs);

        let [old_value_rlc, new_value_rlc] = cb.advice_columns(cs);

        let [depth, key, direction, sibling] = cb.advice_columns(cs);
        let depth_is_zero = IsZeroGadget::configure(cs, cb, selector.current(), depth);

        let segment_type = OneHot::configure(cs, cb);
        let path_type = OneHot::configure(cs, cb);

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

        let new_left = direction.current() * new_hash.previous()
            + (Query::one() - direction.current()) * sibling.previous();
        let new_right = direction.current() * sibling.previous()
            + (Query::one() - direction.current()) * new_hash.previous();
        cb.add_lookup(
            "poseidon hash correct for new path",
            [new_left, new_right, new_hash.current()],
            poseidon.lookup(),
        );

        cb.add_lookup(
            "direction = key.bit(depth)",
            [key.current(), depth.current(), direction.current()],
            key_bit.lookup(),
        );

        cb.add_constraint(
            "depth increased by 1 or is 0",
            selector.current(),
            depth.current() * (depth.current() - depth.previous()),
        );
        cb.condition(depth_is_zero.current(), |cb| {
            cb.add_constraint(
                "if depth is zero, segment_type is 0, unchanged, or increased by 1",
                selector.current(),
                segment_type.current()
                    * (segment_type.current() - segment_type.previous())
                    * (segment_type.current() - segment_type.previous() - 1),
            );
        });
        cb.condition(!depth_is_zero.current(), |cb| {
            cb.add_constraint(
                "key does not change if depth is not zero",
                selector.current(),
                key.current() - key.previous(),
            )
        });

        cb.condition(proof_type.matches(MPTProofType::NonceChanged), |cb| {
            cb.condition(segment_type.matches(SegmentType::AccountTrie), |cb| {});
            cb.condition(segment_type.matches(SegmentType::AccountLeaf), |cb| {
                cb.condition(depth_is_zero.current(), |cb| {
                    let account_key = key.previous();
                    cb.add_lookup(
                        "sibling at 0 depth is poseidon(1, account_key)",
                        [Query::one(), account_key, sibling.current()],
                        poseidon.lookup(),
                    );
                });
            });
            cb.add_constraint(
                "segment_type is not StorageTrie or StorageTrie",
                selector.current(),
                Query::from(segment_type.matches(SegmentType::StorageTrie))
                    + segment_type.matches(SegmentType::StorageLeaf),
            );
        });
        cb.condition(proof_type.matches(MPTProofType::BalanceChanged), |cb| {
            cb.condition(segment_type.matches(SegmentType::AccountTrie), |cb| {});
            cb.condition(segment_type.matches(SegmentType::AccountLeaf), |cb| {});
            cb.add_constraint(
                "segment_type is not StorageTrie or StorageTrie",
                selector.current(),
                Query::from(segment_type.matches(SegmentType::StorageTrie))
                    + segment_type.matches(SegmentType::StorageLeaf),
            );
        });
        cb.condition(proof_type.matches(MPTProofType::CodeHashExists), |cb| {
            cb.condition(segment_type.matches(SegmentType::AccountTrie), |cb| {});
            cb.condition(segment_type.matches(SegmentType::AccountLeaf), |cb| {});
            cb.add_constraint(
                "segment_type is not StorageTrie or StorageTrie",
                selector.current(),
                Query::from(segment_type.matches(SegmentType::StorageTrie))
                    + segment_type.matches(SegmentType::StorageLeaf),
            );
        });
        cb.condition(
            proof_type.matches(MPTProofType::AccountDoesNotExist),
            |cb| {
                cb.add_constraint(
                    "segment_type is AccountTrie",
                    selector.current(),
                    Query::from(segment_type.matches(SegmentType::AccountTrie)) - 1,
                );
            },
        );
        cb.add_constraint(
            "AccountDestructed not implemented.",
            selector.current(),
            Query::from(proof_type.matches(MPTProofType::AccountDestructed)),
        );
        cb.condition(proof_type.matches(MPTProofType::StorageChanged), |cb| {
            cb.condition(segment_type.matches(SegmentType::AccountTrie), |cb| {});
            cb.condition(segment_type.matches(SegmentType::AccountLeaf), |cb| {});
            cb.condition(segment_type.matches(SegmentType::StorageTrie), |cb| {});
            cb.condition(segment_type.matches(SegmentType::StorageLeaf), |cb| {});
        });
        cb.condition(
            proof_type.matches(MPTProofType::StorageDoesNotExist),
            |cb| {
                cb.condition(segment_type.matches(SegmentType::AccountTrie), |cb| {});
                cb.condition(segment_type.matches(SegmentType::AccountLeaf), |cb| {});
                cb.condition(segment_type.matches(SegmentType::StorageTrie), |cb| {});
                cb.condition(segment_type.matches(SegmentType::StorageLeaf), |cb| {});
            },
        );

        Self {
            selector,
            old_hash,
            new_hash,
            proof_type,
            old_value_rlc,
            new_value_rlc,
            address,
            storage_key_rlc,
            segment_type,
            path_type,
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
                self.address
                    .assign(region, offset, address_to_fr(proof.claim.address));
                // self.storage_key_rlc.assign(region, offset, rlc(proof.claim.storage_key, randomness));
                // self.new_value_rlc.assign(region, offset, ...)
                // self.old_value_rlc.assign(region, offset, ...)

                // self.is_common_path.assign(
                //     region,
                //     offset,
                //     !(*is_padding_open || *is_padding_close),
                // );
                self.segment_type
                    .assign(region, offset, SegmentType::AccountTrie);

                let path_type = match (*is_padding_open, *is_padding_close) {
                    (false, false) => PathType::Common,
                    (false, true) => PathType::Old,
                    (true, false) => PathType::New,
                    (true, true) => unreachable!(),
                };
                self.path_type.assign(region, offset, path_type);

                self.sibling.assign(region, offset, *sibling);
                self.new_hash.assign(region, offset, *new_hash);
                self.old_hash.assign(region, offset, *old_hash);
                self.direction.assign(region, offset, *direction);

                offset += 1;
            }
        }
    }
}

fn address_to_fr(a: Address) -> Fr {
    let mut bytes = [0u8; 32];
    bytes[32 - 20..].copy_from_slice(a.as_bytes());
    bytes.reverse();
    Fr::from_repr(bytes).unwrap()
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
