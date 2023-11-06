use super::MptUpdateConfig;
use crate::{
    gadgets::mpt_update::{assign_word_rlc, path::PathType, segment::SegmentType, ZERO_PAIR_HASH},
    types::{
        storage::{StorageLeaf, StorageProof},
        trie::{next_domain, TrieRows},
        ClaimKind, HashDomain, Proof,
    },
    util::{account_key, rlc, u256_to_big_endian},
    MPTProofType,
};
use ethers_core::types::Address;
use halo2_proofs::{
    arithmetic::{Field, FieldExt},
    circuit::{Region, Value},
    halo2curves::bn256::Fr,
};
use itertools::izip;

impl MptUpdateConfig {
    pub fn assign_proof(
        &self,
        region: &mut Region<'_, Fr>,
        offset: usize,
        proof: &Proof,
        randomness: Value<Fr>,
    ) -> usize {
        let mut offset = offset;
        let proof_type = MPTProofType::from(proof.claim);
        let storage_key =
            randomness.map(|r| rlc(&u256_to_big_endian(&proof.claim.storage_key()), r));
        let old_value = randomness.map(|r| proof.claim.old_value_assignment(r));
        let new_value = randomness.map(|r| proof.claim.new_value_assignment(r));

        for i in 0..proof.n_rows() {
            self.proof_type.assign(region, offset + i, proof_type);
            self.storage_key_rlc.assign(region, offset + i, storage_key);
            self.old_value.assign(region, offset + i, old_value);
            self.new_value.assign(region, offset + i, new_value);
        }

        let key = account_key(proof.claim.address);
        // checking if type 1 or type 2
        let (other_key, other_leaf_data_hash) = if proof.old.key != key {
            assert!(proof.new.key == key || proof.new.key == proof.old.key);
            (proof.old.key, proof.old.leaf_data_hash.unwrap())
        } else if proof.new.key != key {
            assert!(proof.old.key == key);
            (proof.new.key, proof.new.leaf_data_hash.unwrap())
        } else {
            // neither is a type 1 path
            // handle type 0 and type 2 paths here:
            (proof.old.key, proof.new.leaf_data_hash.unwrap_or_default())
        };
        // Assign start row
        self.segment_type.assign(region, offset, SegmentType::Start);
        self.path_type.assign(region, offset, PathType::Start);
        self.old_hash.assign(region, offset, proof.claim.old_root);
        self.new_hash.assign(region, offset, proof.claim.new_root);

        self.key.assign(region, offset, key);
        self.other_key.assign(region, offset, other_key);
        self.domain.assign(region, offset, HashDomain::Pair);

        self.intermediate_values[0].assign(
            region,
            offset,
            Fr::from_u128(address_high(proof.claim.address)),
        );
        self.intermediate_values[1].assign(
            region,
            offset,
            u64::from(address_low(proof.claim.address)),
        );

        let rlc_fr = |x: Fr| {
            let mut bytes = x.to_bytes();
            bytes.reverse();
            randomness.map(|r| rlc(&bytes, r))
        };

        self.second_phase_intermediate_values[0].assign(
            region,
            offset,
            rlc_fr(proof.claim.old_root),
        );
        self.second_phase_intermediate_values[1].assign(
            region,
            offset,
            rlc_fr(proof.claim.new_root),
        );

        offset += 1;

        let n_account_trie_rows =
            self.assign_account_trie_rows(region, offset, &proof.account_trie_rows);
        for i in 0..n_account_trie_rows {
            self.key.assign(region, offset + i, key);
            self.other_key.assign(region, offset + i, other_key);
        }
        offset += n_account_trie_rows;

        let final_path_type = proof
            .address_hash_traces
            .first()
            .map(|(_, _, _, _, _, is_padding_open, is_padding_close)| {
                match (*is_padding_open, *is_padding_close) {
                    (false, false) => PathType::Common,
                    (false, true) => PathType::ExtensionOld,
                    (true, false) => PathType::ExtensionNew,
                    (true, true) => unreachable!(),
                }
            })
            .unwrap_or(PathType::Common);
        let (final_old_hash, final_new_hash) = match proof.address_hash_traces.first() {
            None => (proof.old.hash(), proof.new.hash()),
            Some((_, _, old_hash, new_hash, _, _, _)) => (*old_hash, *new_hash),
        };

        if proof.old_account.is_none() && proof.new_account.is_none() {
            offset -= 1;
            self.is_zero_gadgets[2].assign_value_and_inverse(region, offset, key - other_key);
            self.is_zero_gadgets[3].assign_value_and_inverse(region, offset, final_old_hash);

            self.intermediate_values[3].assign(region, offset, other_leaf_data_hash);

            // we don't need to assign any leaf rows for empty accounts
            return proof.n_rows();
        }

        let segment_types = vec![
            SegmentType::AccountLeaf0,
            SegmentType::AccountLeaf1,
            SegmentType::AccountLeaf2,
            SegmentType::AccountLeaf3,
        ];

        let leaf_path_type = match final_path_type {
            PathType::Common => {
                // need to check if the old or new account is type 2 empty
                match (
                    final_old_hash.is_zero_vartime(),
                    final_new_hash.is_zero_vartime(),
                ) {
                    (true, true) => unreachable!("proof type must be AccountDoesNotExist"),
                    (true, false) => PathType::ExtensionNew,
                    (false, true) => PathType::ExtensionOld,
                    (false, false) => PathType::Common,
                }
            }
            _ => final_path_type,
        };

        let directions = match proof_type {
            MPTProofType::NonceChanged | MPTProofType::CodeSizeExists => {
                vec![true, false, false, false]
            }
            MPTProofType::BalanceChanged => vec![true, false, false, true],
            MPTProofType::PoseidonCodeHashExists => vec![true, true],
            MPTProofType::CodeHashExists => vec![true, false, true, true],
            MPTProofType::StorageChanged | MPTProofType::StorageDoesNotExist => {
                vec![true, false, true, false]
            }
            MPTProofType::AccountDoesNotExist => unreachable!(),
            MPTProofType::AccountDestructed => unimplemented!(),
        };
        let next_offset = offset + directions.len();

        let old_hashes = proof
            .old_account_leaf_hashes()
            .unwrap_or_else(|| vec![final_old_hash; 4]);
        let new_hashes = proof
            .new_account_leaf_hashes()
            .unwrap_or_else(|| vec![final_new_hash; 4]);
        let siblings = proof.account_leaf_siblings();

        for (i, (segment_type, sibling, old_hash, new_hash, direction)) in
            izip!(segment_types, siblings, old_hashes, new_hashes, directions).enumerate()
        {
            if i == 0 {
                self.is_zero_gadgets[3].assign_value_and_inverse(region, offset, old_hash);
                self.domain.assign(region, offset + i, HashDomain::Leaf);
            } else {
                self.domain
                    .assign(region, offset + i, HashDomain::AccountFields);
            }
            self.segment_type.assign(region, offset + i, segment_type);
            self.path_type.assign(region, offset + i, leaf_path_type);
            self.sibling.assign(region, offset + i, sibling);
            self.old_hash.assign(region, offset + i, old_hash);
            self.new_hash.assign(region, offset + i, new_hash);
            self.direction.assign(region, offset + i, direction);
            self.key.assign(region, offset + i, key);
            self.other_key.assign(region, offset + i, other_key);

            match segment_type {
                SegmentType::AccountLeaf0 => {
                    let [.., other_key_column, other_leaf_data_hash_column] =
                        self.intermediate_values;
                    other_key_column.assign(region, offset, other_key);
                    other_leaf_data_hash_column.assign(region, offset, other_leaf_data_hash);
                }
                SegmentType::AccountLeaf3 => {
                    if let ClaimKind::Storage { key, .. } | ClaimKind::IsEmpty(Some(key)) =
                        proof.claim.kind
                    {
                        self.key.assign(region, offset + 3, proof.storage.key());
                        let [storage_key_high, storage_key_low, new_domain, ..] =
                            self.intermediate_values;
                        let [rlc_storage_key_high, rlc_storage_key_low, ..] =
                            self.second_phase_intermediate_values;
                        assign_word_rlc(
                            region,
                            offset + 3,
                            key,
                            [storage_key_high, storage_key_low],
                            [rlc_storage_key_high, rlc_storage_key_low],
                            randomness,
                        );
                        self.other_key
                            .assign(region, offset + 3, proof.storage.other_key());
                        new_domain.assign(region, offset + 3, HashDomain::AccountFields);
                    }
                }
                _ => {}
            };
        }
        self.key.assign(region, offset, key);
        self.other_key.assign(region, offset, other_key);
        self.is_zero_gadgets[2].assign_value_and_inverse(region, offset, key - other_key);
        if let ClaimKind::CodeHash { old, new } = proof.claim.kind {
            let [old_high, old_low, new_high, new_low, ..] = self.intermediate_values;
            let [old_rlc_high, old_rlc_low, new_rlc_high, new_rlc_low, ..] =
                self.second_phase_intermediate_values;
            if let Some(value) = old {
                assign_word_rlc(
                    region,
                    offset + 3,
                    value,
                    [old_high, old_low],
                    [old_rlc_high, old_rlc_low],
                    randomness,
                );
            }
            if let Some(value) = new {
                assign_word_rlc(
                    region,
                    offset + 3,
                    value,
                    [new_high, new_low],
                    [new_rlc_high, new_rlc_low],
                    randomness,
                );
            }
        };
        self.assign_storage(region, next_offset, &proof.storage, randomness);
        return proof.n_rows();
    }

    // Valid assignment proving that the address 0 doesn't exist in an empty MPT.
    pub fn assign_padding_row(&self, region: &mut Region<'_, Fr>, offset: usize) {
        self.proof_type
            .assign(region, offset, MPTProofType::AccountDoesNotExist);
        self.key.assign(region, offset, *ZERO_PAIR_HASH);
        self.other_key.assign(region, offset, *ZERO_PAIR_HASH);
        self.domain.assign(region, offset, HashDomain::Pair);
    }

    fn assign_storage_trie_rows(
        &self,
        region: &mut Region<'_, Fr>,
        starting_offset: usize,
        rows: &TrieRows,
    ) -> usize {
        let n_rows = self.assign_trie_rows(region, starting_offset, rows);
        for i in 0..n_rows {
            self.segment_type
                .assign(region, starting_offset + i, SegmentType::StorageTrie);
        }
        n_rows
    }

    fn asssign_storage(
        &self,
        region: &mut Region<'_, Fr>,
        offset: usize,
        storage: &StorageProof,
        randomness: Value<Fr>,
    ) -> usize {
        match storage {
            StorageProof::Root(_) => 0,
            StorageProof::Update {
                key,
                trie_rows,
                old_leaf,
                new_leaf,
                ..
            } => {
                let other_key = storage.other_key();
                let n_trie_rows = self.assign_storage_trie_rows(region, offset, trie_rows);
                let n_leaf_rows = self.assign_storage_leaf_row(
                    region,
                    offset + n_trie_rows,
                    *key,
                    other_key,
                    old_leaf,
                    new_leaf,
                    randomness,
                );
                let n_rows = n_trie_rows + n_leaf_rows;

                for i in 0..n_rows {
                    self.key.assign(region, offset + i, *key);
                    self.other_key.assign(region, offset + i, other_key);
                }

                n_rows
            }
        }
    }

    fn assign_account_trie_rows(
        &self,
        region: &mut Region<'_, Fr>,
        starting_offset: usize,
        rows: &TrieRows,
    ) -> usize {
        let n_rows = self.assign_trie_rows(region, starting_offset, rows);
        for i in 0..n_rows {
            self.segment_type
                .assign(region, starting_offset + i, SegmentType::AccountTrie);
        }
        n_rows
    }

    fn assign_empty_storage_proof(
        &self,
        region: &mut Region<'_, Fr>,
        offset: usize,
        key: Fr,
        other_key: Fr,
        old: &StorageLeaf,
        new: &StorageLeaf,
    ) -> usize {
        let [_, _, _, other_leaf_data_hash, ..] = self.intermediate_values;
        let [.., key_equals_other_key, hash_is_zero] = self.is_zero_gadgets;
        match (old, new) {
            (
                StorageLeaf::Leaf {
                    mpt_key: old_key,
                    value_hash: old_value_hash,
                },
                StorageLeaf::Leaf {
                    mpt_key: new_key,
                    value_hash: new_value_hash,
                },
            ) => {
                assert!(key != other_key);

                key_equals_other_key.assign_value_and_inverse(region, offset, key - other_key);

                assert_eq!(new_key, old_key);
                assert_eq!(old_value_hash, new_value_hash);

                hash_is_zero.assign_value_and_inverse(region, offset, old.hash());

                other_leaf_data_hash.assign(region, offset, *old_value_hash);
            }
            (StorageLeaf::Empty { .. }, StorageLeaf::Empty { .. }) => {
                assert!(key == other_key);

                assert_eq!(old.hash(), Fr::zero());
                assert_eq!(new.hash(), Fr::zero());

                key_equals_other_key.assign_value_and_inverse(region, offset, key - other_key);
            }
            (StorageLeaf::Entry { .. }, _) | (_, StorageLeaf::Entry { .. }) => return 0,
            (StorageLeaf::Leaf { .. }, StorageLeaf::Empty { .. })
            | (StorageLeaf::Empty { .. }, StorageLeaf::Leaf { .. }) => unreachable!(),
        }

        0
    }

    fn assign_trie_rows(
        &self,
        region: &mut Region<'_, Fr>,
        starting_offset: usize,
        rows: &TrieRows,
    ) -> usize {
        for (i, row) in rows.0.iter().enumerate() {
            let offset = starting_offset + i;
            self.depth
                .assign(region, offset, u64::try_from(i + 1).unwrap());
            self.path_type.assign(region, offset, row.path_type);

            if let Some(next_row) = rows.0.get(i + 1) {
                if !matches!(next_row.path_type, PathType::Start | PathType::Common)
                    && row.path_type == PathType::Common
                {
                    self.intermediate_values[2].assign(
                        region,
                        offset,
                        next_domain(row.domain, row.direction),
                    );
                }
            }
            for (value, column) in [
                (row.sibling, self.sibling),
                (row.old, self.old_hash),
                (row.new, self.new_hash),
                (row.direction.into(), self.direction),
                (row.domain.into(), self.domain),
            ] {
                column.assign(region, offset, value);
            }
        }
        rows.len()
    }

    fn assign_storage(
        &self,
        region: &mut Region<'_, Fr>,
        offset: usize,
        storage: &StorageProof,
        randomness: Value<Fr>,
    ) -> usize {
        match storage {
            StorageProof::Root(_) => 0,
            StorageProof::Update {
                key,
                trie_rows,
                old_leaf,
                new_leaf,
                ..
            } => {
                let other_key = storage.other_key();
                let n_trie_rows = self.assign_storage_trie_rows(region, offset, trie_rows);
                let n_leaf_rows = self.assign_storage_leaf_row(
                    region,
                    offset + n_trie_rows,
                    *key,
                    other_key,
                    old_leaf,
                    new_leaf,
                    randomness,
                );
                let n_rows = n_trie_rows + n_leaf_rows;

                for i in 0..n_rows {
                    self.key.assign(region, offset + i, *key);
                    self.other_key.assign(region, offset + i, other_key);
                }

                n_rows
            }
        }
    }

    fn assign_storage_leaf_row(
        &self,
        region: &mut Region<'_, Fr>,
        offset: usize,
        key: Fr,
        other_key: Fr,
        old: &StorageLeaf,
        new: &StorageLeaf,
        randomness: Value<Fr>,
    ) -> usize {
        let path_type = match (old, new) {
            (StorageLeaf::Entry { .. }, StorageLeaf::Entry { .. }) => PathType::Common,
            (StorageLeaf::Entry { .. }, _) => PathType::ExtensionOld,
            (_, StorageLeaf::Entry { .. }) => PathType::ExtensionNew,
            _ => {
                return self.assign_empty_storage_proof(
                    region,
                    offset - 1,
                    key,
                    other_key,
                    old,
                    new,
                )
            }
        };
        self.path_type.assign(region, offset, path_type);
        self.segment_type
            .assign(region, offset, SegmentType::StorageLeaf0);
        self.direction.assign(region, offset, true);
        self.domain.assign(region, offset, HashDomain::Leaf);

        let sibling = match path_type {
            PathType::Start => unreachable!(),
            PathType::Common | PathType::ExtensionOld => old.key(),
            PathType::ExtensionNew => new.key(),
        };
        self.sibling.assign(region, offset, sibling);

        let (old_hash, new_hash) = match path_type {
            PathType::Start => unreachable!(),
            PathType::Common => (old.value_hash(), new.value_hash()),
            PathType::ExtensionOld => (old.value_hash(), new.hash()),
            PathType::ExtensionNew => (old.hash(), new.value_hash()),
        };
        self.old_hash.assign(region, offset, old_hash);
        self.new_hash.assign(region, offset, new_hash);

        let [old_high, old_low, new_high, new_low, ..] = self.intermediate_values;
        let [old_rlc_high, old_rlc_low, new_rlc_high, new_rlc_low, ..] =
            self.second_phase_intermediate_values;

        if let StorageLeaf::Entry { .. } = old {
            assign_word_rlc(
                region,
                offset,
                old.value(),
                [old_high, old_low],
                [old_rlc_high, old_rlc_low],
                randomness,
            );
        }

        if let StorageLeaf::Entry { .. } = new {
            assign_word_rlc(
                region,
                offset,
                new.value(),
                [new_high, new_low],
                [new_rlc_high, new_rlc_low],
                randomness,
            );
        }

        let [old_hash_is_zero_storage_hash, new_hash_is_zero_storage_hash, ..] =
            self.is_zero_gadgets;
        old_hash_is_zero_storage_hash.assign_value_and_inverse(
            region,
            offset,
            old_hash - *ZERO_PAIR_HASH,
        );
        new_hash_is_zero_storage_hash.assign_value_and_inverse(
            region,
            offset,
            new_hash - *ZERO_PAIR_HASH,
        );

        match path_type {
            PathType::Start => unreachable!(),
            PathType::Common => {}
            PathType::ExtensionOld => {
                let new_key = new.key();
                let other_key = if key != new_key { new_key } else { old.key() };

                let [.., key_equals_other_key, new_hash_is_zero] = self.is_zero_gadgets;
                key_equals_other_key.assign_value_and_inverse(region, offset, key - other_key);
                new_hash_is_zero.assign_value_and_inverse(region, offset, new_hash);

                if key != other_key {
                    let [.., other_leaf_data_hash] = self.intermediate_values;
                    other_leaf_data_hash.assign(region, offset, new.value_hash());
                }
            }
            PathType::ExtensionNew => {
                let old_key = old.key();
                let other_key = if key != old_key { old_key } else { new.key() };

                let [.., key_equals_other_key, old_hash_is_zero] = self.is_zero_gadgets;
                key_equals_other_key.assign_value_and_inverse(region, offset, key - other_key);
                old_hash_is_zero.assign_value_and_inverse(region, offset, old_hash);

                if key != other_key {
                    let [.., other_leaf_data_hash] = self.intermediate_values;
                    other_leaf_data_hash.assign(region, offset, old.value_hash());
                }
            }
        }

        1
    }
}

fn address_high(a: Address) -> u128 {
    let high_bytes: [u8; 16] = a.0[..16].try_into().unwrap();
    u128::from_be_bytes(high_bytes)
}

fn address_low(a: Address) -> u32 {
    let low_bytes: [u8; 4] = a.0[16..].try_into().unwrap();
    u32::from_be_bytes(low_bytes)
}
