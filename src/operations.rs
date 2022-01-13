//! The constraint system matrix for operations inside the arity-2 Merkle Patricia Tree, it would:
//  * constraint hashType transition for both old and new hashtype from the lookup table ☑
//  * constraint old <-> New hashType from the lookup table ☑
//  * assign and constraint IsFirst row according to NewHashType ☑
//  * constraint the root of each first row must be the new root hash of prevs opeartion by inducing
//    a auxing "roots" column ☑
//  * inducing a depth column for accumulating path ☑
//  * constraint path as bit except when newhashtype is leaf ☑
//  * verify the key column by accumulating the path bit and LeafPath bits ☑
//  * (TODO) verify the sibling and oldhash when "leaf extension" hashtype is encountered
//
//  |-----||--------|------------------|------------------|---------|-------|--------|--------|--------|--------|--------|----------------|----------------|
//  | row ||IsFirst*|    OldHashType   |    NewHashType   |  path   |  key  |siblings|OldHash |  hash  | depth**| roots**| TypePairTable**|TypeTransTable**|
//  |-----||--------|------------------|------------------|---------|-------|--------|--------|--------|--------|--------|----------------|--=-------------|
//  |  0  ||   1    |       Empty      |      Leaf        | LeafPath|Leafkey|        | rootx  | root0  |   1    | root0  |                |                |
//  |  1  ||   1    |        Mid       |      Mid         | cbit_1  |       |        | root0  | root1  |   1    | root1  |                |                |
//  |  2  ||   0    |      LeafExt     |      Mid         | cbit_2  |       |        |        | hash1  |   2    | root1  |                |                |
//  |  3  ||   0    |   LeafExtFinal   |      Mid         | cbit_3  |       |        |        | hash2  |   4    | root1  |                |                |
//  |  4  ||   0    |       Empty      |      Leaf        | LeafPath|Leafkey|        |        | hash3  |   8    | root1  |                |                |
//  |  5  ||   1    |        Mid       |      Mid         | cbit_4  |       |        | root1  | root2  |   1    | root2  |                |                |
//  |-----||--------|------------------|------------------|---------|-------|--------|--------|--------|--------|--------|----------------|----------------|
//
//  * indicate a "controlled" column (being queried and assigned inside chip)
//  ** indicate a "private" column (a controlled column which is only used in the chip)

#![allow(unused_imports)]

use crate::serde::HashType;
use ff::Field;
use halo2::{
    arithmetic::FieldExt,
    circuit::{Cell, Chip, Layouter},
    dev::{MockProver, VerifyFailure},
    plonk::{
        Advice, Assignment, Circuit, Column, ConstraintSystem, Error, Expression, Instance,
        Selector, TableColumn,
    },
    poly::Rotation,
};
use lazy_static::lazy_static;
use std::marker::PhantomData;

pub(crate) struct MPTOpChip<F> {
    config: MPTOpChipConfig,
    _marker: PhantomData<F>,
}

#[derive(Clone, Debug)]
pub(crate) struct MPTOpChipConfig {
    pub is_first: Column<Advice>,

    root_aux: Column<Advice>,
    depth_aux: Column<Advice>,
    type_table: (TableColumn, TableColumn),
    trans_table: (TableColumn, TableColumn),
}

#[derive(Clone, Debug)]
pub(crate) struct Mappings {
    op: Vec<(HashType, HashType)>,
    trans: Vec<(HashType, HashType)>,
}

lazy_static! {
    static ref TYPEMAP: Mappings = {
        Mappings {
            op: vec![
                (HashType::Empty, HashType::Leaf),
                (HashType::Leaf, HashType::Leaf),
                (HashType::Middle, HashType::Middle),
                (HashType::LeafExt, HashType::Middle),
                (HashType::LeafExtFinal, HashType::Middle),
            ],
            trans: vec![
                (HashType::Middle, HashType::Middle),
                (HashType::Middle, HashType::Empty), //insert new leaf under a node
                (HashType::Middle, HashType::Leaf),
                (HashType::Middle, HashType::LeafExt),
                (HashType::Middle, HashType::LeafExtFinal),
                (HashType::LeafExt, HashType::LeafExt),
                (HashType::LeafExt, HashType::LeafExtFinal),
                (HashType::LeafExtFinal, HashType::Leaf),
                (HashType::LeafExtFinal, HashType::Empty),
            ],
        }
    };
}

impl<Fp: FieldExt> Chip<Fp> for MPTOpChip<Fp> {
    type Config = MPTOpChipConfig;
    type Loaded = Mappings;

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &TYPEMAP
    }
}

impl<Fp: FieldExt> MPTOpChip<Fp> {
    ///
    ///  OpChip suppose:
    ///  + the range of col in arguments has been constrainted (like is_leaf is {0, 1})
    ///
    fn configure(
        meta: &mut ConstraintSystem<Fp>,
        s_row: Selector,
        sibling: Column<Advice>,
        path: Column<Advice>,
        key: Column<Advice>,
        old_hash_type: Column<Advice>,
        new_hash_type: Column<Advice>,
        old_hash: Column<Advice>,
        new_hash: Column<Advice>,
    ) -> <Self as Chip<Fp>>::Config {
        let is_first = meta.advice_column();
        let root_aux = meta.advice_column();
        let depth_aux = meta.advice_column();
        let type_table = (meta.lookup_table_column(), meta.lookup_table_column());
        let trans_table = (meta.lookup_table_column(), meta.lookup_table_column());

        //transition - old
        meta.lookup(|meta| {
            let border =
                Expression::Constant(Fp::one()) - meta.query_advice(is_first, Rotation::cur());
            let hash = border.clone() * meta.query_advice(old_hash_type, Rotation::cur());
            let prev_hash = border * meta.query_advice(old_hash_type, Rotation::prev());

            vec![(prev_hash, trans_table.0), (hash, trans_table.1)]
        });

        //transition - new
        meta.lookup(|meta| {
            let border =
                Expression::Constant(Fp::one()) - meta.query_advice(is_first, Rotation::cur());
            let hash = border.clone() * meta.query_advice(new_hash_type, Rotation::cur());
            let prev_hash = border * meta.query_advice(new_hash_type, Rotation::prev());

            vec![(prev_hash, trans_table.0), (hash, trans_table.1)]
        });

        //old - new
        meta.lookup(|meta| {
            let old_hash = meta.query_advice(old_hash_type, Rotation::cur());
            let new_hash = meta.query_advice(new_hash_type, Rotation::cur());

            vec![(old_hash, type_table.0), (new_hash, type_table.1)]
        });

        //notice we need to enforce the row 0's equality to constraint it as 1
        meta.enable_equality(is_first.into());
        meta.create_gate("is first", |meta| {
            let sel = meta.query_selector(s_row);
            let is_first = meta.query_advice(is_first, Rotation::next());
            let new_hash_type = meta.query_advice(new_hash_type, Rotation::cur());
            let leaf_type = Expression::Constant(Fp::from(HashType::Leaf as u64));

            // is_first.next ∈ {0, 1}
            // if is_leaf is_first.next = 1
            // notice we need extra constraint to set the first row is 1
            // this constraint also enforce the first row of unused region must set is_first to 1
            vec![
                sel.clone()
                    * (Expression::Constant(Fp::one()) - is_first.clone())
                    * is_first.clone(),
                sel * is_first * (new_hash_type - leaf_type),
            ]
        });

        meta.create_gate("path bit", |meta| {
            let sel = meta.query_selector(s_row);
            let new_hash_type = meta.query_advice(new_hash_type, Rotation::cur());
            let leaf_type = Expression::Constant(Fp::from(HashType::Leaf as u64));

            let path = meta.query_advice(path, Rotation::cur());
            let path_bit = (Expression::Constant(Fp::one()) - path.clone()) * path;

            // if (new_hash_type is not leaf) path ∈ {0, 1}
            vec![sel * path_bit * (new_hash_type - leaf_type)]
        });

        meta.create_gate("root aux", |meta| {
            let sel = meta.query_selector(s_row);
            let is_first = meta.query_advice(is_first, Rotation::cur());
            let root_aux_cur = meta.query_advice(root_aux, Rotation::cur());
            let root_aux_next = meta.query_advice(root_aux, Rotation::next());
            let hash = meta.query_advice(new_hash, Rotation::next());
            let old_hash = meta.query_advice(old_hash, Rotation::next());

            // if is_first root_aux == hash
            // else root_aux == root_aux.next
            // if is_first old_hash.next == root_aux
            vec![
                sel.clone()
                    * (Expression::Constant(Fp::one()) - is_first.clone())
                    * (root_aux_cur.clone() - root_aux_next.clone()),
                sel.clone() * is_first.clone() * (root_aux_next - hash),
                sel * is_first.clone() * (old_hash - root_aux_cur),
            ]
        });

        meta.create_gate("depth aux", |meta| {
            let sel = meta.query_selector(s_row);
            let is_first = meta.query_advice(is_first, Rotation::cur());
            let depth_aux_cur = meta.query_advice(depth_aux, Rotation::cur());
            let depth_aux_next = meta.query_advice(depth_aux, Rotation::next());

            // if is_first depth == 1
            // else depth * 2 = depth.next
            vec![
                sel.clone()
                    * is_first.clone()
                    * (Expression::Constant(Fp::one()) - depth_aux_cur.clone()),
                sel * (Expression::Constant(Fp::one()) - is_first)
                    * (depth_aux_cur * Expression::Constant(Fp::from(2u64)) - depth_aux_next),
            ]
        });

        meta.create_gate("calc key", |meta| {
            let sel = meta.query_selector(s_row);
            let is_first = meta.query_advice(is_first, Rotation::cur());
            let path_cur = meta.query_advice(path, Rotation::cur())
                * meta.query_advice(depth_aux, Rotation::cur());
            let key_cur = path_cur - meta.query_advice(key, Rotation::cur());

            // if is_first key = path * depth
            // else key = path * depth + key.prev
            vec![
                sel.clone() * is_first.clone() * key_cur.clone(),
                sel * (Expression::Constant(Fp::one()) - is_first)
                    * (meta.query_advice(key, Rotation::prev()) + key_cur),
            ]
        });

        //TODO: verify sibling

        MPTOpChipConfig {
            is_first,
            root_aux,
            depth_aux,
            type_table,
            trans_table,
        }
    }

    //fill hashtype table and aux col
    pub fn load(
        &self,
        layouter: &mut impl Layouter<Fp>,
        new_hash_types: &Vec<HashType>,
        hash: &Vec<Fp>,
    ) -> Result<(), Error> {
        assert_eq!(new_hash_types.len(), hash.len());
        assert!(hash.len() > 0, "input must not empty");

        layouter.assign_region(
            || "aux region",
            |mut region| {
                let is_first = self.config().is_first;
                let root_aux = self.config().root_aux;
                let depth_aux = self.config().depth_aux;

                region.assign_advice_from_constant(|| "top of is_first", is_first, 0, Fp::one())?;

                let mut cur_root = Fp::zero();
                let mut cur_depth = 0u64;
                let mut is_first_col = true;
                //assign rest of is_first according to hashtypes
                for (index, val) in new_hash_types.iter().zip(hash.iter()).enumerate() {
                    let (hash_type, hash) = val;
                    region.assign_advice(
                        || "is_first",
                        is_first,
                        index + 1,
                        || {
                            Ok(match *hash_type {
                                HashType::Leaf => Fp::one(),
                                _ => Fp::zero(),
                            })
                        },
                    )?;

                    cur_root = if is_first_col { *hash } else { cur_root };
                    cur_depth = if is_first_col { 1u64 } else { cur_depth * 2 };

                    region.assign_advice(|| "root", root_aux, index, || Ok(cur_root))?;

                    region.assign_advice(
                        || "depth",
                        depth_aux,
                        index,
                        || Ok(Fp::from(cur_depth)),
                    )?;

                    is_first_col = match *hash_type {
                        HashType::Leaf => true,
                        _ => false,
                    };
                }
                Ok(())
            },
        )?;

        layouter.assign_table(
            || "trans table",
            |mut table| {
                let (cur_col, next_col) = self.config().trans_table;
                for (offset, trans) in self.loaded().trans.iter().enumerate() {
                    let (cur, next) = trans;
                    table.assign_cell(
                        || "cur hash",
                        cur_col,
                        offset,
                        || Ok(Fp::from(*cur as u64)),
                    )?;

                    table.assign_cell(
                        || "next hash",
                        next_col,
                        offset,
                        || Ok(Fp::from(*next as u64)),
                    )?;
                }
                Ok(())
            },
        )?;

        layouter.assign_table(
            || "op table",
            |mut table| {
                let (old_col, new_col) = self.config().type_table;
                for (offset, op) in self.loaded().op.iter().enumerate() {
                    let (old, new) = op;
                    table.assign_cell(
                        || "old hash",
                        old_col,
                        offset,
                        || Ok(Fp::from(*old as u64)),
                    )?;

                    table.assign_cell(
                        || "new hash",
                        new_col,
                        offset,
                        || Ok(Fp::from(*new as u64)),
                    )?;
                }
                Ok(())
            },
        )?;

        Ok(())
    }

    pub fn construct(config: MPTOpChipConfig) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }
}

#[cfg(test)]
mod test {
    #![allow(unused_imports)]

    use super::*;
    use ff::Field;
    use halo2::{
        circuit::{Cell, Region, SimpleFloorPlanner},
        dev::{MockProver, VerifyFailure},
        pairing::bn256::Fr as Fp, // why halo2-merkle tree use base field?
        plonk::{Circuit, Expression, Selector},
    };
    use rand::{random, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    #[derive(Clone, Debug)]
    struct MPTTestConfig {
        s_row: Selector,
        sibling: Column<Advice>,
        path: Column<Advice>,
        key: Column<Advice>,
        old_hash_type: Column<Advice>,
        new_hash_type: Column<Advice>,
        old_hash: Column<Advice>,
        new_hash: Column<Advice>,
        chip: MPTOpChipConfig,
    }

    #[derive(Clone, Default)]
    struct MPTTestSingleOpCircuit {
        pub old_hash_type: Vec<HashType>,
        pub new_hash_type: Vec<HashType>,
        pub path: Vec<Fp>,
        pub old_hash: Vec<Fp>,
        pub new_hash: Vec<Fp>,
        pub siblings: Vec<Fp>, //siblings from top to bottom
    }

    impl Circuit<Fp> for MPTTestSingleOpCircuit {
        type Config = MPTTestConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            let s_row = meta.selector();
            let sibling = meta.advice_column();
            let path = meta.advice_column();
            let key = meta.advice_column();
            let old_hash_type = meta.advice_column();
            let new_hash_type = meta.advice_column();
            let old_hash = meta.advice_column();
            let new_hash = meta.advice_column();

            MPTTestConfig {
                s_row,
                sibling,
                path,
                key,
                old_hash_type,
                new_hash_type,
                old_hash,
                new_hash,
                chip: MPTOpChip::configure(
                    meta,
                    s_row,
                    sibling,
                    path,
                    key,
                    old_hash_type,
                    new_hash_type,
                    old_hash,
                    new_hash,
                ),
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            layouter.assign_region(|| "main", |mut region| Ok(()))?;

            let op_chip = MPTOpChip::<Fp>::construct(config.chip);
            op_chip.load(&mut layouter, &self.new_hash_type, &self.new_hash)?;
            Ok(())
        }
    }

    #[test]
    fn test_single_path() {}
}
