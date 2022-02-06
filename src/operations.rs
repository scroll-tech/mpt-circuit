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
//  Following is the EXPECTED layout of the chip, there is a padding row before each opeartion and
//  being marked by the IsFirst col
//
//  |-----||--------|------------------|------------------|---------|-------|--------|--------|--------|--------|--------|----------------|----------------|
//  | row ||IsFirst*|    OldHashType   |    NewHashType   |  path   |accKey*|siblings| OldVal | NewVal | depth**| roots**| TypePairTable**|TypeTransTable**|
//  |-----||--------|------------------|------------------|---------|-------|--------|--------|--------|--------|--------|----------------|--=-------------|
//  |  0  ||   1    |                  |                  |         |       |        | rootx  | root0  |        |        |                |                |
//  |  1  ||   0    |       Empty      |      Leaf        | LeafPath|Leafkey|        |   x    | leaf0  |   1    | root0  |                |                |
//  |  2  ||   1    |                  |                  |         |       |        | root0  | root1  |        |        |                |                |
//  |  3  ||   0    |        Mid       |      Mid         | cbit_1  |       |        | hash01 | hash11 |   1    | root1  |                |                |
//  |  4  ||   0    |        Mid       |      Mid         | cbit_1  |       |        | hash02 | hash12 |   2    | root1  |                |                |
//  |  5  ||   0    |      LeafExt     |      Mid         | cbit_2  |       |        | hash03 | hash13 |   4    | root1  |                |                |
//  |  6  ||   0    |   LeafExtFinal   |      Mid         | cbit_3  |       |        |   0    | hash14 |   8    | root1  |                |                |
//  |  7  ||   0    |       Empty      |      Leaf        | LeafPath|Leafkey|        |   x    | leaf1  |   16   | root1  |                |                |
//  |  8  ||   1    |                  |                  |         |       |        | root1  | root2  |        |        |                |                |
//  |  9  ||   0    |        Mid       |      Mid         | cbit_1  |       |        | hash11 | hash21 |   1    | root2  |                |                |
//  | 10  ||   0    |        Mid       |      Mid         | cbit_4  |       |        | hash12 | hash22 |   2    | root2  |                |                |
//  |-----||--------|------------------|------------------|---------|-------|--------|--------|--------|--------|--------|----------------|----------------|
//
//  * indicate a "controlled" column (being queried and assigned inside chip)
//  ** indicate a "private" column (a controlled column which is only used in the chip)
//

#![allow(unused_imports)]
#![allow(clippy::too_many_arguments)]

use super::HashType;
use ff::Field;
use halo2::{
    arithmetic::FieldExt,
    circuit::{Cell, Chip, Layouter, Region},
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
    pub key: Column<Advice>,

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
                (HashType::Start, HashType::Leaf),
                (HashType::Start, HashType::Middle),
                (HashType::Start, HashType::Empty),
                (HashType::Start, HashType::LeafExt),
                (HashType::Start, HashType::LeafExtFinal),
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
    pub fn configure(
        meta: &mut ConstraintSystem<Fp>,
        s_row: Selector,
        path: Column<Advice>,
        old_hash_type: Column<Advice>,
        new_hash_type: Column<Advice>,
        old_hash: Column<Advice>,
        new_hash: Column<Advice>,
    ) -> <Self as Chip<Fp>>::Config {
        let is_first = meta.advice_column();
        let key = meta.advice_column();
        let root_aux = meta.advice_column();
        let depth_aux = meta.advice_column();
        let type_table = (meta.lookup_table_column(), meta.lookup_table_column());
        let trans_table = (meta.lookup_table_column(), meta.lookup_table_column());

        //notice we need to enforce the row 0's equality to constraint it as 1
        meta.enable_equality(is_first.into());

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

        meta.create_gate("is first", |meta| {
            let sel = meta.query_selector(s_row);
            let is_first = meta.query_advice(is_first, Rotation::cur());
            let new_hash_type = meta.query_advice(new_hash_type, Rotation::cur());
            // is_first ∈ {0, 1}
            // if is_first then new_hash_type == start (or say, 0)
            // TODO: should we also constraint old_hash_type == start ?
            vec![
                sel.clone()
                    * (Expression::Constant(Fp::one()) - is_first.clone())
                    * is_first.clone(),
                sel * is_first * new_hash_type,
            ]
        });

        meta.create_gate("start new op", |meta| {
            let sel = meta.query_selector(s_row);
            let is_first = meta.query_advice(is_first, Rotation::cur());
            let new_hash_type = meta.query_advice(new_hash_type, Rotation::prev());
            let leaf_type = Expression::Constant(Fp::from(HashType::Leaf as u64));

            let old_hash = meta.query_advice(old_hash, Rotation::prev());
            let new_hash = meta.query_advice(new_hash, Rotation::prev());

            // how new op (a row marked as "is_first") can be opened:
            // + new_hash_type.prev is leaf ||
            // + prev row has an "identify op": old_hash == new_hash
            vec![sel * is_first * (new_hash_type - leaf_type) * (old_hash - new_hash)]
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

        meta.create_gate("root and depth", |meta| {
            let sel = meta.query_selector(s_row);
            let enable =
                Expression::Constant(Fp::one()) - meta.query_advice(is_first, Rotation::cur());
            let is_first = meta.query_advice(is_first, Rotation::prev());

            let root_aux_start = meta.query_advice(root_aux, Rotation::cur())
                - meta.query_advice(new_hash, Rotation::prev());
            let root_aux_common = meta.query_advice(root_aux, Rotation::cur())
                - meta.query_advice(root_aux, Rotation::prev());

            let depth_aux_start =
                meta.query_advice(depth_aux, Rotation::cur()) - Expression::Constant(Fp::one());
            let depth_aux_common = meta.query_advice(depth_aux, Rotation::cur())
                - meta.query_advice(depth_aux, Rotation::prev())
                    * Expression::Constant(Fp::from(2u64));

            // for any row which is_first is 0:
            // if is_first.prev == 0 then root_aux == root_aux.prev else root_aux == new_hash
            // if is_first.prev == 0 then depth_aux == depth_aux.prev * 2 else depth_aux == 1
            vec![
                sel.clone()
                    * enable.clone()
                    * (is_first.clone() * root_aux_start
                        + (Expression::Constant(Fp::one()) - is_first.clone()) * root_aux_common),
                sel * enable
                    * (is_first.clone() * depth_aux_start
                        + (Expression::Constant(Fp::one()) - is_first) * depth_aux_common),
            ]
        });

        meta.create_gate("op continue", |meta| {
            let sel = meta.query_selector(s_row);
            let is_first = meta.query_advice(is_first, Rotation::cur());
            let old_hash = meta.query_advice(old_hash, Rotation::cur());
            let root_aux = meta.query_advice(root_aux, Rotation::prev());

            vec![sel * is_first * (old_hash - root_aux)]
        });

        //TODO: verify sibling

        MPTOpChipConfig {
            is_first,
            key,
            root_aux,
            depth_aux,
            type_table,
            trans_table,
        }
    }

    // padding a row for each operation
    pub fn padding_aux(
        &self,
        region: &mut Region<'_, Fp>,
        offset: usize,
        pad_root: Fp,
    ) -> Result<usize, Error> {
        region.assign_advice(
            || "key padding",
            self.config().key,
            offset,
            || Ok(Fp::zero()),
        )?;
        region.assign_advice(
            || "depth padding",
            self.config().depth_aux,
            offset,
            || Ok(Fp::zero()),
        )?;
        region.assign_advice(
            || "root padding",
            self.config().root_aux,
            offset,
            || Ok(pad_root),
        )?;
        if offset == 0 {
            //need to fix the "is_first" flag in first working row
            region.assign_advice_from_constant(
                || "top of is_first",
                self.config().is_first,
                0,
                Fp::one(),
            )?;
        } else {
            region.assign_advice(
                || "is_first",
                self.config().is_first,
                offset,
                || Ok(Fp::one()),
            )?;
        }

        Ok(offset + 1)
    }

    // fill data for a single op in spec position of the region (include the padding row),
    // should return the next rows of the regoin being filled
    pub fn fill_aux(
        &self,
        region: &mut Region<'_, Fp>,
        mut offset: usize,
        path: &[Fp],
        new_root: Fp,
    ) -> Result<usize, Error> {
        assert!(!path.is_empty(), "input must not empty");
        // padding first row
        offset = self.padding_aux(region, offset, new_root)?;

        let is_first = self.config().is_first;
        let key_aux = self.config().key;
        let root_aux = self.config().root_aux;
        let depth_aux = self.config().depth_aux;

        let mut cur_depth = Fp::one();
        let mut acc_key = Fp::zero();

        //assign rest of is_first according to hashtypes
        for (index, path) in path.iter().enumerate() {
            let index = index + offset;
            acc_key = *path * cur_depth + acc_key;

            region.assign_advice(|| "is_first", is_first, index, || Ok(Fp::zero()))?;
            region.assign_advice(|| "root", root_aux, index, || Ok(new_root))?;
            region.assign_advice(|| "depth", depth_aux, index, || Ok(cur_depth))?;
            region.assign_advice(|| "key", key_aux, index, || Ok(acc_key))?;

            cur_depth = cur_depth.double();
        }

        offset += path.len();
        //always prepare for next op (mutiple assignation is ok)
        // self.padding_aux(region, offset)?;

        Ok(offset)
    }

    //fill hashtype table
    pub fn load(&self, layouter: &mut impl Layouter<Fp>) -> Result<(), Error> {
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
    use crate::test_utils::*;
    use halo2::{
        circuit::{Cell, SimpleFloorPlanner},
        dev::{MockProver, VerifyFailure},
        plonk::{Circuit, Expression, Selector},
    };

    #[derive(Clone, Debug)]
    struct MPTTestConfig {
        s_row: Selector,
        path: Column<Advice>,
        old_hash_type: Column<Advice>,
        new_hash_type: Column<Advice>,
        old_val: Column<Advice>,
        new_val: Column<Advice>,
        chip: MPTOpChipConfig,
    }

    #[derive(Clone, Default)]
    struct MPTTestSingleOpCircuit {
        pub old_hash_type: Vec<HashType>,
        pub new_hash_type: Vec<HashType>,
        pub path: Vec<Fp>,
        pub old_val: Vec<Fp>, //val start from root and till leaf
        pub new_val: Vec<Fp>,
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
            let path = meta.advice_column();
            let old_hash_type = meta.advice_column();
            let new_hash_type = meta.advice_column();
            let old_val = meta.advice_column();
            let new_val = meta.advice_column();

            let constant = meta.fixed_column();
            meta.enable_constant(constant);

            MPTTestConfig {
                s_row,
                path,
                old_hash_type,
                new_hash_type,
                old_val,
                new_val,
                chip: MPTOpChip::configure(
                    meta,
                    s_row,
                    path,
                    old_hash_type,
                    new_hash_type,
                    old_val,
                    new_val,
                ),
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            let op_chip = MPTOpChip::<Fp>::construct(config.chip.clone());

            layouter.assign_region(
                || "op main",
                |mut region| {
                    let last = self.fill_layer(&config, &mut region, 0, &op_chip)?;
                    self.pad_row(&config, &mut region, last, &op_chip)?;
                    Ok(())
                },
            )?;

            op_chip.load(&mut layouter)?;
            Ok(())
        }
    }

    impl MPTTestSingleOpCircuit {
        pub fn pad_row(
            &self,
            config: &MPTTestConfig,
            region: &mut Region<'_, Fp>,
            offset: usize,
            aux_chip: &MPTOpChip<Fp>,
        ) -> Result<usize, Error> {
            let final_root = self.new_val[0];

            region.assign_advice(|| "padding path", config.path, offset, || Ok(Fp::zero()))?;
            region.assign_advice(
                || "padding hash type",
                config.new_hash_type,
                offset,
                || Ok(Fp::zero()),
            )?;
            region.assign_advice(
                || "padding old type",
                config.old_hash_type,
                offset,
                || Ok(Fp::zero()),
            )?;
            region.assign_advice(
                || "padding old root",
                config.old_val,
                offset,
                || Ok(final_root),
            )?;
            region.assign_advice(
                || "padding new root",
                config.new_val,
                offset,
                || Ok(final_root),
            )?;

            aux_chip.padding_aux(region, offset, final_root)
        }

        pub fn fill_layer(
            &self,
            config: &MPTTestConfig,
            region: &mut Region<'_, Fp>,
            offset: usize,
            aux_chip: &MPTOpChip<Fp>,
        ) -> Result<usize, Error> {
            // notice we can have different length for old_val and new_val
            for (index, val) in self.old_val.iter().enumerate() {
                region.assign_advice(
                    || "old hash or leaf val",
                    config.old_val,
                    index + offset,
                    || Ok(*val),
                )?;
            }

            for (index, val) in self.new_val.iter().enumerate() {
                region.assign_advice(
                    || "new hash or leaf val",
                    config.new_val,
                    index + offset,
                    || Ok(*val),
                )?;
            }

            if offset != 0 {
                config.s_row.enable(region, offset)?;
            }
            // pad first row
            region.assign_advice(|| "path", config.path, offset, || Ok(Fp::zero()))?;
            region.assign_advice(
                || "hash_type_old",
                config.old_hash_type,
                offset,
                || Ok(Fp::zero()),
            )?;
            region.assign_advice(
                || "hash_type_new",
                config.new_hash_type,
                offset,
                || Ok(Fp::zero()),
            )?;

            // other col start from row 1
            for ind in 0..self.path.len() {
                let offset = offset + ind + 1;
                config.s_row.enable(region, offset)?;

                region.assign_advice(|| "path", config.path, offset, || Ok(self.path[ind]))?;
                region.assign_advice(
                    || "hash_type_old",
                    config.old_hash_type,
                    offset,
                    || Ok(Fp::from(self.old_hash_type[ind] as u64)),
                )?;
                region.assign_advice(
                    || "hash_type_new",
                    config.new_hash_type,
                    offset,
                    || Ok(Fp::from(self.new_hash_type[ind] as u64)),
                )?;
            }

            aux_chip.fill_aux(region, offset, &self.path, self.new_val[0])
        }
    }

    lazy_static! {

        static ref DEMOCIRCUIT1: MPTTestSingleOpCircuit = {
            MPTTestSingleOpCircuit {
                siblings: vec![Fp::zero()],
                old_val: vec![Fp::zero(), rand_fp()],
                new_val: vec![Fp::from(11u64), Fp::from(0x1EAFu64)],
                path: vec![Fp::from(4u64)], //the key is 0b100u64
                old_hash_type: vec![HashType::Empty],
                new_hash_type: vec![HashType::Leaf],
            }
        };

        static ref DEMOCIRCUIT2: MPTTestSingleOpCircuit = {
            MPTTestSingleOpCircuit {
                siblings: vec![Fp::from(11u64), rand_fp()],
                old_val: vec![Fp::from(11u64), Fp::zero(), rand_fp()],
                new_val: vec![Fp::from(22u64), rand_fp(), Fp::from(0x1EAFu64)],
                path: vec![Fp::one(), Fp::from(8u64)], //the key is 0b10001u64
                old_hash_type: vec![HashType::LeafExtFinal, HashType::Empty],
                new_hash_type: vec![HashType::Middle, HashType::Leaf],
            }
        };

        static ref DEMOCIRCUIT3: MPTTestSingleOpCircuit = {
            let siblings = vec![Fp::from(11u64), Fp::zero(), Fp::from(22u64), rand_fp()];
            let mut old_val = vec![Fp::from(22u64)];
            let mut new_val = vec![Fp::from(33u64)];
            for _ in 0..3 {
                old_val.push(rand_fp());
                new_val.push(rand_fp());
            }
            old_val.push(rand_fp());
            new_val.push(Fp::from(0x1EAFu64));

            MPTTestSingleOpCircuit {
                siblings,
                old_val,
                new_val,
                path: vec![Fp::one(), Fp::zero(), Fp::one(), Fp::from(5u64)], //the key is 0b101101u64
                old_hash_type: vec![
                    HashType::Middle,
                    HashType::LeafExt,
                    HashType::LeafExtFinal,
                    HashType::Empty,
                ],
                new_hash_type: vec![
                    HashType::Middle,
                    HashType::Middle,
                    HashType::Middle,
                    HashType::Leaf,
                ],
            }
        };
    }

    #[test]
    fn test_single_op() {
        let k = 5;
        let prover = MockProver::<Fp>::run(k, &*DEMOCIRCUIT1, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
        let prover = MockProver::<Fp>::run(k, &*DEMOCIRCUIT2, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
        let prover = MockProver::<Fp>::run(k, &*DEMOCIRCUIT3, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[derive(Clone, Default)]
    struct MPTTestOpCircuit {
        pub ops: Vec<MPTTestSingleOpCircuit>,
    }

    impl Circuit<Fp> for MPTTestOpCircuit {
        type Config = MPTTestConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            MPTTestSingleOpCircuit::configure(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            let op_chip = MPTOpChip::<Fp>::construct(config.chip.clone());

            layouter.assign_region(
                || "multi op main",
                |mut region| {
                    let mut offset = 0;
                    for op in self.ops.iter() {
                        offset = op.fill_layer(&config, &mut region, offset, &op_chip)?;
                    }

                    let last_op = self.ops.last().unwrap();
                    //2 more "real" padding
                    config.s_row.enable(&mut region, offset)?;
                    offset = last_op.pad_row(&config, &mut region, offset, &op_chip)?;
                    config.s_row.enable(&mut region, offset)?;
                    last_op.pad_row(&config, &mut region, offset, &op_chip)?;

                    Ok(())
                },
            )?;

            op_chip.load(&mut layouter)?;

            Ok(())
        }
    }

    #[test]
    fn test_multiple_op() {
        let k = 5;

        let circuit = MPTTestOpCircuit {
            ops: vec![
                DEMOCIRCUIT1.clone(),
                DEMOCIRCUIT2.clone(),
                DEMOCIRCUIT3.clone(),
            ],
        };

        #[cfg(feature = "print_layout")]
        print_layout!("operate_layout.png", k, &circuit);

        let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
