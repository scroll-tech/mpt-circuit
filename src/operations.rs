//! The constraint system matrix for operations inside the arity-2 Merkle Patricia Tree, it would:
//  * constraint hashType transition for both old and new hashtype from the lookup table
//  * constraint old <-> New hashType from the lookup table
//  * constraint the rowtype to leafType is IsLeaf is marked
//  * constraint the root of each first row must be the new root hash of prevs opeartion by inducing
//    a auxing "roots" column
//  * verify the key column by accumulating the path bit and LeafPath bits
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

use ff::Field;
use halo2::{
    circuit::{Cell, Chip, Layouter},
    dev::{MockProver, VerifyFailure},
    plonk::{
        Advice, TableColumn, Assignment, Circuit, Column, ConstraintSystem, Error, Expression, Instance,
        Selector,
    },
    poly::Rotation,
    arithmetic::FieldExt,
};
use lazy_static::lazy_static;
use std::marker::PhantomData;
use super::HashType;

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
        let type_table = (
            meta.lookup_table_column(),
            meta.lookup_table_column(),
        );
        let trans_table = (
            meta.lookup_table_column(),
            meta.lookup_table_column(),
        );

        //transition - old
        meta.lookup(|meta|{
            let border = Expression::Constant(Fp::one()) - meta.query_advice(is_first, Rotation::cur()); 
            let hash = border.clone() * meta.query_advice(old_hash_type, Rotation::cur());
            let prev_hash = border * meta.query_advice(old_hash_type, Rotation::prev());

            vec![
                (prev_hash, trans_table.0),
                (hash, trans_table.1),
            ]
        });
        
        //transition - new
        meta.lookup(|meta|{
            let border = Expression::Constant(Fp::one()) - meta.query_advice(is_first, Rotation::cur());
            let hash = border.clone() * meta.query_advice(new_hash_type, Rotation::cur());
            let prev_hash = border * meta.query_advice(new_hash_type, Rotation::prev());

            vec![
                (prev_hash, trans_table.0),
                (hash, trans_table.1),
            ]
        });

        //old - new 
        meta.lookup(|meta|{
            let old_hash = meta.query_advice(old_hash_type, Rotation::cur());
            let new_hash = meta.query_advice(new_hash_type, Rotation::cur());

            vec![
                (old_hash, type_table.0),
                (new_hash, type_table.1),
            ]
        });

        //notice we need to enforce the row 0's equality to constraint it as 1
        meta.enable_equality(is_first.into());
        meta.create_gate("is first", |meta|{
            let sel = meta.query_selector(s_row);
            let is_first = meta.query_advice(is_first, Rotation::next());
            let new_hash_type = meta.query_advice(new_hash_type, Rotation::cur());
            let leaf_type = Expression::Constant(Fp::from(HashType::Leaf as u64));

            vec![
                sel.clone()* (Expression::Constant(Fp::one()) - is_first.clone()) * is_first.clone(),
                sel* (new_hash_type - leaf_type) * is_first,
            ]
        });

        //notice we need to enforce the row 0's equality
        meta.create_gate("root aux", |meta|{
            let sel = meta.query_selector(s_row);
            let is_first = meta.query_advice(is_first, Rotation::cur());
            let root_aux_cur = meta.query_advice(root_aux, Rotation::cur());
            let root_aux_next = meta.query_advice(root_aux, Rotation::next());
            let hash = meta.query_advice(new_hash, Rotation::next());

            vec![sel.clone() * (Expression::Constant(Fp::one()) - is_first.clone()) * (root_aux_cur - root_aux_next.clone()),
                sel * (root_aux_next - hash) * is_first,
            ]
        });

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
    ) -> Result<(), Error> {

        Ok(())
    }

    pub fn construct(config: MPTOpChipConfig) -> Self {
        Self { 
            config,
            _marker: PhantomData,
        }
    }
}


