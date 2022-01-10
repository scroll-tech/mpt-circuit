//! The constraint system matrix for operations inside the arity-2 Merkle Patricia Tree, it would:
//  * constraint old <-> New hashType from the lookup table
//  * constraint the rowtype: the cell of the NewHashType column in the prev row of a first_row (RowType cell = 1) 
//    must be a Leaf type
//  * constraint the root of each first row must be the new root hash of prevs opeartion by inducing
//    a auxing "roots" column
//  * verify the key column by accumulating the path bit and LeafPath bits
//  * (TODO) verify the sibling and oldhash when "leaf extension" hashtype is encountered
//
//  |-----||--------|------------------|------------------|---------|-------|--------|--------|--------|--------|----------------|----------------|
//  | row ||IsFirst |    OldHashType   |    NewHashType   |  path   |  key  |siblings|OldHash |  hash  | roots  |  OldTypeTable  |  NewTypeTable  |
//  |-----||--------|------------------|------------------|---------|-------|--------|--------|--------|--------|----------------|--=-------------|
//  |  0  ||   1    |       Empty      |      Leaf        | LeafPath|Leafkey|        | rootx  | root0  | root0  |                |                |
//  |  1  ||   1    |        Mid       |      Mid         | cbit_1  |       |        | root0  | root1  | root1  |                |                |
//  |  2  ||   0    |      LeafExt     |      Mid         | cbit_2  |       |        |        | hash1  | root1  |                |                |
//  |  3  ||   0    |   LeafExtFinal   |      Mid         | cbit_3  |       |        |        | hash2  | root1  |                |                |
//  |  4  ||   0    |       Empty      |      Leaf        | LeafPath|Leafkey|        |        | hash3  | root1  |                |                |
//  |  5  ||   1    |        Mid       |      Mid         | cbit_4  |       |        | root1  | root2  | root2  |                |                |
//  |-----||--------|------------------|------------------|---------|-------|--------|--------|--------|--------|----------------|----------------|


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

#[derive(Clone, Copy, Debug)]
enum HashType {
    Empty,
    Middle,
    LeafExt,
    LeafExtFinal,
    Leaf,
}

struct MPTOpChip<F> {
    config: MPTOpChipConfig,
    _marker: PhantomData<F>,
}

#[derive(Clone, Debug)]
struct MPTOpChipConfig {
    root_aux: Column<Advice>,
    depth_aux: Column<Advice>,
    type_table: (TableColumn, TableColumn),
}

lazy_static! {
    static ref TYPEMAP: Vec<(HashType, HashType)> = {
        vec![
            (HashType::Empty, HashType::Leaf),
            (HashType::Leaf, HashType::Leaf),
            (HashType::Middle, HashType::Middle),
            (HashType::Middle, HashType::LeafExt),
            (HashType::Middle, HashType::LeafExtFinal),
        ]
    };
}

impl<Fp: FieldExt> Chip<Fp> for MPTOpChip<Fp> {

    type Config = MPTOpChipConfig;
    type Loaded = Vec<(HashType, HashType)>;

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &TYPEMAP
    }
}

impl<Fp: FieldExt> MPTOpChip<Fp> {

    fn configure(
        meta: &mut ConstraintSystem<Fp>,
        is_first: Column<Advice>,
        sibling: Column<Advice>,
        path: Column<Advice>,
        key: Column<Advice>,
        old_hash_type: Column<Advice>,
        new_hash_type: Column<Advice>,
        old_hash: Column<Advice>,
        new_hash: Column<Advice>,       
    ) -> <Self as Chip<Fp>>::Config {

        let root_aux = meta.advice_column();
        let depth_aux = meta.advice_column();
        let type_table = (
            meta.lookup_table_column(),
            meta.lookup_table_column(),
        );

        meta.create_gate("is first", |meta|{

        });

        meta.lookup(|meta|{
            let old_hash = meta.query_advice(old_hash_type, Rotation::cur());
            let new_hash = meta.query_advice(new_hash_type, Rotation::cur());

            vec![
                (old_hash, type_table.0),
                (new_hash, type_table.1),
            ]
        });

        MPTOpChipConfig {
            root_aux,
            depth_aux,
            type_table,            
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


