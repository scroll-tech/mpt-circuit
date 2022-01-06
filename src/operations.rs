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
use std::marker::PhantomData;

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
    is_first: Column<Advice>,
    sibling: Column<Advice>,
    path: Column<Advice>,
    key: Column<Advice>,
    old_hash_type: Column<Advice>,
    new_hash_type: Column<Advice>,
    old_hash: Column<Advice>,
    new_hash: Column<Advice>,

    root_aux: Column<Advice>,
    type_table: (TableColumn, TableColumn),
}



impl<Fp: FieldExt> Chip<Fp> for MPTOpChip<Fp> {

    type Config = MPTOpChipConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
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
        let type_table = (
            meta.lookup_table_column(),
            meta.lookup_table_column(),
        );

        MPTOpChipConfig {
            is_first,
            sibling,
            path,
            key,
            old_hash_type,
            new_hash_type,
            old_hash,
            new_hash,
            root_aux,
            type_table,            
        }
    }

    pub fn construct(config: MPTOpChipConfig) -> Self {
        Self { 
            config,
            _marker: PhantomData,
        }
    }
}


