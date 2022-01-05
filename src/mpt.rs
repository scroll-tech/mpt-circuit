//! The constraint system matrix for an arity-2 Merkle Patricia Tree using lookup-table for hashing
//  The lookup table is formed by <left, right, hash> and the input can be 
//  <val_col, sibling_col, val_col@Rotation::(-1)]>

//  |-----||--------|------------------|------------------|---------|----------------|----------------|--------|
//  | row ||IsFirst |       val        |     sibling      |  path   |     left       |     right      |  hash  |
//  |-----||--------|------------------|------------------|---------|----------------|--=-------------|--------|
//  |  0  ||   1    |       root1      |                  |         |                |                |        |
//  |  1  ||   0    |     digest_1     |      elem_11     | cbit_11 |digest_1/elem_11|digest_1/elem_11| hash1  |
//  |  2  ||   0    |     digest_2     |      elem_12     | cbit_12 |digest_1/elem_12|digest_1/elem_12| hash2  |
//  |  3  ||   0    |       leaf1      |      elem_13     | cbit_13 |  leaf1/elem_13 |  leaf1/elem_13 | hash3  |
//  |  4  ||   1    |       root2      |                  |         |                |                |        |
//  |-----||--------|------------------|------------------|---------|----------------|----------------|--------|


use halo2::{
    circuit::{Chip, Layouter},
    plonk::{
        Advice, Column, TableColumn, ConstraintSystem, Error, Expression,
    },
    poly::Rotation,
    arithmetic::FieldExt,
};
use std::marker::PhantomData;

//use lazy_static::lazy_static;
//use rand::{thread_rng, Rng, SeedableRng};
//use rand_chacha::ChaCha8Rng;

struct MPTChip<F> {
    config: MPTChipConfig,
    _marker: PhantomData<F>
}

/// Config a chip for verify mutiple merkle path in MPT
#[derive(Clone, Debug)]
struct MPTChipConfig {
    is_first: Column<Advice>,
    val: Column<Advice>,
    sibling: Column<Advice>,
    path: Column<Advice>,
    left: TableColumn,
    right: TableColumn,
    hash: TableColumn,
}

/*
struct Alloc {
    cell: Cell,
    value: Fp,
}

enum MaybeAlloc {
    Alloc(Alloc),
    Unalloc(Fp),
}

impl MaybeAlloc {
    fn value(&self) -> Fp {
        match self {
            MaybeAlloc::Alloc(alloc) => alloc.value.clone(),
            MaybeAlloc::Unalloc(value) => value.clone(),
        }
    }

    fn cell(&self) -> Cell {
        match self {
            MaybeAlloc::Alloc(alloc) => alloc.cell.clone(),
            MaybeAlloc::Unalloc(_) => unreachable!(),
        }
    }
}
*/

impl<Fp: FieldExt> Chip<Fp> for MPTChip<Fp> {
    type Config = MPTChipConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<Fp: FieldExt> MPTChip<Fp> {

    fn configure(
        meta: &mut ConstraintSystem<Fp>,
        is_first: Column<Advice>,
        val: Column<Advice>,
        sibling: Column<Advice>,
        path: Column<Advice>,        
    ) -> <Self as Chip<Fp>>::Config {
        let left = meta.lookup_table_column();
        let right = meta.lookup_table_column();
        let hash = meta.lookup_table_column();

        // Only lookup for hash table should be
        // setuped here, no other gates required
        //
        // |-------|-------|-------|
        // |  val  |sibling|  path |
        // |-------|-------|-------|
        // |   a   |   b   |  bit  |
        // |   c   |   d   |  bit  |
        // |-------|-------|-------|
        // where:
        //     bit = 0  ==>  l = a, r = b
        //     bit = 1  ==>  l = b, r = a
        //     h = upper cell of val col
        //
        // and we lookup (l, r, h) for each row which IsFirst is zero
        // that is:
        // (
        //   bit * (b - a) + a,
        //   bit * (a - b) + b,
        //   a.Rotation(-1)
        // )
        //
        // from table formed by (left, right, hash)
        meta.lookup(|meta|{
            let not_first = Expression::Constant(Fp::one()) - meta.query_advice(is_first, Rotation::cur());

            let path_bit = meta.query_advice(path, Rotation::cur());
            let val_col = meta.query_advice(val, Rotation::cur());
            let sibling_col = meta.query_advice(sibling, Rotation::cur());
            let right_lookup = not_first.clone() * (path_bit.clone() * (val_col.clone() - sibling_col.clone()) + sibling_col.clone());
            let left_lookup = not_first.clone() * (path_bit * (sibling_col - val_col.clone()) + val_col);
            let hash_lookup = not_first * meta.query_advice(val, Rotation::prev());

            vec![(left_lookup, left), 
            (right_lookup, right), 
            (hash_lookup, hash)]
        });

        MPTChipConfig {
            is_first,
            val,
            sibling,
            path,
            left,
            right,
            hash,
        }
    }

    pub fn construct(config: MPTChipConfig) -> Self {
        MPTChip { 
            config,
            _marker: PhantomData,
        }
    }

    pub fn load(
        &self,
        layouter: &mut impl Layouter<Fp>,
        hashing_records: Vec<(Fp, Fp, Fp)>,
    ) -> Result<(), Error> {

        let left = self.config().left;
        let right = self.config().right;
        let hash = self.config().hash;

        layouter.assign_table(
            ||"hash table",
            |mut table|{

                hashing_records.iter().enumerate().try_for_each(|(offset, val)|{
                    let (lh, rh, h) = val;

                    table.assign_cell(
                        || "left",
                        left,
                        offset,
                        || Ok(*lh)
                    )?;

                    table.assign_cell(
                        || "right",
                        right,
                        offset,
                        || Ok(*rh)
                    )?;

                    table.assign_cell(
                        || "result",
                        hash,
                        offset,
                        || Ok(*h)
                    )?;                    

                    Ok(())
                })
            }
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use ff::Field;
    use halo2::{
        circuit::SimpleFloorPlanner,
        dev::{MockProver, VerifyFailure},
        pairing::bn256::Fr as Fp, // why halo2-merkle tree use Fp?
        plonk::Circuit,
    };

    #[derive(Clone, Default)]
    struct MPTTestSinglePathCircuit {
        last: Fp, //the bottom node
        siblings: Vec<Fp>,
        path: u32, //the path key simply expressed by u32
    }
    
    impl Circuit<Fp> for MPTTestSinglePathCircuit {
        type Config = MPTChipConfig;
        type FloorPlanner = SimpleFloorPlanner;
        
        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {

            let is_first = meta.advice_column();
            let val = meta.advice_column();
            let sibling = meta.advice_column();
            let path = meta.advice_column();
            let one = Expression::Constant(Fp::one());

            meta.create_gate("boolean/bit", |meta| {
                let is_first_col = meta.query_advice(is_first, Rotation::cur());
                let path_col = meta.query_advice(path, Rotation::cur());
                vec![is_first_col.clone() * (is_first_col - one.clone()),
                path_col.clone() * (path_col - one.clone())]
            });

            MPTChip::configure(meta, is_first, val, sibling, path)
        }

        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
            let mpt_chip = MPTChip::<Fp>::construct(config);
            //mpt_chip.load(&mut layouter)?;
            Ok(())
        }

    }
}

