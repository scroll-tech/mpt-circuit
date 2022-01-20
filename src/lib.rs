//! mpt demo circuits
//

#![allow(dead_code)]
#![deny(missing_docs)]
#![deny(unsafe_code)]

pub use crate::serde::{Hash, HashType, Row, RowDeError};

pub mod mpt;
pub mod operations;
mod serde;

#[cfg(test)]
mod test_utils;

use ff::PrimeField;
use halo2::{
    arithmetic::FieldExt,
    circuit::{Layouter, Region, SimpleFloorPlanner},
    plonk::{Advice, Circuit, Selector, Column, ConstraintSystem, Error},
};

#[derive(Clone, Debug)]
struct MPTConfig {
    s_row: Selector,
    sibling: Column<Advice>,
    path: Column<Advice>,
    old_hash_type: Column<Advice>,
    new_hash_type: Column<Advice>,
    old_hash: Column<Advice>,
    new_hash: Column<Advice>,
    old_val: Column<Advice>,
    new_val: Column<Advice>,    
    op_chip: operations::MPTOpChipConfig,
    old_state_chip: mpt::MPTChipConfig,
    new_state_chip: mpt::MPTChipConfig,
}

#[derive(Clone, Default)]
struct SingleOp<Fp: PrimeField> {
    pub old_hash_type: Vec<HashType>,
    pub new_hash_type: Vec<HashType>,
    pub key: Fp,
    pub old_leaf: Option<Fp>,
    pub new_leaf: Option<Fp>,
    // suppose the hash started from root to leaf node
    // i.e. the max length of old/new_hash is equal to
    // path and siblings, while the length and siblings 
    // has same length, the last element inside path/siblings
    // is not used 
    pub old_hash: Vec<Fp>,
    pub new_hash: Vec<Fp>,
    pub path: Vec<Fp>,
    pub siblings: Vec<Fp>, 
}

impl<Fp: FieldExt> SingleOp<Fp> {

    // indicate rows would take in circuit layout (include the heading row)
    fn use_rows(&self) -> usize { self.siblings.len() + 1 }

    fn start_root(&self) -> Fp { self.old_hash[0] }

    fn new_root(&self) -> Fp { self.new_hash[0] }

    fn gen_hash_traces(&self, hashes: &Vec<Fp>) -> Vec<(Fp, Fp, Fp)> {

        let mut last_hash = hashes[0];
        let mut trace = Vec::new();
        for (index, hash) in hashes.iter().skip(1).enumerate() {

            trace.push(
                if self.path[index] == Fp::one() {
                    (self.siblings[index], *hash, last_hash)
                } else {
                    (*hash, self.siblings[index], last_hash)
                }
            );
            last_hash = *hash
        }

        trace
    }

    fn old_hash_traces(&self) -> Vec<(Fp, Fp, Fp)> {
        self.gen_hash_traces(&self.old_hash)
    }

    fn new_hash_traces(&self) -> Vec<(Fp, Fp, Fp)> {
        self.gen_hash_traces(&self.new_hash)
    }

    fn fill_layer(
        &self,
        config: &MPTConfig,
        region: &mut Region<'_, Fp>,
        offset: usize,
    ) -> Result<usize, Error> {

        let mut old_val = self.old_hash.clone();
        if let Some(v) = self.old_leaf {
            old_val.push(v);
        }
        // notice we can have different length for old_val and new_val
        // we not care about unassigned cell because they just be reffered in lookup, not gate
        for (index, val) in old_val.iter().enumerate()  {
            region.assign_advice(|| "old hash or leaf val", config.old_val, index + offset, || Ok(*val))?;
        }
        let mut new_val = self.new_hash.clone();
        if let Some(v) = self.new_leaf {
            new_val.push(v);
        }
        for (index, val) in new_val.iter().enumerate()  {
            region.assign_advice(|| "new hash or leaf val", config.new_val, index + offset, || Ok(*val))?;
        }

        // pad first row
        region.assign_advice(|| "path", config.path, offset, || Ok(Fp::zero()))?;
        region.assign_advice(|| "hash_type_old", config.old_hash_type, offset, || Ok(Fp::zero()))?;
        region.assign_advice(|| "hash_type_new", config.new_hash_type, offset, || Ok(Fp::zero()))?;

        // other col start from row 1
        for ind in 0..self.path.len() {
            let offset = offset + ind + 1;
            config.s_row.enable(region, offset)?;

            region.assign_advice(
                || "path", 
                config.path,
                offset,
                || Ok(self.path[ind]))?;
            region.assign_advice(
                || "sibling",
                config.sibling,
                offset,
                || Ok(self.siblings[ind]),
            )?;
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

        // now use a op_chip for assigning the aux region
        let op_chip = operations::MPTOpChip::<Fp>::construct(config.op_chip.clone());
        op_chip.fill_aux(region, offset, &self.path, self.new_root())
    }
    
}

#[derive(Clone, Default)]
struct MPTDemoCircuit<Fp: PrimeField> {
    pub ops: Vec<SingleOp<Fp>>,
    pub max_rows: usize,
    used_rows: usize,
    old_hash_traces: Vec<(Fp, Fp, Fp)>,
    new_hash_traces: Vec<(Fp, Fp, Fp)>,
    start_root: Option<Fp>,
    exit_root: Option<Fp>,
}

impl<Fp: FieldExt> MPTDemoCircuit<Fp> {
    pub fn add_operation(&mut self, op: SingleOp<Fp>) -> Result<(), Error>{

        if self.used_rows + op.use_rows() > self.max_rows {
            return Err(Error::BoundsFailure)
        }
        self.used_rows += op.use_rows();

        self.exit_root.replace(op.new_root());
        if self.start_root.is_none() {
            self.start_root.replace(op.start_root());
        }

        self.old_hash_traces.append(&mut op.old_hash_traces());
        self.new_hash_traces.append(&mut op.new_hash_traces());

        self.ops.push(op);

        Ok(())
    }
}

impl<Fp: FieldExt> Circuit<Fp> for MPTDemoCircuit<Fp> {
    type Config = MPTConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {

        let s_row = meta.selector();
        let sibling = meta.advice_column();
        let path = meta.advice_column();
        let old_hash_type = meta.advice_column();
        let new_hash_type = meta.advice_column();
        let old_hash = meta.advice_column();
        let new_hash = meta.advice_column();
        let old_val = meta.advice_column();
        let new_val = meta.advice_column();

        let op_chip = operations::MPTOpChip::<Fp>::configure(meta, s_row, sibling, path, old_hash_type, new_hash_type, old_hash, new_hash);
        let new_state_chip = mpt::MPTChip::<Fp>::configure(meta, old_hash_type, old_hash, op_chip.key, sibling, path);
        let old_state_chip = mpt::MPTChip::<Fp>::configure(meta, new_hash_type, new_hash, op_chip.key, sibling, path);

        MPTConfig {
            s_row,
            sibling,
            path,
            old_hash_type,
            new_hash_type,
            old_hash,
            new_hash,
            old_val,
            new_val,
            op_chip,
            old_state_chip,
            new_state_chip,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {

        layouter.assign_region(
            || "multi op main",
            |mut region| {
                let mut offset = 0;

                for op in self.ops.iter() {
                    offset = op.fill_layer(&config, &mut region, offset)?;
                }
                
                for offset in 1..self.max_rows {
                    config.s_row.enable(&mut region, offset)?;
                }

                Ok(())
            },
            
        )?;

        let op_chip = operations::MPTOpChip::<Fp>::construct(config.op_chip);
        op_chip.load(&mut layouter)?;
        let state_new_chip = mpt::MPTChip::<Fp>::construct(config.new_state_chip);
        state_new_chip.load(&mut layouter, self.new_hash_traces.clone())?;
        let state_old_chip = mpt::MPTChip::<Fp>::construct(config.old_state_chip);
        state_old_chip.load(&mut layouter, self.old_hash_traces.clone())?;

        Ok(())
    }

}