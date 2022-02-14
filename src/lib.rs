//! mpt demo circuits
//

#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_macros)]
#![deny(missing_docs)]
#![deny(unsafe_code)]

pub use crate::serde::{Hash, Row, RowDeError};

mod mpt;
mod operation;
mod layers;
mod serde;

#[cfg(test)]
mod test_utils;

/// Indicate the type of a row
#[derive(Clone, Copy, Debug)]
pub enum HashType {
    /// Marking the start of node
    Start = 0,
    /// Empty node
    Empty,
    /// middle node
    Middle,
    /// leaf node which is extended to middle in insert
    LeafExt,
    /// leaf node which is extended to middle in insert, which is the last node in new path
    LeafExtFinal,
    /// leaf node
    Leaf,
}
/*
use ff::PrimeField;
use halo2::{
    arithmetic::FieldExt,
    circuit::{Layouter, Region, SimpleFloorPlanner},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Selector},
};

/// The config for circuit
#[derive(Clone, Debug)]
pub struct MPTConfig {
    s_row: Selector,
    sibling: Column<Advice>,
    path: Column<Advice>,
    old_hash_type: Column<Advice>,
    new_hash_type: Column<Advice>,
    old_val: Column<Advice>,
    new_val: Column<Advice>,
    op_chip: operations::MPTOpChipConfig,
    old_state_chip: mpt::MPTChipConfig,
    new_state_chip: mpt::MPTChipConfig,
}

/// Represent for a single operation
#[derive(Clone, Default, Debug)]
pub struct SingleOp<Fp: PrimeField> {
    old_hash_type: Vec<HashType>,
    new_hash_type: Vec<HashType>,
    key: Fp,
    old_leaf: Option<Fp>,
    new_leaf: Option<Fp>,
    // suppose the hash started from root to leaf node
    // i.e. the max length of old/new_hash is equal to
    // path and siblings, while the length and siblings
    // has same length, the last element inside path/siblings
    // is not used
    old_hash: Vec<Fp>,
    new_hash: Vec<Fp>,
    path: Vec<Fp>,
    siblings: Vec<Fp>,
}

// Turn a row array into single op, brutely fail with any reason like
// a unfinished op
impl<'d, Fp: FieldExt> From<&'d [serde::Row]> for SingleOp<Fp> {
    fn from(rows: &[serde::Row]) -> Self {
        let mut ret = SingleOp::<Fp> {
            key: Fp::from_bytes(rows[0].key.as_ref()).unwrap(),
            ..Default::default()
        };

        let leaf_val = Fp::from_bytes(rows.last().unwrap().old_value.as_ref()).unwrap();
        ret.old_leaf = if leaf_val != Fp::zero() {
            Some(leaf_val)
        } else {
            None
        };
        let leaf_val = Fp::from_bytes(rows.last().unwrap().new_value.as_ref()).unwrap();
        ret.new_leaf = if leaf_val != Fp::zero() {
            Some(leaf_val)
        } else {
            None
        };

        rows.iter().for_each(|row| {
            ret.old_hash
                .push(Fp::from_bytes(row.old_hash.as_ref()).unwrap());
            ret.new_hash
                .push(Fp::from_bytes(row.new_hash.as_ref()).unwrap());
            ret.siblings.push(Fp::from_bytes(row.sib.as_ref()).unwrap());
            let mut to_hash_int = row.path.to_bytes_le();
            to_hash_int.resize(32, 0u8);
            ret.path
                .push(Fp::from_bytes(&to_hash_int.try_into().unwrap()).unwrap());

            ret.new_hash_type.push(row.new_hash_type);
            ret.old_hash_type.push(row.old_hash_type);
        });

        ret
    }
}

impl<Fp: FieldExt> SingleOp<Fp> {
    // indicate rows would take in circuit layout (include the heading row)
    fn use_rows(&self) -> usize {
        self.siblings.len() + 1
    }

    fn start_root(&self) -> Fp {
        self.old_hash[0]
    }

    fn new_root(&self) -> Fp {
        self.new_hash[0]
    }

    fn gen_hash_traces(&self, hashes: &[Fp]) -> Vec<(Fp, Fp, Fp)> {
        let mut last_hash = hashes[0];
        let mut trace = Vec::new();
        for (index, hash) in hashes.iter().skip(1).enumerate() {
            trace.push(if self.path[index] == Fp::one() {
                (self.siblings[index], *hash, last_hash)
            } else {
                (*hash, self.siblings[index], last_hash)
            });
            last_hash = *hash
        }

        trace
    }

    fn old_hash_traces(&self) -> Vec<(Fp, Fp, Fp)> {
        let mut ret = self.gen_hash_traces(&self.old_hash);
        if let Some(leaf_v) = &self.old_leaf {
            ret.push((self.key, *leaf_v, *self.old_hash.last().unwrap()));
        };

        ret
    }

    fn new_hash_traces(&self) -> Vec<(Fp, Fp, Fp)> {
        let mut ret = self.gen_hash_traces(&self.new_hash);
        if let Some(leaf_v) = &self.new_leaf {
            ret.push((self.key, *leaf_v, *self.new_hash.last().unwrap()));
        };

        ret
    }

    fn fill_layer(
        &self,
        config: &MPTConfig,
        region: &mut Region<'_, Fp>,
        offset: usize,
        op_chip: &operations::MPTOpChip<Fp>,
    ) -> Result<usize, Error> {
        // pick assigned rang from path, notice one more row is required
        let assigned_range = self.path.len() + 1;

        let mut old_val = self.old_hash.clone();
        if let Some(v) = self.old_leaf {
            old_val.push(v);
        }
        // notice we can have different length for old_val and new_val
        for (index, val) in old_val.iter().enumerate() {
            region.assign_advice(
                || "old hash or leaf val",
                config.old_val,
                index + offset,
                || Ok(*val),
            )?;
        }
        // also we should pad the rest cell
        for index in old_val.len()..assigned_range {
            region.assign_advice(
                || "old hash or leaf val padding",
                config.old_val,
                index + offset,
                || Ok(Fp::zero()),
            )?;
        }

        let mut new_val = self.new_hash.clone();
        if let Some(v) = self.new_leaf {
            new_val.push(v);
        }
        for (index, val) in new_val.iter().enumerate() {
            region.assign_advice(
                || "new hash or leaf val",
                config.new_val,
                index + offset,
                || Ok(*val),
            )?;
        }
        for index in new_val.len()..assigned_range {
            region.assign_advice(
                || "new hash or leaf val padding",
                config.new_val,
                index + offset,
                || Ok(Fp::zero()),
            )?;
        }

        // pad first row
        region.assign_advice(|| "path", config.path, offset, || Ok(Fp::zero()))?;
        region.assign_advice(|| "sibling path", config.sibling, offset, || Ok(Fp::zero()))?;
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

            region.assign_advice(|| "path", config.path, offset, || Ok(self.path[ind]))?;
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

        op_chip.fill_aux(region, offset, &self.path, self.new_root())
    }

    // each op can pad one or more rows
    fn pad_row(
        &self,
        config: &MPTConfig,
        region: &mut Region<'_, Fp>,
        offset: usize,
        op_chip: &operations::MPTOpChip<Fp>,
    ) -> Result<usize, Error> {
        //notice: do not pad row 0
        assert_ne!(offset, 0);

        region.assign_advice(|| "padding path", config.path, offset, || Ok(Fp::zero()))?;
        region.assign_advice(
            || "padding sibling",
            config.sibling,
            offset,
            || Ok(Fp::zero()),
        )?;
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
            || Ok(self.new_root()),
        )?;
        region.assign_advice(
            || "padding new root",
            config.new_val,
            offset,
            || Ok(self.new_root()),
        )?;

        op_chip.padding_aux(region, offset, self.new_root())
    }
}

/// The demo circuit for op circuit
#[derive(Clone, Default)]
pub struct MPTDemoCircuit<Fp: PrimeField> {
    /// max row the circuits can accordinate
    pub max_rows: usize,
    ops: Vec<SingleOp<Fp>>,
    used_rows: usize,
    old_hash_traces: Vec<(Fp, Fp, Fp)>,
    new_hash_traces: Vec<(Fp, Fp, Fp)>,
    start_root: Option<Fp>,
    exit_root: Option<Fp>,
}

impl<Fp: FieldExt> MPTDemoCircuit<Fp> {
    /// create new instance
    pub fn new(max_rows: usize) -> Self {
        Self {
            max_rows,
            ..Default::default()
        }
    }

    /// insert an operation
    pub fn add_operation(&mut self, op: SingleOp<Fp>) -> Result<(), Error> {
        if self.used_rows + op.use_rows() > self.max_rows {
            return Err(Error::BoundsFailure);
        }
        self.used_rows += op.use_rows();

        if let Some(root) = self.exit_root {
            if op.start_root() != root {
                return Err(Error::Synthesis);
            }
        }

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
        let old_val = meta.advice_column();
        let new_val = meta.advice_column();
        let cst = meta.fixed_column();
        meta.enable_constant(cst);

        let op_chip = operations::MPTOpChip::<Fp>::configure(
            meta,
            s_row,
            path,
            old_hash_type,
            new_hash_type,
            old_val,
            new_val,
        );
        let old_state_chip = mpt::MPTChip::<Fp>::configure(
            meta,
            s_row,
            old_hash_type,
            old_val,
            op_chip.key,
            sibling,
            path,
        );
        let new_state_chip = mpt::MPTChip::<Fp>::configure(
            meta,
            s_row,
            new_hash_type,
            new_val,
            op_chip.key,
            sibling,
            path,
        );

        MPTConfig {
            s_row,
            sibling,
            path,
            old_hash_type,
            new_hash_type,
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
        let op_chip = operations::MPTOpChip::<Fp>::construct(config.op_chip.clone());
        op_chip.load(&mut layouter)?;
        let state_new_chip = mpt::MPTChip::<Fp>::construct(config.new_state_chip.clone());
        state_new_chip.load(&mut layouter, self.new_hash_traces.clone())?;
        let state_old_chip = mpt::MPTChip::<Fp>::construct(config.old_state_chip.clone());
        state_old_chip.load(&mut layouter, self.old_hash_traces.clone())?;

        layouter.assign_region(
            || "multi op main",
            |mut region| {
                for offset in 1..self.max_rows {
                    config.s_row.enable(&mut region, offset)?;
                }

                let mut offset = 0;
                for op in self.ops.iter() {
                    offset = op.fill_layer(&config, &mut region, offset, &op_chip)?;
                }
                let last_op = self.ops.last().unwrap();

                for pad_offset in offset..self.max_rows {
                    last_op.pad_row(&config, &mut region, pad_offset, &op_chip)?;
                }

                Ok(())
            },
        )?;

        Ok(())
    }
}
*/