//! mpt demo circuits
//

#![allow(dead_code)]
#![allow(unused_macros)]
#![allow(clippy::too_many_arguments)]
#![deny(missing_docs)]
#![deny(unsafe_code)]

pub use crate::serde::{Hash, Row, RowDeError};

mod eth;
mod layers;
mod mpt;
mod mpt_table;
#[cfg(test)]
mod test_utils;

pub mod operation;
pub mod serde;

use eth::StorageGadget;
use hash_circuit::hash::PoseidonHashTable;
/// re-export required namespace from depened poseidon hash circuit
pub use hash_circuit::{hash, poseidon};
pub use mpt_table::MPTProofType;
use mpt_table::{Config as MPTConfig, MPTEntry, MPTTable};

use lazy_static::lazy_static;
use std::sync::Mutex;
lazy_static! {
    static ref RAND_BASE: Mutex<Vec<u64>> = Mutex::new(vec![0x10000u64]);
}

/// global entry to set new RAND_BASE instead of default: 0x100
pub fn set_rand_base(r: u64) {
    RAND_BASE.lock().unwrap().push(r);
}

fn get_rand_base() -> u64 {
    *RAND_BASE
        .lock()
        .unwrap()
        .last()
        .expect("always has init element")
}

/// Indicate the operation type of a row in MPT circuit
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

// we lookup the transition of ctrl type from the preset table, and different kind of rules
// is specified here
enum CtrlTransitionKind {
    Mpt = 1,        // transition in MPT circuit
    Account,        // transition in account circuit
    Operation = 99, // transition of the old state to new state in MPT circuit
}

use eth::AccountGadget;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression},
};
use hash::Hashable;
use layers::{LayerGadget, PaddingGadget};
use mpt::MPTOpGadget;
use operation::{AccountOp, HashTracesSrc, SingleOp};

// building lagrange polynmials L for T so that L(n) = 1 when n = T else 0, n in [0, TO]
fn lagrange_polynomial<Fp: FieldExt, const T: usize, const TO: usize>(
    ref_n: Expression<Fp>,
) -> Expression<Fp> {
    let mut denominators: Vec<Fp> = (0..=TO)
        .map(|v| Fp::from(T as u64) - Fp::from(v as u64))
        .collect();
    denominators.swap_remove(T);
    let denominator = denominators.into_iter().fold(Fp::one(), |acc, v| v * acc);
    assert_ne!(denominator, Fp::zero());

    let mut factors: Vec<Expression<Fp>> = (0..(TO + 1))
        .map(|v| ref_n.clone() - Expression::Constant(Fp::from(v as u64)))
        .collect();
    factors.swap_remove(T);
    factors.into_iter().fold(
        Expression::Constant(denominator.invert().unwrap()),
        |acc, f| acc * f,
    )
}

/// The config for circuit
#[derive(Clone, Debug)]
pub struct SimpleTrieConfig {
    layer: LayerGadget,
    padding: PaddingGadget,
    mpt: MPTOpGadget,
}

/// The chip for op on a simple trie
#[derive(Clone, Default)]
pub struct SimpleTrie<F: FieldExt> {
    c_size: usize, //how many rows
    start_root: F,
    final_root: F,
    ops: Vec<SingleOp<F>>,
}

const OP_MPT: u32 = 1;
const OP_PADDING: u32 = 0;

impl<Fp: FieldExt> SimpleTrie<Fp> {
    /// create a new, empty circuit with specified size
    pub fn new(c_size: usize) -> Self {
        Self {
            c_size,
            ..Default::default()
        }
    }

    /// Add an op into the circuit data
    pub fn add_op(&mut self, op: SingleOp<Fp>) {
        if self.ops.is_empty() {
            self.start_root = op.start_root();
        } else {
            assert_eq!(self.final_root, op.start_root());
        }
        self.final_root = op.new_root();
        self.ops.push(op);
    }

    /// Obtain the total rows required by each operation
    pub fn use_rows(&self) -> usize {
        self.ops.iter().fold(0, |acc, op| acc + op.use_rows())
    }
}

impl<Fp: FieldExt> Circuit<Fp> for SimpleTrie<Fp> {
    type Config = SimpleTrieConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            c_size: self.c_size,
            ..Default::default()
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let layer = LayerGadget::configure(
            meta,
            2,
            MPTOpGadget::min_free_cols(),
            MPTOpGadget::min_ctrl_types(),
        );
        let padding = PaddingGadget::configure(
            meta,
            layer.public_sel(),
            layer.exported_cols(OP_PADDING).as_slice(),
            layer.get_ctrl_type_flags(),
        );
        let mpt = MPTOpGadget::configure_simple(
            meta,
            layer.public_sel(),
            layer.exported_cols(OP_MPT).as_slice(),
            layer.get_ctrl_type_flags(),
            layer.get_free_cols(),
            Some(layer.get_root_indexs()),
        );

        let cst = meta.fixed_column();
        meta.enable_constant(cst);

        SimpleTrieConfig {
            layer,
            padding,
            mpt,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "main",
            |mut region| {
                let mut series: usize = 1;
                let mut last_op_code = config.layer.start_op_code();
                let mut start = config
                    .layer
                    .assign(&mut region, self.c_size, self.start_root)?;
                for op in self.ops.iter() {
                    let block_start = start;
                    config.layer.pace_op(
                        &mut region,
                        start,
                        (last_op_code, OP_MPT),
                        op.use_rows(),
                    )?;
                    start = config.mpt.assign(&mut region, start, op)?;
                    assert!(
                        start <= self.c_size,
                        "assigned rows exceed limited {}",
                        self.c_size
                    );
                    config.layer.complete_block(
                        &mut region,
                        block_start,
                        series,
                        Some((op.start_root(), op.new_root())),
                        None,
                        op.use_rows(),
                    )?;
                    series += 1;
                    last_op_code = OP_MPT;
                }

                let row_left = self.c_size - start;
                if row_left > 0 {
                    config.layer.pace_op(
                        &mut region,
                        start,
                        (last_op_code, OP_PADDING),
                        row_left,
                    )?;
                    config.padding.padding(&mut region, start, row_left)?;
                    config.layer.complete_block(
                        &mut region,
                        start,
                        series,
                        None,
                        None,
                        row_left,
                    )?;
                }

                Ok(())
            },
        )?;

        config
            .mpt
            .tables
            .fill_constant(&mut layouter, MPTOpGadget::transition_rules())?;
        config.mpt.hash_table.dev_fill(
            &mut layouter,
            self.ops.iter().flat_map(|op| op.hash_traces()),
        )?;

        // only ctrl_type as HashType::leaf / empty can start new block
        let possible_end_block = [
            (OP_MPT, HashType::Empty as u32),
            (OP_MPT, HashType::Leaf as u32),
        ];
        let possible_start_block = [(OP_MPT, HashType::Start as u32), (OP_PADDING, 0)];

        let border_list: Vec<layers::OpBorder> = possible_start_block
            .into_iter()
            .flat_map(|st0| possible_end_block.iter().map(move |st1| (st0, *st1)))
            .collect();
        config.layer.set_op_border(
            &mut layouter,
            &border_list,
            &[],
            (OP_MPT, HashType::Start as u32),
        )
    }
}

/// For an operation on the eth storage (2-layer) trie
#[derive(Clone, Debug)]
pub struct EthTrieConfig {
    layer: LayerGadget,
    account: AccountGadget,
    storage: StorageGadget,
    account_trie: MPTOpGadget,
    state_trie: MPTOpGadget,
    padding: PaddingGadget,
    tables: mpt::MPTOpTables,
    hash_tbl: mpt::HashTable,
    mpt_tbl: Option<MPTConfig>,
}

impl EthTrieConfig {
    /// the beginning of hash table index
    pub fn hash_tbl_begin(&self) -> usize {
        self.hash_tbl.commitment_index()[0]
    }

    /// the beginning of mpt table index
    pub fn mpt_tbl_begin(&self) -> usize {
        self.mpt_tbl
            .as_ref()
            .expect("only call for non-lite circuit")
            .mpt_table_begin_index()
    }

    /// configure for lite circuit (no mpt table included, for fast testing)
    pub fn configure_base<Fp: FieldExt>(
        meta: &mut ConstraintSystem<Fp>,
        hash_tbl: [Column<Advice>; 5],
    ) -> Self {
        let tables = mpt::MPTOpTables::configure_create(meta);
        let hash_tbl = mpt::HashTable::configure_assign(&hash_tbl);

        let layer = LayerGadget::configure(
            meta,
            5,
            std::cmp::max(
                MPTOpGadget::min_free_cols(),
                std::cmp::max(
                    AccountGadget::min_free_cols(),
                    StorageGadget::min_free_cols(),
                ),
            ),
            std::cmp::max(
                MPTOpGadget::min_ctrl_types(),
                std::cmp::max(
                    AccountGadget::min_ctrl_types(),
                    StorageGadget::min_ctrl_types(),
                ),
            ),
        );
        let padding = PaddingGadget::configure(
            meta,
            layer.public_sel(),
            layer.exported_cols(OP_PADDING).as_slice(),
            layer.get_ctrl_type_flags(),
        );
        let account_trie = MPTOpGadget::configure(
            meta,
            layer.public_sel(),
            layer.exported_cols(OP_TRIE_ACCOUNT).as_slice(),
            layer.get_ctrl_type_flags(),
            layer.get_free_cols(),
            Some(layer.get_root_indexs()),
            tables.clone(),
            hash_tbl.clone(),
        );
        let state_trie = MPTOpGadget::configure(
            meta,
            layer.public_sel(),
            layer.exported_cols(OP_TRIE_STATE).as_slice(),
            layer.get_ctrl_type_flags(),
            layer.get_free_cols(),
            None,
            tables.clone(),
            hash_tbl.clone(),
        );
        let account = AccountGadget::configure(
            meta,
            layer.public_sel(),
            layer.exported_cols(OP_ACCOUNT).as_slice(),
            layer.get_ctrl_type_flags(),
            layer.get_free_cols(),
            Some(layer.get_address_index()),
            tables.clone(),
            hash_tbl.clone(),
        );
        let storage = StorageGadget::configure(
            meta,
            layer.public_sel(),
            layer.exported_cols(OP_STORAGE).as_slice(),
            layer.get_ctrl_type_flags(),
            layer.get_free_cols(),
            hash_tbl.clone(),
        );

        let cst = meta.fixed_column();
        meta.enable_constant(cst);

        Self {
            layer,
            account_trie,
            state_trie,
            account,
            storage,
            padding,
            tables,
            hash_tbl,
            mpt_tbl: None,
        }
    }

    /// configure for lite circuit (no mpt table included, for fast testing)
    pub fn configure_lite<Fp: FieldExt>(meta: &mut ConstraintSystem<Fp>) -> Self {
        let hash_tbl = [0; 5].map(|_| meta.advice_column());
        Self::configure_base(meta, hash_tbl)
    }

    /// configure for full circuit
    pub fn configure_sub<Fp: FieldExt>(
        meta: &mut ConstraintSystem<Fp>,
        mpt_tbl: [Column<Advice>; 7],
        hash_tbl: [Column<Advice>; 5],
        randomness: Expression<Fp>,
    ) -> Self {
        let mut lite_cfg = Self::configure_base(meta, hash_tbl);
        let mpt_tbl = MPTTable::configure(meta, mpt_tbl, randomness);
        let layer = &lite_cfg.layer;
        let layer_exported = layer.exported_cols(0);
        let gadget_ind = layer.get_gadget_index();
        let root_ind = layer.get_root_indexs();
        let addr_ind = layer.get_address_index();

        mpt_tbl.bind_mpt_circuit(
            meta,
            gadget_ind,
            layer_exported[0],
            addr_ind,
            [root_ind.0, root_ind.1],
            [layer_exported[2], layer_exported[5]],
            [layer_exported[3], layer_exported[6]],
            [layer_exported[4], layer_exported[7]],
        );

        lite_cfg.mpt_tbl.replace(mpt_tbl);
        lite_cfg
    }

    /// synthesize the mpt table part, the randomness also specify
    /// if the base part of mpt table should be assigned
    pub fn load_mpt_table<'d, Fp: Hashable>(
        &self,
        layouter: &mut impl Layouter<Fp>,
        randomness: Option<Fp>,
        ops: impl IntoIterator<Item = &'d AccountOp<Fp>>,
        tbl_tips: impl IntoIterator<Item = MPTProofType>,
        rows: usize,
    ) -> Result<(), Error> {
        let mpt_entries = tbl_tips.into_iter().zip(ops).map(|(proof_type, op)| {
            if let Some(rand) = randomness {
                MPTEntry::from_op(proof_type, op, rand)
            } else {
                MPTEntry::from_op_no_base(proof_type, op)
            }
        });

        let mpt_tbl = MPTTable::construct(
            self.mpt_tbl.clone().expect("only call under NON-LITE mode"),
            mpt_entries,
            rows,
        );
        mpt_tbl.load(layouter)
    }

    /// synthesize the hash table part, it is an development-only
    /// entry which just fill the hashes come from mpt circuit itself
    pub fn dev_load_hash_table<'d, Fp: Hashable>(
        &self,
        layouter: &mut impl Layouter<Fp>,
        hash_traces: impl Iterator<Item = &'d (Fp, Fp, Fp)> + Clone,
        rows: usize,
    ) -> Result<(), Error> {
        self.hash_tbl.dev_fill_with_paddings(
            layouter,
            HashTracesSrc::from(hash_traces),
            (
                Fp::zero(),
                Fp::zero(),
                Hashable::hash([Fp::zero(), Fp::zero()]),
            ),
            rows,
        )
    }

    /// synthesize core part without advice tables (hash and mpt table),
    /// require a `Hashable` trait on the working field
    pub fn synthesize_core<'d, Fp: Hashable>(
        &self,
        layouter: &mut impl Layouter<Fp>,
        ops: impl Iterator<Item = &'d AccountOp<Fp>> + Clone,
        rows: usize,
    ) -> Result<(), Error> {
        let start_root = ops
            .clone()
            .next()
            .map(|op| op.account_root_before())
            .unwrap_or_else(Fp::zero);

        layouter.assign_region(
            || "main",
            |mut region| {
                let mut series: usize = 1;
                let mut last_op_code = self.layer.start_op_code();
                let mut start = self.layer.assign(&mut region, rows, start_root)?;

                let empty_account = Default::default();
                for op in ops.clone() {
                    let block_start = start;
                    self.layer.pace_op(
                        &mut region,
                        start,
                        (last_op_code, OP_TRIE_ACCOUNT),
                        op.use_rows_trie_account(),
                    )?;
                    start = self.account_trie.assign(&mut region, start, &op.acc_trie)?;
                    self.layer.pace_op(
                        &mut region,
                        start,
                        (OP_TRIE_ACCOUNT, OP_ACCOUNT),
                        op.use_rows_account(),
                    )?;
                    start = self.account.assign(
                        &mut region,
                        start,
                        (
                            op.account_before.as_ref().unwrap_or(&empty_account),
                            op.account_after.as_ref().unwrap_or(&empty_account),
                        ),
                        op.address_rep.clone(),
                        Some(op.state_trie.is_none()),
                    )?;
                    if let Some(trie) = &op.state_trie {
                        self.layer.pace_op(
                            &mut region,
                            start,
                            (OP_ACCOUNT, OP_TRIE_STATE),
                            op.use_rows_trie_state(),
                        )?;
                        start = self.state_trie.assign(&mut region, start, trie)?;
                        self.layer
                            .pace_op(&mut region, start, (OP_TRIE_STATE, OP_STORAGE), 1)?;
                        start = self.storage.assign(&mut region, start, op)?;

                        last_op_code = OP_STORAGE;
                    } else {
                        last_op_code = OP_ACCOUNT;
                    }

                    assert!(start <= rows, "assigned rows for exceed limited {rows}");

                    self.layer.complete_block(
                        &mut region,
                        block_start,
                        series,
                        Some((op.account_root_before(), op.account_root())),
                        Some(op.address),
                        start - block_start,
                    )?;

                    series += 1;
                }

                let row_left = rows - start;
                if row_left > 0 {
                    self.layer
                        .pace_op(&mut region, start, (last_op_code, OP_PADDING), row_left)?;
                    self.padding.padding(&mut region, start, row_left)?;
                    self.layer
                        .complete_block(&mut region, start, series, None, None, row_left)?;
                }

                Ok(())
            },
        )?;

        self.tables.fill_constant(
            layouter,
            MPTOpGadget::transition_rules().chain(AccountGadget::transition_rules()),
        )?;

        let possible_end_block = [
            //            (OP_TRIE_STATE, HashType::Empty as u32),
            //            (OP_TRIE_STATE, HashType::Leaf as u32),
            (OP_ACCOUNT, 3),
            (OP_STORAGE, 0),
        ];
        let possible_start_block = [(OP_TRIE_ACCOUNT, HashType::Start as u32), (OP_PADDING, 0)];
        let border_list: Vec<layers::OpBorder> = possible_start_block
            .into_iter()
            .flat_map(|st0| possible_end_block.iter().map(move |st1| (st0, *st1)))
            .collect();

        // manually made op border list
        let op_border_list = [
            ((OP_ACCOUNT, 0), (OP_TRIE_ACCOUNT, HashType::Empty as u32)),
            ((OP_ACCOUNT, 0), (OP_TRIE_ACCOUNT, HashType::Leaf as u32)),
            ((OP_TRIE_STATE, HashType::Start as u32), (OP_ACCOUNT, 2)),
            ((OP_STORAGE, 0), (OP_TRIE_STATE, HashType::Empty as u32)),
            ((OP_STORAGE, 0), (OP_TRIE_STATE, HashType::Leaf as u32)),
        ];

        self.layer.set_op_border_ex(
            layouter,
            &border_list,
            &op_border_list,
            &[
                (OP_TRIE_ACCOUNT, HashType::Start as u32),
                (OP_PADDING, HashType::Start as u32),
            ],
        )
    }
}
/// The chip for op on an storage trie
#[derive(Clone, Default)]
pub struct EthTrie<F: FieldExt> {
    start_root: F,
    final_root: F,
    ops: Vec<AccountOp<F>>,
}

const OP_TRIE_ACCOUNT: u32 = 1;
const OP_TRIE_STATE: u32 = 2;
const OP_ACCOUNT: u32 = 3;
const OP_STORAGE: u32 = 4;

impl<Fp: FieldExt> EthTrie<Fp> {
    /// Obtain the wrapped operation sequence
    pub fn get_ops(&self) -> &[AccountOp<Fp>] {
        &self.ops
    }

    /// Add an op into the circuit data
    pub fn add_op(&mut self, op: AccountOp<Fp>) {
        if self.ops.is_empty() {
            self.start_root = op.account_root_before();
        } else {
            assert_eq!(self.final_root, op.account_root_before());
        }
        self.final_root = op.account_root();
        self.ops.push(op);
    }

    /// Add an op array
    pub fn add_ops(&mut self, ops: impl IntoIterator<Item = AccountOp<Fp>>) {
        for op in ops {
            self.add_op(op)
        }
    }

    /// Obtain the final root
    pub fn final_root(&self) -> Fp {
        self.final_root
    }
}

/// the mpt circuit type
#[derive(Clone, Default, Debug)]
pub struct EthTrieCircuit<F: FieldExt, const LITE: bool> {
    /// the maxium records in circuits (would affect vk)
    pub calcs: usize,
    /// the operations in circuits
    pub ops: Vec<AccountOp<F>>,
    /// the mpt table for operations,
    /// if NONE, circuit work under lite mode
    /// no run-time checking for the consistents between ops and generated mpt table
    pub mpt_table: Vec<MPTProofType>,
}

impl<Fp: Hashable> EthTrieCircuit<Fp, true> {
    /// create circuit without mpt table
    pub fn new_lite(calcs: usize, ops: Vec<AccountOp<Fp>>) -> Self {
        Self {
            calcs,
            ops,
            ..Default::default()
        }
    }
}

impl<Fp: Hashable> EthTrieCircuit<Fp, false> {
    /// create circuit
    pub fn new(calcs: usize, ops: Vec<AccountOp<Fp>>, mpt_table: Vec<MPTProofType>) -> Self {
        Self {
            calcs,
            ops,
            mpt_table,
        }
    }

    /// downgrade circuit to lite mode
    pub fn switch_lite(self) -> EthTrieCircuit<Fp, true> {
        EthTrieCircuit::<Fp, true> {
            calcs: self.calcs,
            ops: self.ops,
            mpt_table: Vec::new(),
        }
    }
}

/// a companied hash circuit as the companion of mpt hashes
pub struct HashCircuit<F: Hashable>(hash::PoseidonHashTable<F>, usize);

impl<Fp: Hashable> HashCircuit<Fp> {
    /// re-warped, all-in-one creation
    pub fn new(calcs: usize, input_with_check: &[&(Fp, Fp, Fp)]) -> Self {
        let mut tbl = PoseidonHashTable::default();
        tbl.constant_inputs_with_check(input_with_check.iter().copied());
        Self(tbl, calcs)
    }
}

impl<Fp: Hashable> Circuit<Fp> for HashCircuit<Fp> {
    type Config = hash::PoseidonHashConfig<Fp>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self(Default::default(), self.1)
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let hash_tbl = [0; 5].map(|_| meta.advice_column());
        hash::PoseidonHashConfig::configure_sub(meta, hash_tbl, hash_circuit::DEFAULT_STEP)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let chip = hash::PoseidonHashChip::<Fp, { hash_circuit::DEFAULT_STEP }>::construct(
            config, 
            &self.0, 
            self.1,
            true,
            None,
        );
        chip.load(&mut layouter)
    }
}

impl<Fp: Hashable> EthTrie<Fp> {
    /// export the hashes involved in current operation sequence
    pub fn hash_traces(&self) -> impl Iterator<Item = &(Fp, Fp, Fp)> + Clone {
        self.ops.iter().flat_map(|op| op.hash_traces())
    }

    /// Obtain the total required rows for mpt and hash circuits (include the top and bottom padding)
    pub fn use_rows(&self) -> (usize, usize) {
        // calc rows for mpt circuit, we need to compare the rows used by adviced region and table region
        // there would be rare case that the hash table is shorter than adviced part
        let adv_rows = self.ops.iter().fold(0usize, |acc, op| acc + op.use_rows());
        let hash_rows =
            HashTracesSrc::from(self.ops.iter().flat_map(|op| op.hash_traces())).count();

        (adv_rows.max(hash_rows), hash_rows * Fp::hash_block_size())
    }

    /// Create all associated circuit objects, depecrated
    pub fn circuits(&self, rows: usize) -> (EthTrieCircuit<Fp, true>, HashCircuit<Fp>) {
        self.clone().to_circuits_lite((rows, Some(rows)))
    }

    /// Create all associated circuit objects for lite circuit, better API
    pub fn to_circuits_lite(
        self,
        rows: (usize, Option<usize>),
    ) -> (EthTrieCircuit<Fp, true>, HashCircuit<Fp>) {
        let (mpt_circuit, hash_circuit) = self.to_circuits(rows, &[]);
        (mpt_circuit.switch_lite(), hash_circuit)
    }

    /// Create all associated circuit objects, better API
    /// [rows] specified the maxium hash entries the accompanied hash circuit can handle
    /// and the option in rows specify the **circuit** rows mpt circuit would used
    /// without specified it would derived a mpt circuit much larger than the accompanied
    /// hash circuit, i.e: if the mpt circuit has almost fully filled there would be more
    /// hashes need to be handled than the accompanied hash circuit can accommodate
    pub fn to_circuits(
        self,
        rows: (usize, Option<usize>),
        tips: &[MPTProofType],
    ) -> (EthTrieCircuit<Fp, false>, HashCircuit<Fp>) {
        let (hash_rows, mpt_rows) = rows;
        let mpt_rows = mpt_rows.unwrap_or(hash_rows);
        let hashes: Vec<_> =
            HashTracesSrc::from(self.ops.iter().flat_map(|op| op.hash_traces())).collect();
        let hash_circuit = HashCircuit::new(hash_rows, &hashes);
        (
            EthTrieCircuit::new(mpt_rows, self.ops, Vec::from(tips)),
            hash_circuit,
        )
    }

    /// Create all associated circuit objects, with specificing the maxium rows circuit
    /// can used for deriving the entry limit in mpt circuit
    pub fn to_circuits_by_circuit_limit(
        self,
        maxium_circuit_rows: usize,
        tips: &[MPTProofType],
    ) -> (EthTrieCircuit<Fp, false>, HashCircuit<Fp>) {
        self.to_circuits((maxium_circuit_rows / Fp::hash_block_size(), None), tips)
    }
}

/// index for hash table's commitments
pub struct CommitmentIndexs(usize, usize, Option<usize>);

impl CommitmentIndexs {
    #[deprecated]
    /// the hash col's pos
    pub fn hash_pos(&self) -> (usize, usize) {
        (self.0, self.1)
    }

    #[deprecated]
    /// the first input col's pos
    pub fn left_pos(&self) -> (usize, usize) {
        (self.0 + 1, self.1 + 1)
    }

    #[deprecated]
    /// the second input col's pos
    pub fn right_pos(&self) -> (usize, usize) {
        (self.0 + 2, self.1 + 2)
    }

    /// the beginning of hash table index
    pub fn hash_tbl_begin(&self) -> usize {
        self.0
    }

    /// the beginning of hash table index, at the accompanied hash circuit
    pub fn hash_tbl_begin_at_accompanied_circuit(&self) -> usize {
        self.1
    }

    /// the beginning of mpt table index
    pub fn mpt_tbl_begin(&self) -> usize {
        self.2.expect("only call for non-lite circuit")
    }

    /// get commitment for lite circuit (no mpt)
    pub fn new<Fp: Hashable>() -> Self {
        let mut cs: ConstraintSystem<Fp> = Default::default();
        let config = EthTrieCircuit::<_, true>::configure(&mut cs);

        let trie_circuit_indexs = config.hash_tbl.commitment_index();

        let mut cs: ConstraintSystem<Fp> = Default::default();
        let config = HashCircuit::configure(&mut cs);

        let hash_circuit_indexs = config.commitment_index();

        Self(trie_circuit_indexs[0], hash_circuit_indexs[0], None)
    }

    /// get commitment for full circuit
    pub fn new_full_circuit<Fp: Hashable>() -> Self {
        let mut cs: ConstraintSystem<Fp> = Default::default();
        let config = EthTrieCircuit::<_, false>::configure(&mut cs);

        let trie_circuit_indexs = config.hash_tbl.commitment_index();
        let mpt_table_start = config
            .mpt_tbl
            .expect("should has mpt table")
            .mpt_table_begin_index();

        let mut cs: ConstraintSystem<Fp> = Default::default();
        let config = HashCircuit::configure(&mut cs);

        let hash_circuit_indexs = config.commitment_index();

        Self(
            trie_circuit_indexs[0],
            hash_circuit_indexs[0],
            Some(mpt_table_start),
        )
    }
}

const TEMP_RANDOMNESS: u64 = 1;

impl<Fp: Hashable, const LITE: bool> Circuit<Fp> for EthTrieCircuit<Fp, LITE> {
    type Config = EthTrieConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            calcs: self.calcs,
            ops: Vec::new(),
            mpt_table: Vec::new(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        if LITE {
            EthTrieConfig::configure_lite(meta)
        } else {
            let base = [0; 7].map(|_| meta.advice_column());
            let hash_tbl = [0; 5].map(|_| meta.advice_column());
            let randomness = Expression::Constant(Fp::from(get_rand_base()));
            EthTrieConfig::configure_sub(meta, base, hash_tbl, randomness)
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        config.dev_load_hash_table(
            &mut layouter,
            self.ops.iter().flat_map(|op| op.hash_traces()),
            self.calcs,
        )?;
        config.synthesize_core(&mut layouter, self.ops.iter(), self.calcs)?;
        if LITE {
            Ok(())
        } else {
            config.load_mpt_table(
                &mut layouter,
                Some(Fp::from(get_rand_base())),
                self.ops.as_slice(),
                self.mpt_table.iter().copied(),
                self.calcs,
            )
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::*;
    use halo2_proofs::dev::MockProver;
    use operation::*;

    #[test]
    fn circuit_degrees() {
        let mut cs: ConstraintSystem<Fp> = Default::default();
        EthTrieCircuit::<_, false>::configure(&mut cs);

        println!("mpt circuit degree: {}", cs.degree());
        assert!(cs.degree() <= 9);

        let mut cs: ConstraintSystem<Fp> = Default::default();
        HashCircuit::configure(&mut cs);

        println!("hash circuit degree: {}", cs.degree());
        assert!(cs.degree() <= 9);
    }

    #[test]
    fn mpt_table_index() {
        let ind = CommitmentIndexs::new_full_circuit::<Fp>().mpt_tbl_begin();
        println!("mpt table index start: {}", ind)
    }

    #[test]
    fn empty_eth_trie() {
        let k = 9;
        let data: EthTrie<Fp> = Default::default();
        let (circuit, _) = data.to_circuits((20, None), &[]);

        let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn rand_eth_trie() {
        let store_key = KeyValue::create_rand(mock_hash);
        let store_before = KeyValue::create_rand(mock_hash);
        let store_after = KeyValue::create_rand(mock_hash);

        let state_trie = SingleOp::<Fp>::create_rand_op(
            3,
            Some((store_before.hash(), store_after.hash())),
            Some(store_key.hash()),
            mock_hash,
        );

        let account_before = Account::<Fp> {
            balance: Fp::from(1000000u64),
            nonce: Fp::from(42u64),
            codehash: (rand_fp(), rand_fp()),
            state_root: state_trie.start_root(),
            ..Default::default()
        };

        let account_after = Account::<Fp> {
            nonce: Fp::from(43u64),
            state_root: state_trie.new_root(),
            ..account_before.clone()
        };

        let account_before = account_before.complete(mock_hash);
        let account_after = account_after.complete(mock_hash);

        let address_rep = KeyValue::create_rand(mock_hash);
        let address = address_rep.limb_0() * Fp::from(0x100000000u64)
            + address_rep.limb_1()
                * Fp::from_u128(0x1000000000000000000000000u128)
                    .invert()
                    .unwrap();

        let acc_trie = SingleOp::<Fp>::create_rand_op(
            4,
            Some((account_before.account_hash(), account_after.account_hash())),
            Some(address_rep.hash()),
            mock_hash,
        );

        let op1 = AccountOp::<Fp> {
            acc_trie,
            state_trie: Some(state_trie),
            account_after: Some(account_after),
            account_before: Some(account_before),
            address,
            address_rep,
            store_key: Some(store_key),
            store_before: Some(store_before),
            store_after: Some(store_after),
            ..Default::default()
        };

        let start_root = op1.account_root_before();
        let final_root = op1.account_root();

        let k = 9;
        let trie = EthTrie::<Fp> {
            start_root,
            final_root,
            ops: vec![op1],
        };

        let (circuit, _) = trie.to_circuits((40, None), &[MPTProofType::StorageChanged]);

        #[cfg(feature = "print_layout")]
        print_layout!("layouts/eth_trie_layout.png", k, &circuit);

        let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
        let ret = prover.verify();
        assert_eq!(ret, Ok(()), "{:#?}", ret);
    }
}
