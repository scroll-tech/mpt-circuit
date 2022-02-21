//! mpt demo circuits
//

#![allow(dead_code)]
#![allow(unused_macros)]
#![deny(missing_docs)]
#![deny(unsafe_code)]

pub use crate::serde::{Hash, Row, RowDeError};

mod eth;
mod layers;
mod mpt;
mod operation;
mod serde;

#[cfg(test)]
mod test_utils;

/// Indicate the operation type of a row in MPT circuit
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

// we lookup the transition of ctrl type from the preset table, and different kind of rules
// is specified here
enum CtrlTransitionKind {
    Mpt = 1,        // transition in MPT circuit
    Account,        // transition in account circuit
    Operation = 99, // transition of the old state to new state in MPT circuit
}

use eth::AccountGadget;
use halo2::{
    arithmetic::FieldExt,
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error, Expression},
};
use layers::{LayerGadget, PaddingGadget};
use mpt::MPTOpGadget;
use operation::{AccountOp, SingleOp};

// building lagrange polynmials L for T so that L(n) = 1 when n = T else 0, n in [0, TO]
fn lagrange_polynomial<Fp: ff::PrimeField, const T: usize, const TO: usize>(
    ref_n: Expression<Fp>,
) -> Expression<Fp> {
    let mut denominators: Vec<Fp> = (0..(TO + 1))
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

impl<Fp: FieldExt> Circuit<Fp> for SimpleTrie<Fp> {
    type Config = SimpleTrieConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let layer = LayerGadget::configure(meta, 2, MPTOpGadget::min_free_cols());
        let padding =
            PaddingGadget::configure(meta, layer.public_sel(), layer.exported_cols(OP_PADDING));
        let mpt = MPTOpGadget::configure_simple(
            meta,
            layer.public_sel(),
            layer.exported_cols(OP_MPT),
            layer.get_free_cols(),
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
                    config.layer.pace_op(
                        &mut region,
                        start,
                        series,
                        (last_op_code, OP_MPT),
                        op.new_root(),
                        op.use_rows(),
                    )?;
                    start = config.mpt.assign(&mut region, start, op)?;
                    assert!(
                        start <= self.c_size,
                        "assigned rows exceed limited {}",
                        self.c_size
                    );
                    series += 1;
                    last_op_code = OP_MPT;
                }

                let row_left = self.c_size - start;
                if row_left > 0 {
                    config.layer.pace_op(
                        &mut region,
                        start,
                        series,
                        (last_op_code, OP_PADDING),
                        self.final_root,
                        row_left,
                    )?;
                    config
                        .padding
                        .padding(&mut region, start, row_left, self.final_root)?;
                }

                Ok(())
            },
        )?;

        config.mpt.init(&mut layouter)?;
        config.mpt.init_hash_table(&mut layouter, self.ops.iter())?;

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
    account_trie: MPTOpGadget,
    state_trie: MPTOpGadget,
    padding: PaddingGadget,
    tables: mpt::MPTOpTables,
    hash_tbls: (mpt::HashTable, mpt::HashTable),
}

/// The chip for op on an storage trie
#[derive(Clone, Default)]
pub struct EthTrie<F: FieldExt> {
    c_size: usize, //how many rows
    start_root: F,
    final_root: F,
    ops: Vec<AccountOp<F>>,
}

const OP_TRIE_ACCOUNT: u32 = 1;
const OP_TRIE_STATE: u32 = 2;
const OP_ACCOUNT: u32 = 3;

impl<Fp: FieldExt> Circuit<Fp> for EthTrie<Fp> {
    type Config = EthTrieConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let tables = mpt::MPTOpTables::configure_create(meta);
        let hash_tbls = (
            mpt::HashTable::configure_create(meta),
            mpt::HashTable::configure_create(meta),
        );

        let layer = LayerGadget::configure(
            meta,
            4,
            std::cmp::max(MPTOpGadget::min_free_cols(), AccountGadget::min_free_cols()),
        );
        let padding =
            PaddingGadget::configure(meta, layer.public_sel(), layer.exported_cols(OP_PADDING));
        let account_trie = MPTOpGadget::configure(
            meta,
            layer.public_sel(),
            layer.exported_cols(OP_TRIE_ACCOUNT),
            layer.get_free_cols(),
            tables.clone(),
            hash_tbls.clone(),
        );
        let state_trie = MPTOpGadget::configure(
            meta,
            layer.public_sel(),
            layer.exported_cols(OP_TRIE_STATE),
            layer.get_free_cols(),
            tables.clone(),
            hash_tbls.clone(),
        );
        let account = AccountGadget::configure(
            meta,
            layer.public_sel(),
            layer.exported_cols(OP_ACCOUNT),
            layer.get_free_cols(),
            tables.clone(),
            hash_tbls.clone(),
        );

        let cst = meta.fixed_column();
        meta.enable_constant(cst);

        EthTrieConfig {
            layer,
            account_trie,
            state_trie,
            account,
            padding,
            tables,
            hash_tbls,
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

                let empty_account = operation::Account::<Fp>::default();
                for op in self.ops.iter() {
                    let op_root = op.account_root();
                    config.layer.pace_op(
                        &mut region,
                        start,
                        series,
                        (last_op_code, OP_TRIE_ACCOUNT),
                        op_root,
                        op.use_rows_trie_account(),
                    )?;
                    start = config
                        .account_trie
                        .assign(&mut region, start, &op.acc_trie)?;
                    config.layer.pace_op(
                        &mut region,
                        start,
                        series,
                        (OP_TRIE_ACCOUNT, OP_ACCOUNT),
                        op_root,
                        op.use_rows_account(),
                    )?;
                    start = config.account.assign(
                        &mut region,
                        start,
                        (
                            op.account_before.as_ref().unwrap_or(&empty_account),
                            &op.account_after,
                        ),
                    )?;
                    if let Some(trie) = &op.state_trie {
                        config.layer.pace_op(
                            &mut region,
                            start,
                            series,
                            (OP_ACCOUNT, OP_TRIE_STATE),
                            op_root,
                            op.use_rows_trie_state(),
                        )?;
                        start = config.state_trie.assign(&mut region, start, trie)?;
                        last_op_code = OP_TRIE_STATE;
                    } else {
                        last_op_code = OP_ACCOUNT;
                    }

                    assert!(
                        start <= self.c_size,
                        "assigned rows for exceed limited {}",
                        self.c_size
                    );

                    series += 1;
                }

                let row_left = self.c_size - start;
                if row_left > 0 {
                    config.layer.pace_op(
                        &mut region,
                        start,
                        series,
                        (last_op_code, OP_PADDING),
                        self.final_root,
                        row_left,
                    )?;
                    config
                        .padding
                        .padding(&mut region, start, row_left, self.final_root)?;
                }

                Ok(())
            },
        )?;

        let empty_trace: Vec<(Fp, Fp, Fp)> = Vec::default();

        let hashs_old = self.ops.iter().flat_map(|op| {
            let i = op.acc_trie.old.hash_traces.iter();
            let i = if let Some(acc) = &op.account_before {
                i.chain(acc.hash_traces.iter())
            } else {
                i.chain(empty_trace.iter())
            };
            if let Some(trie) = &op.state_trie {
                i.chain(trie.old.hash_traces.iter())
            } else {
                i.chain(empty_trace.iter())
            }
        });

        config.hash_tbls.0.fill(&mut layouter, hashs_old)?;

        let hashs_new = self.ops.iter().flat_map(|op| {
            let i = op
                .acc_trie
                .new
                .hash_traces
                .iter()
                .chain(op.account_after.hash_traces.iter());
            if let Some(trie) = &op.state_trie {
                i.chain(trie.new.hash_traces.iter())
            } else {
                i.chain(empty_trace.iter())
            }
        });

        config.hash_tbls.1.fill(&mut layouter, hashs_new)?;
        config.tables.fill_constant(
            &mut layouter,
            MPTOpGadget::transition_rules().chain(AccountGadget::transition_rules()),
        )?;

        let possible_end_block = [
            (OP_TRIE_STATE, HashType::Empty as u32),
            (OP_TRIE_STATE, HashType::Leaf as u32),
            (OP_ACCOUNT, 4),
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
            ((OP_TRIE_STATE, HashType::Start as u32), (OP_ACCOUNT, 3)),
        ];

        config.layer.set_op_border(
            &mut layouter,
            &border_list,
            &op_border_list,
            (OP_TRIE_ACCOUNT, HashType::Start as u32),
        )
    }
}

#[cfg(test)]
mod test {
    #![allow(unused_imports)]
    use super::*;
    use crate::{serde::Row, test_utils::*};
    use ff::Field;
    use halo2::dev::{MockProver, VerifyFailure};
    use operation::*;

    #[test]
    fn geth_case_simple_trie() {
        let ops: Vec<SingleOp<Fp>> = Row::fold_flattern_rows(Row::from_lines(TEST_FILE).unwrap())
            .iter()
            .map(|v| SingleOp::<Fp>::from(v.as_slice()))
            .collect();

        let k = 5;
        let circuit = SimpleTrie::<Fp> {
            c_size: 22,
            start_root: ops[0].start_root(),
            final_root: ops.last().unwrap().new_root(),
            ops,
        };

        #[cfg(feature = "print_layout")]
        print_layout!("layouts/simple_trie_layout.png", k, &circuit);

        let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));

        //no padding
        let circuit = SimpleTrie::<Fp> {
            c_size: 20,
            start_root: circuit.start_root,
            final_root: circuit.final_root,
            ops: circuit.ops,
        };

        let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    fn decompose_path(key: Fp, layers: usize) -> (Vec<bool>, Fp) {
        assert!(layers < 128, "not able to decompose more than 128 layers");
        let test = key.get_lower_128();
        (
            (0..layers)
                .map(|i| (test & (1u128 << i as u128)) != 0u128)
                .collect(),
            (key - Fp::from_u128(test & ((1u128 << layers) - 1)))
                * Fp::from_u128(1u128 << layers).invert().unwrap(),
        )
    }

    /// create an random operation data (only contains middle and leaf type)
    /// with the help of siblings and calculating path ad-hoc by hasher function
    fn create_rand_op(
        layers: usize,
        leafs: Option<(Fp, Fp)>,
        hasher: impl FnMut(&Fp, &Fp) -> Fp + Clone,
    ) -> SingleOp<Fp> {
        let mut siblings: Vec<Fp> = (0..layers).map(|_| rand_fp()).collect();
        let key = rand_fp();

        let (path, key_res) = decompose_path(key, siblings.len());
        let (old_leaf, new_leaf) = leafs.unwrap_or_else(|| (rand_fp(), rand_fp()));

        let old = MPTPath::<Fp>::create(&path, &siblings, key, old_leaf, hasher.clone());
        let new = MPTPath::<Fp>::create(&path, &siblings, key, new_leaf, hasher);
        let mut path: Vec<Fp> = path
            .into_iter()
            .map(|b| if b { Fp::one() } else { Fp::zero() })
            .collect();
        siblings.push(Fp::zero());
        path.push(key_res);

        SingleOp::<Fp> {
            key,
            old,
            new,
            siblings,
            path,
        }
    }

    #[test]
    fn rand_eth_trie() {
        let state_trie = create_rand_op(3, None, mock_hash);

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

        let acc_trie = create_rand_op(
            4,
            Some((account_before.account_hash(), account_after.account_hash())),
            mock_hash,
        );

        let op1 = AccountOp::<Fp> {
            acc_trie,
            state_trie: Some(state_trie),
            account_after,
            account_before: Some(account_before),
        };

        let start_root = op1.account_root_before();
        let final_root = op1.account_root();

        let k = 6;
        let circuit = EthTrie::<Fp> {
            c_size: 20,
            start_root,
            final_root,
            ops: vec![op1],
        };

        #[cfg(feature = "print_layout")]
        print_layout!("layouts/eth_trie_layout.png", k, &circuit);

        let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
