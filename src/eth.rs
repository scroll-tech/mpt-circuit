//! represent operation on a storage trie in ethereum, which is a 2-layer trie, the leaf
//! of first trie is related to the root of another one, three gadgets (2 MptGadget and 1 AccountGadget)
//! are put together to form the circuit
//
// AccountGadget has to layout several lookup for a 2-member hash scheme: Hash(a, b) = c;
// to save some cost, we use a 3-col layout for such a lookup chip so finally the total requirment
// of free cols (4 cols) is not exceed the MPT's (6)
//
// ### The layout of a accout chip is like:
//  |-----||---------|--------|----------------|----------------|----------------|----------------|----------------|--------|
//  | row ||ctrl_type|s_enable|     Input      |  Intermediate  |     Exported   |     HashTable (left, right, hash)        |
//  |-----||---------|--------|----------------|----------------|----------------|----------------|----------------|--------|
//  |  2  || <other> |    0   |                |                |   <hash_final> |                                          |
//  |  3  ||    0    |    1   |     nonce      |                |    hash_final  |          hash3 hash2 hash_final          |
//  |  4  ||    1    |    1   |    balance     |      hash3     |      hash2     |          nonce balance hash3             |
//  |  5  ||    2    |    1   |Codehash_first  |                |      hash2     |            hash1 Root hash2              |
//  |  6  ||    3    |    1   |Codehash_Second |      hash1     |      Root      |  Codehash_first |Codehash_Second hash1   |
//  |  7  || <other> |    0   |                |                |      Root      |                                          |
//  |-----||---------|--------|----------------|----------------|----------------|----------------|----------------|--------|
//
//  Two lookup rules check cells in input and intermedia from hashtable for the 4 hashes, then a series of gates build
//  equality relation required (because the chip must be able to apply at any position of the circuit, equality can not be applied)
//
//  the ctrl_type is external for account chip. Our gadget use two accout chips and simply constraint the transition of rows:
//  0 -> 1, 1 -> 2, 2 -> 3
//
//  ### empty circuit
//  notice an empty circuit (all cells are zero) would satisify all constraints, which allow MPT circuit for empty leaf / trie
//  being connected with it
//
//  ### padding row
//  an additional row (marked as 4) can be add to the end which require the two account state are identify. with this special marking
//  row we can omit the state trie following AccountGadget

use super::mpt;
use super::CtrlTransitionKind;
use crate::operation::Account;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Chip, Region},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};
use lazy_static::lazy_static;

pub const CIRCUIT_ROW: usize = 5;
const LAST_ROW: usize = CIRCUIT_ROW - 1;

lazy_static! {
    static ref TRANSMAP: Vec<(u32, u32)> = {
        let mut ret: Vec<_> = (0..LAST_ROW).map(|s| (s as u32, (s + 1) as u32)).collect();
        ret.push((0, 0));
        ret
    };
}

#[derive(Clone, Debug)]
pub(crate) struct AccountGadget {
    old_state: AccountChipConfig,
    new_state: AccountChipConfig,
    s_enable: Column<Advice>,
    ctrl_type: Column<Advice>,
}

impl AccountGadget {
    pub fn min_free_cols() -> usize {
        4
    }

    /// create gadget from assigned cols, we need:
    /// + circuit selector * 1
    /// + exported col * 4 (MUST by following sequence: layout_flag, s_enable, old_val, new_val)
    /// + free col * 4
    pub fn configure<Fp: FieldExt>(
        meta: &mut ConstraintSystem<Fp>,
        sel: Selector,
        exported: [Column<Advice>; 4],
        free: &[Column<Advice>],
        tables: mpt::MPTOpTables,
        hash_tbls: (mpt::HashTable, mpt::HashTable), //(old, new)
    ) -> Self {
        assert!(free.len() >= 6, "require at least 6 free cols");
        let s_enable = exported[1];
        let ctrl_type = exported[0];
        let exported_old = exported[2];
        let exported_new = exported[3];

        let old_state = AccountChip::configure(
            meta,
            sel,
            s_enable,
            ctrl_type,
            exported_old,
            &free[0..2],
            hash_tbls.0,
        );
        let new_state = AccountChip::configure(
            meta,
            sel,
            s_enable,
            ctrl_type,
            exported_new,
            &free[2..4],
            hash_tbls.1,
        );

        //transition
        meta.lookup("account row trans", |meta| {
            let s_enable = meta.query_advice(s_enable, Rotation::cur())
                * (Expression::Constant(Fp::one())
                    - AccountChip::<'_, Fp>::lagrange_polynomial_for_row::<0>(
                        meta.query_advice(ctrl_type, Rotation::cur()),
                    ));
            let row_n = s_enable.clone() * meta.query_advice(ctrl_type, Rotation::cur());
            let prev_row_n = s_enable.clone() * meta.query_advice(ctrl_type, Rotation::prev());

            vec![
                (prev_row_n, tables.0),
                (row_n, tables.1),
                (
                    s_enable * Expression::Constant(Fp::from(CtrlTransitionKind::Account as u64)),
                    tables.2,
                ),
            ]
        });

        //additional row
        meta.create_gate("nonce", |meta| {
            let s_enable = meta.query_selector(sel) * meta.query_advice(s_enable, Rotation::cur());
            let row0 = AccountChip::<'_, Fp>::lagrange_polynomial_for_row::<0>(
                meta.query_advice(ctrl_type, Rotation::cur()),
            );
            let old_nonce = meta.query_advice(old_state.input, Rotation::cur());
            let new_nonce = meta.query_advice(new_state.input, Rotation::cur());

            vec![
                s_enable
                    * row0
                    * (new_nonce.clone() - old_nonce.clone())
                    * (new_nonce - old_nonce - Expression::Constant(Fp::one())),
            ]
        });

        //additional row
        meta.create_gate("padding row", |meta| {
            let s_enable = meta.query_selector(sel) * meta.query_advice(s_enable, Rotation::cur());
            let row4 = AccountChip::<'_, Fp>::lagrange_polynomial_for_row::<4>(
                meta.query_advice(ctrl_type, Rotation::cur()),
            );
            let old_root = meta.query_advice(exported_old, Rotation::cur());
            let new_root = meta.query_advice(exported_new, Rotation::cur());

            vec![s_enable * row4 * (new_root - old_root)]
        });

        Self {
            s_enable,
            ctrl_type,
            old_state,
            new_state,
        }
    }

    pub fn transition_rules() -> impl Iterator<Item = (u32, u32, u32)> + Clone {
        TRANSMAP
            .iter()
            .map(|(a, b)| (*a, *b, CtrlTransitionKind::Account as u32))
    }

    /// assign data and enable flag for account circuit
    pub fn assign<'d, Fp: FieldExt>(
        &self,
        region: &mut Region<'_, Fp>,
        offset: usize,
        data: (&'d Account<Fp>, &'d Account<Fp>),
        apply_last_row: Option<bool>,
    ) -> Result<usize, Error> {
        let old_acc_chip = AccountChip::<Fp> {
            offset,
            config: self.old_state.clone(),
            data: data.0,
        };
        let new_acc_chip = AccountChip::<Fp> {
            offset,
            config: self.new_state.clone(),
            data: data.1,
        };

        let apply_last_row = if let Some(apply) = apply_last_row {
            if apply {
                assert_eq!(data.0.state_root, data.1.state_root);
            }

            apply
        } else {
            data.0.state_root == data.1.state_root
        };

        let end_offset = offset + CIRCUIT_ROW - if apply_last_row { 0 } else { 1 };

        old_acc_chip.assign(region)?;
        new_acc_chip.assign(region)?;

        for (index, offset) in (offset..end_offset).enumerate() {
            region.assign_advice(
                || "enable account circuit",
                self.s_enable,
                offset,
                || Ok(Fp::one()),
            )?;
            region.assign_advice(
                || "account circuit rows",
                self.ctrl_type,
                offset,
                || Ok(Fp::from(index as u64)),
            )?;
            if index == LAST_ROW {
                region.assign_advice(
                    || "padding last row",
                    self.old_state.input,
                    offset,
                    || Ok(Fp::zero()),
                )?;
                region.assign_advice(
                    || "padding last row",
                    self.new_state.input,
                    offset,
                    || Ok(Fp::zero()),
                )?;
            }
        }

        Ok(end_offset)
    }
}

#[derive(Clone, Debug)]
struct AccountChipConfig {
    input: Column<Advice>,
    intermediate: Column<Advice>,
    exported: Column<Advice>,
}

/// chip for verify mutiple merkle path in MPT
/// it do not need any auxiliary cols
struct AccountChip<'d, F> {
    offset: usize,
    config: AccountChipConfig,
    data: &'d Account<F>,
}

impl<Fp: FieldExt> Chip<Fp> for AccountChip<'_, Fp> {
    type Config = AccountChipConfig;
    type Loaded = Account<Fp>;

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        self.data
    }
}

impl<'d, Fp: FieldExt> AccountChip<'d, Fp> {
    fn lagrange_polynomial_for_row<const T: usize>(ref_n: Expression<Fp>) -> Expression<Fp> {
        super::lagrange_polynomial::<Fp, T, LAST_ROW>(ref_n)
    }

    fn configure(
        meta: &mut ConstraintSystem<Fp>,
        sel: Selector,
        s_enable: Column<Advice>,
        ctrl_type: Column<Advice>,
        exported: Column<Advice>,
        free_cols: &[Column<Advice>],
        hash_table: mpt::HashTable,
    ) -> <Self as Chip<Fp>>::Config {
        let input = free_cols[0];
        let intermediate = free_cols[1];

        // first hash lookup
        meta.lookup_any("account hash calc1", |meta| {
            // only enable on row 1, 3
            let s_enable = meta.query_advice(s_enable, Rotation::cur());
            let ctrl_type = meta.query_advice(ctrl_type, Rotation::cur());
            let enable_rows = Self::lagrange_polynomial_for_row::<1>(ctrl_type.clone())
                + Self::lagrange_polynomial_for_row::<3>(ctrl_type);
            let enable = enable_rows * s_enable;

            vec![
                (
                    enable.clone() * meta.query_advice(input, Rotation::prev()),
                    meta.query_advice(hash_table.0, Rotation::cur()),
                ),
                (
                    enable.clone() * meta.query_advice(input, Rotation::cur()),
                    meta.query_advice(hash_table.1, Rotation::cur()),
                ),
                (
                    enable * meta.query_advice(intermediate, Rotation::cur()),
                    meta.query_advice(hash_table.2, Rotation::cur()),
                ),
            ]
        });

        // second hash lookup
        meta.lookup_any("account hash calc2", |meta| {
            // only enable on row 1, 3
            let s_enable = meta.query_advice(s_enable, Rotation::cur());
            let ctrl_type = meta.query_advice(ctrl_type, Rotation::cur());
            let enable_rows = Self::lagrange_polynomial_for_row::<1>(ctrl_type.clone())
                + Self::lagrange_polynomial_for_row::<3>(ctrl_type);
            let enable = enable_rows * s_enable;

            vec![
                (
                    enable.clone() * meta.query_advice(intermediate, Rotation::cur()),
                    meta.query_advice(hash_table.0, Rotation::cur()),
                ),
                (
                    enable.clone() * meta.query_advice(exported, Rotation::cur()),
                    meta.query_advice(hash_table.1, Rotation::cur()),
                ),
                (
                    enable * meta.query_advice(exported, Rotation::prev()),
                    meta.query_advice(hash_table.2, Rotation::cur()),
                ),
            ]
        });

        meta.create_gate("account calc", |meta| {
            let s_enable = meta.query_selector(sel) * meta.query_advice(s_enable, Rotation::cur());
            let ctrl_type = meta.query_advice(ctrl_type, Rotation::cur());
            let exported_equal1 = meta.query_advice(exported, Rotation::cur())
                - meta.query_advice(exported, Rotation::prev());
            let exported_equal2 = meta.query_advice(exported, Rotation::cur())
                - meta.query_advice(exported, Rotation::next());

            // equalities in the circuit
            // (notice the value for leafExtendedFinal can be omitted)
            vec![
                s_enable.clone()
                    * Self::lagrange_polynomial_for_row::<2>(ctrl_type.clone())
                    * exported_equal1.clone(), // equality of hash2
                s_enable.clone()
                    * Self::lagrange_polynomial_for_row::<0>(ctrl_type.clone())
                    * exported_equal1, // equality of account trie leaf
                s_enable * Self::lagrange_polynomial_for_row::<3>(ctrl_type) * exported_equal2, // equality of state trie root
            ]
        });

        AccountChipConfig {
            input,
            intermediate,
            exported,
        }
    }

    fn assign(&self, region: &mut Region<'_, Fp>) -> Result<usize, Error> {
        assert_eq!(self.data.hash_traces.len(), 4);
        let config = &self.config;
        // fill the connected circuit
        let offset = self.offset - 1;
        region.assign_advice(
            || "account hash",
            config.exported,
            offset,
            || Ok(self.data.account_hash()),
        )?;

        // row 0
        let offset = offset + 1;
        region.assign_advice(|| "input 0", config.input, offset, || Ok(self.data.nonce))?;
        region.assign_advice(
            || "exported 0",
            config.exported,
            offset,
            || Ok(self.data.account_hash()),
        )?;
        // row 1
        let offset = offset + 1;
        region.assign_advice(|| "input 1", config.input, offset, || Ok(self.data.balance))?;
        region.assign_advice(
            || "intermediate 1",
            config.intermediate,
            offset,
            || Ok(self.data.hash_traces[2].2),
        )?;
        region.assign_advice(
            || "exported 1",
            config.exported,
            offset,
            || Ok(self.data.hash_traces[1].2),
        )?;
        // row 2
        let offset = offset + 1;
        region.assign_advice(
            || "input 2",
            config.input,
            offset,
            || Ok(self.data.codehash.0),
        )?;
        region.assign_advice(
            || "exported 2",
            config.exported,
            offset,
            || Ok(self.data.hash_traces[1].2),
        )?;
        // row 3
        let offset = offset + 1;
        region.assign_advice(
            || "input 3",
            config.input,
            offset,
            || Ok(self.data.codehash.1),
        )?;
        region.assign_advice(
            || "intermediate 3",
            config.intermediate,
            offset,
            || Ok(self.data.hash_traces[0].2),
        )?;
        region.assign_advice(
            || "exported 3",
            config.exported,
            offset,
            || Ok(self.data.state_root),
        )?;
        // row 4: notice this is not belong to account chip in general
        region.assign_advice(
            || "state root",
            config.exported,
            offset + 1,
            || Ok(self.data.state_root),
        )?;

        Ok(offset)
    }
}

#[cfg(test)]
mod test {
    #![allow(unused_imports)]

    use super::*;
    use crate::{serde::Row, test_utils::*};
    use halo2_proofs::{
        circuit::{Cell, Layouter, Region, SimpleFloorPlanner},
        dev::{MockProver, VerifyFailure},
        plonk::{Circuit, Expression},
    };

    #[derive(Clone, Debug)]
    struct AccountTestConfig {
        gadget: AccountGadget,
        sel: Selector,
        free_cols: [Column<Advice>; 10],
        op_tabl: mpt::MPTOpTables,
        hash_tabl: (mpt::HashTable, mpt::HashTable),
    }

    // express for a single path block
    #[derive(Clone, Default)]
    struct AccountTestCircuit {
        data: (Account<Fp>, Account<Fp>),
    }

    impl Circuit<Fp> for AccountTestCircuit {
        type Config = AccountTestConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            let sel = meta.selector();
            let free_cols = [(); 10].map(|_| meta.advice_column());
            let exported_cols = [free_cols[0], free_cols[1], free_cols[2], free_cols[3]];
            let op_tabl = mpt::MPTOpTables::configure_create(meta);
            let hash_tabl = (
                mpt::HashTable::configure_create(meta),
                mpt::HashTable::configure_create(meta),
            );

            let gadget = AccountGadget::configure(
                meta,
                sel,
                exported_cols,
                &free_cols[4..],
                op_tabl.clone(),
                hash_tabl.clone(),
            );

            AccountTestConfig {
                gadget,
                sel,
                free_cols,
                op_tabl,
                hash_tabl,
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            config
                .op_tabl
                .fill_constant(&mut layouter, AccountGadget::transition_rules())?;
            config
                .hash_tabl
                .0
                .fill(&mut layouter, self.data.0.hash_traces.iter())?;
            config
                .hash_tabl
                .1
                .fill(&mut layouter, self.data.1.hash_traces.iter())?;

            layouter.assign_region(
                || "account",
                |mut region| {
                    let till =
                        config
                            .gadget
                            .assign(&mut region, 1, (&self.data.0, &self.data.1), None)?;
                    for offset in 1..till {
                        config.sel.enable(&mut region, offset)?;
                    }
                    for col in config.free_cols {
                        region.assign_advice(|| "flush last row", col, till, || Ok(Fp::zero()))?;
                    }
                    Ok(())
                },
            )
        }
    }

    #[test]
    fn single_account() {
        let acc_data = Account::<Fp> {
            balance: Fp::from(100000u64),
            nonce: Fp::from(42u64),
            codehash: (rand_fp(), rand_fp()),
            state_root: rand_fp(),
            ..Default::default()
        };

        let old_acc_data = Account::<Fp> {
            nonce: Fp::from(41u64),
            ..acc_data.clone()
        };

        let acc_data = acc_data.complete(mock_hash);
        let old_acc_data = old_acc_data.complete(mock_hash);

        let circuit = AccountTestCircuit {
            data: (old_acc_data, acc_data),
        };

        let k = 4;
        #[cfg(feature = "print_layout")]
        print_layout!("layouts/accgadget_layout.png", k, &circuit);

        let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
