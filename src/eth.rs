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
use crate::operation::{Account, AccountOp, KeyValue};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Chip, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};
use lazy_static::lazy_static;

pub const CIRCUIT_ROW: usize = 6;
const N_CONTROL_TYPES: usize = 6;
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
    s_ctrl_type: [Column<Advice>; 4],

    state_change_key: Column<Advice>,
    state_change_aux: [Column<Advice>; 2],
}

impl AccountGadget {
    pub fn min_free_cols() -> usize {
        6
    }

    pub fn min_ctrl_types() -> usize {
        4
    }

    /// create gadget from assigned cols, we need:
    /// + circuit selector * 1
    /// + exported col * 8 (MUST by following sequence: layout_flag, s_enable, old_val, new_val, key_val and 3 ext field for old/new/key_val)
    /// + free col * 4
    pub fn configure<Fp: FieldExt>(
        meta: &mut ConstraintSystem<Fp>,
        sel: Selector,
        exported: &[Column<Advice>],
        s_ctrl_type: &[Column<Advice>],
        free: &[Column<Advice>],
        address_index: Option<Column<Advice>>,
        tables: mpt::MPTOpTables,
        hash_tbl: mpt::HashTable,
    ) -> Self {
        assert!(free.len() >= 4, "require at least 4 free cols");
        let s_enable = exported[1];
        let ctrl_type = exported[0];
        let data_old = exported[2];
        let data_new = exported[3];
        let data_key = exported[4]; //the mpt gadget above it use the col as 'data key'
        let state_change_key = data_key; //while we use it as 'state_change_key'
        let data_old_ext = exported[5];
        let data_new_ext = exported[6];
        let s_ctrl_type = s_ctrl_type[0..4].try_into().expect("same size");

        let old_state = AccountChip::configure(
            meta,
            sel,
            s_enable,
            s_ctrl_type,
            data_old,
            data_old_ext,
            [free[0], free[1]],
            hash_tbl.clone(),
        );
        let new_state = AccountChip::configure(
            meta,
            sel,
            s_enable,
            s_ctrl_type,
            data_new,
            data_new_ext,
            [free[2], free[3]],
            hash_tbl.clone(),
        );

        let state_change_aux: [Column<Advice>; 2] = free[4..6].try_into().expect("size specified");

        //transition
        meta.lookup("account row trans", |meta| {
            let s_enable = meta.query_advice(s_enable, Rotation::cur())
                * (Expression::Constant(Fp::one())
                    - meta.query_advice(s_ctrl_type[0], Rotation::cur()));

            tables.build_lookup(
                s_enable,
                meta.query_advice(ctrl_type, Rotation::prev()),
                meta.query_advice(ctrl_type, Rotation::cur()),
                CtrlTransitionKind::Account as u64,
            )
        });

        if let Some(address_index) = address_index {
            meta.create_gate("address constraint", |meta| {
                let s_enable =
                    meta.query_selector(sel) * meta.query_advice(s_enable, Rotation::cur());
                let row0 = meta.query_advice(s_ctrl_type[0], Rotation::cur());
                let address_limb_0 = meta.query_advice(old_state.intermediate_1, Rotation::cur());
                let address_limb_1 = meta.query_advice(new_state.intermediate_1, Rotation::cur());

                vec![
                    s_enable
                        * row0
                        * (address_limb_0 * Expression::Constant(Fp::from(0x100000000u64))
                            + address_limb_1
                                * Expression::Constant(
                                    Fp::from_u128(0x1000000000000000000000000u128)
                                        .invert()
                                        .unwrap(),
                                )
                            - meta.query_advice(address_index, Rotation::cur())),
                ]
            });

            meta.lookup_any("address hash", |meta| {
                let s_enable = meta.query_advice(s_enable, Rotation::cur())
                    * meta.query_advice(s_ctrl_type[0], Rotation::cur());

                let address_limb_0 = meta.query_advice(old_state.intermediate_1, Rotation::cur());
                let address_limb_1 = meta.query_advice(new_state.intermediate_1, Rotation::cur());
                let addr_hash = meta.query_advice(data_key, Rotation::prev());

                hash_tbl.build_lookup(meta, s_enable, address_limb_0, address_limb_1, addr_hash)
            });
        }

        // this gate constraint each gadget handle at most one change in account data
        /* meta.create_gate("single update for account data", |meta| {
            let enable = meta.query_selector(sel) * meta.query_advice(s_enable, Rotation::cur());
            let data_diff = meta.query_advice(data_old, Rotation::cur())
                - meta.query_advice(data_new, Rotation::cur());
            let data_ext_diff = meta.query_advice(data_old_ext, Rotation::cur())
                - meta.query_advice(data_new_ext, Rotation::cur());

            let is_diff_boolean =
                data_diff.clone() * meta.query_advice(state_change_aux[0], Rotation::cur());
            let is_diff_ext_boolean =
                data_ext_diff.clone() * meta.query_advice(state_change_aux[1], Rotation::cur());

            let one = Expression::Constant(Fp::one());
            // switch A || B to ! (!A ^ !B)
            let has_diff = one.clone()
                - (one.clone() - is_diff_boolean.clone())
                    * (one.clone() - is_diff_ext_boolean.clone());
            let diff_acc = has_diff
                + meta.query_advice(s_enable, Rotation::prev())
                    * meta.query_advice(state_change_key, Rotation::prev());
            let state_change_key = meta.query_advice(state_change_key, Rotation::cur());

            vec![
                enable.clone() * data_diff * (one.clone() - is_diff_boolean),
                enable.clone() * data_ext_diff * (one.clone() - is_diff_ext_boolean),
                enable.clone() * (state_change_key.clone() - diff_acc),
                enable * state_change_key.clone() * (one - state_change_key),
            ]
        });*/

        //additional row
        // TODO: nonce now can increase more than 1, we should constraint it with lookup table (better than a compare circuit)
        // BUT: this constraint should also exist in state circui so do we really need it?
        /*        meta.create_gate("nonce", |meta| {
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
        });*/

        //additional row
        meta.create_gate("padding row", |meta| {
            let s_enable = meta.query_selector(sel) * meta.query_advice(s_enable, Rotation::cur());
            let row3 = meta.query_advice(s_ctrl_type[3], Rotation::cur());
            let old_root = meta.query_advice(data_old, Rotation::cur());
            let new_root = meta.query_advice(data_new, Rotation::cur());

            vec![s_enable * row3 * (new_root - old_root)]
        });

        Self {
            s_enable,
            ctrl_type,
            s_ctrl_type,
            old_state,
            new_state,
            state_change_key,
            state_change_aux,
        }
    }

    pub fn transition_rules() -> impl Iterator<Item = ([u32; 3], u32)> + Clone {
        TRANSMAP
            .iter()
            .copied()
            .map(|(a, b)| ([a, b, 0], CtrlTransitionKind::Account as u32))
    }

    /// assign data and enable flag for account circuit
    pub fn assign<'d, Fp: FieldExt>(
        &self,
        region: &mut Region<'_, Fp>,
        offset: usize,
        data: (&'d Account<Fp>, &'d Account<Fp>),
        address: KeyValue<Fp>,
        apply_last_row: Option<bool>,
    ) -> Result<usize, Error> {
        let old_acc_chip = AccountChip::<Fp> {
            offset,
            config: &self.old_state,
            data: data.0,
        };
        let new_acc_chip = AccountChip::<Fp> {
            offset,
            config: &self.new_state,
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

        // overwrite the datalimb in first row for address
        for (col, val) in [
            (old_acc_chip.config.intermediate_1, address.limb_0()),
            (new_acc_chip.config.intermediate_1, address.limb_1()),
        ] {
            region.assign_advice(|| "address assignment", col, offset, || Value::known(val))?;
        }

        let mut has_data_delta = false;
        for (index, offset) in (offset..end_offset).enumerate() {
            region.assign_advice(
                || "enable account circuit",
                self.s_enable,
                offset,
                || Value::known(Fp::one()),
            )?;
            region.assign_advice(
                || "account circuit rows",
                self.ctrl_type,
                offset,
                || Value::known(Fp::from(index as u64)),
            )?;
            region.assign_advice(
                || "enable s_ctrl",
                self.s_ctrl_type[index],
                offset,
                || Value::known(Fp::one()),
            )?;
            if index == LAST_ROW {
                region.assign_advice(
                    || "padding last row",
                    self.old_state.intermediate_2,
                    offset,
                    || Value::known(Fp::zero()),
                )?;

                region.assign_advice(
                    || "padding last row",
                    self.new_state.intermediate_2,
                    offset,
                    || Value::known(Fp::zero()),
                )?;
            }
            let data_delta = match index {
                0 => [data.0.nonce - data.1.nonce, Fp::zero()],
                1 => [data.0.balance - data.1.balance, Fp::zero()],
                2 => [
                    data.0.codehash.0 - data.1.codehash.0,
                    data.0.codehash.1 - data.1.codehash.1,
                ],
                3 => [data.0.state_root - data.1.state_root, Fp::zero()],
                _ => [Fp::zero(), Fp::zero()],
            };

            if !has_data_delta {
                has_data_delta =
                    !(bool::from(data_delta[0].is_zero()) && bool::from(data_delta[1].is_zero()));
            }

            for (col, val) in self.state_change_aux.iter().zip(data_delta) {
                region.assign_advice(
                    || "data delta",
                    *col,
                    offset,
                    || {
                        Value::known(if bool::from(val.is_zero()) {
                            Fp::zero()
                        } else {
                            val.invert().unwrap()
                        })
                    },
                )?;
            }

            region.assign_advice(
                || "is data delta",
                self.state_change_key,
                offset,
                || {
                    Value::known(if has_data_delta {
                        Fp::one()
                    } else {
                        Fp::zero()
                    })
                },
            )?;
        }

        Ok(end_offset)
    }
}

#[derive(Clone, Debug)]
struct AccountChipConfig {
    intermediate_1: Column<Advice>,
    intermediate_2: Column<Advice>,
    acc_data_fields: Column<Advice>,
    acc_data_fields_ext: Column<Advice>, // for accommodate codehash's low field
}

/// chip for verify account data's hash in zkktrie
struct AccountChip<'d, F> {
    offset: usize,
    config: &'d AccountChipConfig,
    data: &'d Account<F>,
}

impl<Fp: FieldExt> Chip<Fp> for AccountChip<'_, Fp> {
    type Config = AccountChipConfig;
    type Loaded = Account<Fp>;

    fn config(&self) -> &Self::Config {
        self.config
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
        _sel: Selector,
        s_enable: Column<Advice>,
        s_ctrl_type: [Column<Advice>; 4],
        acc_data_fields: Column<Advice>,
        acc_data_fields_ext: Column<Advice>,
        free_cols: [Column<Advice>; 2],
        hash_table: mpt::HashTable,
    ) -> <Self as Chip<Fp>>::Config {
        let [intermediate_1, intermediate_2] = free_cols;

        // first hash lookup (Poseidon(Codehash_first, Codehash_Second) = hash1)
        meta.lookup_any("account hash1 calc", |meta| {
            // only enable on row 2
            let s_enable = meta.query_advice(s_enable, Rotation::cur());
            let enable_rows = meta.query_advice(s_ctrl_type[2], Rotation::cur());
            let enable = enable_rows * s_enable;
            let fst = meta.query_advice(acc_data_fields, Rotation::cur());
            let snd = meta.query_advice(acc_data_fields_ext, Rotation::cur());
            let hash = meta.query_advice(intermediate_1, Rotation::cur());

            hash_table.build_lookup(meta, enable, fst, snd, hash)
        });

        // second hash lookup (Poseidon(hash1, Root) = hash2, Poseidon(hash3, hash2) = hash_final)
        // TODO: re-enable once there are new traces.
        // meta.lookup_any("account hash2 and hash_final calc", |meta| {
        //     // only enable on row 1 and 2
        //     let s_enable = meta.query_advice(s_enable, Rotation::cur());
        //     let enable_rows = meta.query_advice(s_ctrl_type[1], Rotation::cur())
        //         + meta.query_advice(s_ctrl_type[2], Rotation::cur());
        //     let enable = enable_rows * s_enable;
        //     let fst = meta.query_advice(intermediate_1, Rotation::cur());
        //     let snd = meta.query_advice(intermediate_2, Rotation::cur());
        //     let hash = meta.query_advice(intermediate_2, Rotation::prev());

        //     hash_table.build_lookup(meta, enable, fst, snd, hash)
        // });

        // // third hash lookup (Poseidon(nonce, balance) = hash3)
        // meta.lookup_any("account hash3 calc", |meta| {
        //     // only enable on row 1
        //     let s_enable = meta.query_advice(s_enable, Rotation::cur());
        //     let enable_rows = meta.query_advice(s_ctrl_type[1], Rotation::cur());
        //     let enable = enable_rows * s_enable;

        //     let fst = meta.query_advice(acc_data_fields, Rotation::prev());
        //     let snd = meta.query_advice(acc_data_fields, Rotation::cur());
        //     let hash = meta.query_advice(intermediate_1, Rotation::cur());

        //     hash_table.build_lookup(meta, enable, fst, snd, hash)
        // });

        // // equality constraint: hash_final and Root
        // meta.create_gate("account calc equalities", |meta| {
        //     let s_enable = meta.query_selector(sel) * meta.query_advice(s_enable, Rotation::cur());
        //     let exported_equal1 = meta.query_advice(intermediate_2, Rotation::cur())
        //         - meta.query_advice(acc_data_fields, Rotation::prev());
        //     let exported_equal2 = meta.query_advice(intermediate_2, Rotation::cur())
        //         - meta.query_advice(acc_data_fields, Rotation::next());
        //
        //     // equalities in the circuit
        //     vec![
        //         s_enable.clone()
        //             * meta.query_advice(s_ctrl_type[0], Rotation::cur())
        //             * exported_equal1, // equality of hash_final
        //         s_enable * meta.query_advice(s_ctrl_type[2], Rotation::cur()) * exported_equal2, // equality of state trie root
        //     ]
        // });

        AccountChipConfig {
            acc_data_fields,
            acc_data_fields_ext,
            intermediate_1,
            intermediate_2,
        }
    }

    fn assign(&self, region: &mut Region<'_, Fp>) -> Result<usize, Error> {
        let config = self.config();
        let data = self.loaded();
        // fill the connected circuit
        let offset = self.offset - 1;
        region.assign_advice(
            || "account hash final",
            config.acc_data_fields,
            offset,
            || Value::known(data.account_hash()),
        )?;

        // fill the main block of chip
        for (col, vals, desc) in [
            (
                config.acc_data_fields,
                [data.nonce, data.balance, data.codehash.0],
                "data field",
            ),
            (
                config.acc_data_fields_ext,
                [Fp::zero(), Fp::zero(), data.codehash.1],
                "data field ext",
            ),
            (
                config.intermediate_2,
                [data.account_hash(), data.hash_traces(1), data.state_root],
                "intermedia 2",
            ),
            (
                config.intermediate_1,
                [Fp::zero(), data.hash_traces(2), data.hash_traces(0)],
                "intermedia 1",
            ),
        ] {
            for (i, val) in vals.iter().enumerate() {
                region.assign_advice(
                    || format!("{} row {} (offset {})", desc, i, self.offset),
                    col,
                    self.offset + i,
                    || Value::known(*val),
                )?;
            }
        }
        // row 4: notice this is not belong to account chip in general
        region.assign_advice(
            || "state root",
            config.acc_data_fields,
            self.offset + LAST_ROW,
            || Value::known(self.data.state_root),
        )?;

        region.assign_advice(
            || "state root padding",
            config.acc_data_fields_ext,
            self.offset + LAST_ROW,
            || Value::known(Fp::zero()),
        )?;

        Ok(self.offset + LAST_ROW)
    }
}

#[derive(Clone, Debug)]
struct StorageChipConfig {
    v_limbs: [Column<Advice>; 2],
}

/// a single row chip for mapping the storage kv (both with 2 limbs) and lookup for its
/// hash value in the prev row, this chip can be used by both key and value
struct StorageChip<'d, F> {
    offset: usize,
    config: &'d StorageChipConfig,
    value: Option<KeyValue<F>>,
}

impl<'d, Fp: FieldExt> StorageChip<'d, Fp> {
    fn configure(
        meta: &mut ConstraintSystem<Fp>,
        _sel: Selector,
        s_enable: Column<Advice>,
        hash: Column<Advice>,
        v_limbs: [Column<Advice>; 2],
        hash_table: &mpt::HashTable,
    ) -> StorageChipConfig {
        meta.lookup_any("value hash", |meta| {
            let enable = meta.query_advice(s_enable, Rotation::cur());
            let fst = meta.query_advice(v_limbs[0], Rotation::cur());
            let snd = meta.query_advice(v_limbs[1], Rotation::cur());
            let hash = meta.query_advice(hash, Rotation::prev());

            hash_table.build_lookup(meta, enable, fst, snd, hash)
        });

        StorageChipConfig { v_limbs }
    }

    fn assign(&self, region: &mut Region<'_, Fp>) -> Result<usize, Error> {
        let config = &self.config;

        region.assign_advice(
            || "val limb 0",
            config.v_limbs[0],
            self.offset,
            || Value::known(self.value.as_ref().map_or_else(Fp::zero, |v| v.limb_0())),
        )?;

        region.assign_advice(
            || "val limb 1",
            config.v_limbs[1],
            self.offset,
            || Value::known(self.value.as_ref().map_or_else(Fp::zero, |v| v.limb_1())),
        )?;

        Ok(self.offset + 1)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct StorageGadget {
    s_value: StorageChipConfig,
    e_value: StorageChipConfig,
    key: StorageChipConfig,
    s_enable: Column<Advice>,
    ctrl_type: Column<Advice>,
    s_ctrl_type: Column<Advice>,
}

impl StorageGadget {
    pub fn min_free_cols() -> usize {
        6
    }

    pub fn min_ctrl_types() -> usize {
        1
    }

    /// create gadget from assigned cols, we need:
    /// + circuit selector * 1
    /// + exported col * 5 (MUST by following sequence: layout_flag, s_enable, old_val, new_val, key_val)
    /// + free col * 4
    pub fn configure<Fp: FieldExt>(
        meta: &mut ConstraintSystem<Fp>,
        sel: Selector,
        exported: &[Column<Advice>],
        s_ctrl_type: &[Column<Advice>],
        _free: &[Column<Advice>],
        hash_tbl: mpt::HashTable,
    ) -> Self {
        let s_enable = exported[1];
        let ctrl_type = exported[0];
        let s_hash = exported[2];
        let e_hash = exported[3];
        let k_hash = exported[4];
        let s_ctrl_type = s_ctrl_type[0];
        let s_val_limbs = [exported[2], exported[5]];
        let e_val_limbs = [exported[3], exported[6]];
        let k_val_limbs = [exported[4], exported[7]];

        let s_value =
            StorageChip::<_>::configure(meta, sel, s_enable, s_hash, s_val_limbs, &hash_tbl);

        let e_value =
            StorageChip::<_>::configure(meta, sel, s_enable, e_hash, e_val_limbs, &hash_tbl);

        let key = StorageChip::<_>::configure(meta, sel, s_enable, k_hash, k_val_limbs, &hash_tbl);

        Self {
            s_enable,
            ctrl_type,
            s_ctrl_type,
            key,
            s_value,
            e_value,
        }
    }

    /// single row gadget has no transition rule
    pub fn transition_rules() -> impl Iterator<Item = (u32, u32, u32)> + Clone {
        [].into_iter()
    }

    pub fn assign<Fp: FieldExt>(
        &self,
        region: &mut Region<'_, Fp>,
        offset: usize,
        full_op: &AccountOp<Fp>,
    ) -> Result<usize, Error> {
        region.assign_advice(
            || "enable storage leaf circuit",
            self.s_enable,
            offset,
            || Value::known(Fp::one()),
        )?;

        region.assign_advice(
            || "storage leaf circuit row",
            self.ctrl_type,
            offset,
            || Value::known(Fp::zero()),
        )?;

        region.assign_advice(
            || "enable s_ctrl",
            self.s_ctrl_type,
            offset,
            || Value::known(Fp::one()),
        )?;

        for (config, value) in [
            (&self.s_value, &full_op.store_before),
            (&self.e_value, &full_op.store_after),
            (&self.key, &full_op.store_key),
        ] {
            let chip = StorageChip {
                offset,
                config,
                value: value.clone(),
            };

            chip.assign(region)?;
        }

        Ok(offset + 1)
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
        free_cols: [Column<Advice>; 14],
        s_ctrl_cols: [Column<Advice>; 4],
        op_tabl: mpt::MPTOpTables,
        hash_tabl: mpt::HashTable,
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
            let free_cols = [(); 14].map(|_| meta.advice_column());
            let s_ctrl_cols = [(); 4].map(|_| meta.advice_column());
            let exported_cols = [
                free_cols[0],
                free_cols[1],
                free_cols[2],
                free_cols[3],
                free_cols[4],
                free_cols[5],
                free_cols[6],
                free_cols[7],
            ];
            let op_tabl = mpt::MPTOpTables::configure_create(meta);
            let hash_tabl = mpt::HashTable::configure_create(meta);

            let gadget = AccountGadget::configure(
                meta,
                sel,
                exported_cols.as_slice(),
                s_ctrl_cols.as_slice(),
                &free_cols[8..],
                None,
                op_tabl.clone(),
                hash_tabl.clone(),
            );

            AccountTestConfig {
                gadget,
                sel,
                free_cols,
                s_ctrl_cols,
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
            config.hash_tabl.dev_fill(
                &mut layouter,
                self.data
                    .0
                    .hash_traces
                    .iter()
                    .chain(self.data.1.hash_traces.iter()),
            )?;

            layouter.assign_region(
                || "account",
                |mut region| {
                    for col in config.free_cols {
                        region.assign_advice(
                            || "flush top row",
                            col,
                            0,
                            || Value::known(Fp::zero()),
                        )?;
                    }

                    for offset in 1..=CIRCUIT_ROW {
                        for col in config.s_ctrl_cols {
                            region.assign_advice(
                                || "flush s_ctrl",
                                col,
                                offset,
                                || Value::known(Fp::zero()),
                            )?;
                        }
                    }

                    let till = config.gadget.assign(
                        &mut region,
                        1,
                        (&self.data.0, &self.data.1),
                        Default::default(),
                        None,
                    )?;
                    for offset in 1..till {
                        config.sel.enable(&mut region, offset)?;
                    }
                    for col in config.free_cols {
                        region.assign_advice(
                            || "flush last row",
                            col,
                            till,
                            || Value::known(Fp::zero()),
                        )?;
                    }
                    Ok(())
                },
            )
        }
    }

    #[test]
    fn gadget_degrees() {
        let mut cs: ConstraintSystem<Fp> = Default::default();
        AccountTestCircuit::configure(&mut cs);

        println!("account gadget degree: {}", cs.degree());
        assert!(cs.degree() <= 9);
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

        let k = 5;
        #[cfg(feature = "print_layout")]
        print_layout!("layouts/accgadget_layout.png", k, &circuit);

        let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
