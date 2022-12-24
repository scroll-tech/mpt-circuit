

use crate::operation::{KeyValue, AccountOp};
use halo2_proofs::{
    arithmetic::{Field, FieldExt},
    circuit::{Layouter, Value},
    plonk::{
        Advice, Column, ConstraintSystem, Error, Expression, Selector, VirtualCells,
    },
    poly::Rotation,
};

mod range_check;
mod byte32;
mod value_rep;

use byte32::Config as PairRepConfig;
use range_check::{Config as RangeCheckCfg, Chip as RangeCheckChip};
use value_rep::Config as RepCfg;

type RepConfig = RepCfg<32, 8>;
type RangeCheckConfig = RangeCheckCfg<8>;

#[derive(Clone, Debug)]
pub(crate) struct Config {
    sel: Selector,
    proof_sel: [Column<Advice>;7], 

    address: Column<Advice>,
    storage_key: Column<Advice>,
    proof_type: Column<Advice>,
    new_root: Column<Advice>,
    old_root: Column<Advice>,
    new_value: Column<Advice>,
    old_value: Column<Advice>,

    // the rep for current single field values
    key_rep: RepConfig,
    new_val_rep: RepConfig,
    old_val_rep: RepConfig,

    range_check_u8: RangeCheckConfig,

    change_aux: Column<Advice>, //used for marking if an entry include change of state (read or write)

    // turn into pair represent (hi, lo)
    storage_key_2: PairRepConfig,
    new_value_2: PairRepConfig,
    old_value_2: PairRepConfig,
}


/*
  The defination is greped from state-circuit
 */

 #[derive(Clone, Copy)]
pub(crate) enum MPTProofType {
    NonceChanged = 1,
    BalanceChanged,
    CodeHashExists,
    AccountDoesNotExist,
    AccountDestructed,
    StorageChanged,
    StorageDoesNotExist
}

#[derive(Clone, Debug, Default)]
pub(crate) struct MPTEntry<F: Field> {
    base: [F; 7],
    storage_key: KeyValue<F>,
    new_value: KeyValue<F>,
    old_value: KeyValue<F>,
}

impl<F: FieldExt> MPTEntry<F> {

    // detect proof type from op data itself, just mocking,
    // not always correct
    pub fn mock_from_op(
        op: &AccountOp<F>,
        randomness: F,
    ) -> Self {

        if op.state_trie.is_some() {
            return if op.store_after.is_none() && op.store_before.is_none() {
                Self::from_op(MPTProofType::StorageDoesNotExist, op, randomness)
            } else {
                Self::from_op(MPTProofType::StorageChanged, op, randomness)
            };
        }

        match (&op.account_before, &op.account_after) {
            (Some(before), Some(after)) => {
                if before.balance != after.balance {
                    Self::from_op(MPTProofType::BalanceChanged, op, randomness)
                } else if before.nonce != after.nonce {
                    Self::from_op(MPTProofType::NonceChanged, op, randomness)
                } else {
                    Self::from_op(MPTProofType::CodeHashExists, op, randomness)
                }                
            },
            (None, Some(_)) => Self::from_op(MPTProofType::CodeHashExists, op, randomness),
            (Some(_), None) => Self::from_op(MPTProofType::AccountDestructed, op, randomness),
            (None, None) => Self::from_op(MPTProofType::AccountDoesNotExist, op, randomness),
        }

    }

    pub fn from_op(
        proof_type: MPTProofType,
        op: &AccountOp<F>,
        randomness: F,
    ) -> Self {
        let storage_key = op.store_key.clone().unwrap_or_default();
        let (old_value, new_value) = match proof_type {
            MPTProofType::CodeHashExists => (
                    op.account_before.as_ref()
                        .map(|acc|acc.codehash)
                        .map(KeyValue::create_base)
                        .unwrap_or_default(),
                    op.account_after.as_ref()
                        .map(|acc|acc.codehash)
                        .map(KeyValue::create_base)
                        .unwrap_or_default(),
                ),
                MPTProofType::StorageChanged =>
                (
                    op.store_before.clone().unwrap_or_default(),
                    op.store_after.clone().unwrap_or_default(),
                ),
            _ => (Default::default(), Default::default()),
        };

        let (old_value_f, new_value_f) = match proof_type {
            MPTProofType::NonceChanged => (
                    op.account_before.as_ref().map(|acc|acc.nonce).unwrap_or_default(),
                    op.account_after.as_ref().map(|acc|acc.nonce).unwrap_or_default(),
                ),
            MPTProofType::BalanceChanged => (
                    op.account_before.as_ref().map(|acc|acc.balance).unwrap_or_default(),
                    op.account_after.as_ref().map(|acc|acc.balance).unwrap_or_default(),
                ),
            MPTProofType::StorageChanged | MPTProofType::CodeHashExists =>
                (
                    old_value.u8_rlc(randomness),
                    new_value.u8_rlc(randomness),    
                ),
            _ => (F::zero(), F::zero()),
        };

        let base = [
            F::from(proof_type as u64),
            op.address,
            storage_key.u8_rlc(randomness),
            old_value_f,
            new_value_f,
            op.account_root_before(),
            op.account_root(),
        ];

        Self {
            base,
            storage_key,
            new_value,
            old_value,
        }
    }
}


#[derive(Clone, Debug)]
pub(crate) struct MPTTable<F: Field> {
    config: Config,
    entries: Vec<MPTEntry<F>>,
}

impl<F: FieldExt> MPTTable<F> {

    pub fn construct(config: Config) -> Self {
        Self {
            config,
            entries: Default::default(),
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        randomness: Expression<F>,
    ) -> Config {
        let sel = meta.selector();
        let address = meta.advice_column();
        let storage_key = meta.advice_column();
        let new_value = meta.advice_column();
        let old_value = meta.advice_column();
        let proof_type = meta.advice_column();
        let new_root = meta.advice_column();
        let old_root = meta.advice_column();

        let proof_sel = [0;7].map(|_|meta.advice_column());
        let change_aux = meta.advice_column();

        let range_check_u8 = RangeCheckChip::<F, 8>::configure(meta);

        let key_rep = RepConfig::configure(meta, &range_check_u8);
        let new_val_rep = RepConfig::configure(meta, &range_check_u8);
        let old_val_rep = RepConfig::configure(meta, &range_check_u8);

        meta.create_gate("bind reps", |meta| {
            let sel = meta.query_selector(sel);
            let enable_codehash = meta.query_advice(proof_sel[2], Rotation::cur());
            let key_val = meta.query_advice(storage_key, Rotation::cur());
            let new_val = enable_codehash.clone() * meta.query_advice(new_value, Rotation::cur());
            let old_val = enable_codehash * meta.query_advice(old_value, Rotation::cur());

            vec![
                sel.clone() * key_rep.bind_rlc_value(meta, key_val, randomness.clone(), None),
                sel.clone() * new_val_rep.bind_rlc_value(meta, new_val, randomness.clone(), None),
                sel * old_val_rep.bind_rlc_value(meta, old_val, randomness, None),
            ]
            
        });

        let storage_key_2 = PairRepConfig::configure(meta, sel, &key_rep.limbs);
        let new_value_2 = PairRepConfig::configure(meta, sel, &new_val_rep.limbs);
        let old_value_2 = PairRepConfig::configure(meta, sel, &new_val_rep.limbs);

        proof_sel.as_slice().iter().copied().enumerate().for_each(|(index, col)|{
            meta.create_gate("proof sel array", |meta| {
                let sel = meta.query_selector(sel);
                let col = meta.query_advice(col, Rotation::cur());
                let proof_type = meta.query_advice(proof_type, Rotation::cur());
    
                // each col is boolean
                // when enabled, it must equal to proof_type
                vec![
                    sel.clone() * col.clone() * (Expression::Constant(F::one()) - col.clone()),
                    sel * col * (Expression::Constant(F::from(index as u64 + 1)) - proof_type),
                ]
            });          
        });

        meta.create_gate("enabled sel is unique", |meta| {
            let sel = meta.query_selector(sel);
            let total_enalbed = proof_sel.as_slice().iter().copied()
                .map(|col|meta.query_advice(col, Rotation::cur()))
                .reduce(|acc, col_exp|acc + col_exp).expect("not null");

            vec![
                sel * total_enalbed.clone() * (Expression::Constant(F::one()) - total_enalbed),
            ]
        });

        Config {
            sel,
            proof_sel,
            address, storage_key, new_value, old_value, proof_type, new_root, old_root,
            change_aux,
            range_check_u8,
            key_rep, new_val_rep, old_val_rep,
            storage_key_2, new_value_2, old_value_2,
        }

    }

    // helpers for build lookups to from 7 values in mpt table entry: the root pair and address index
    // are fixed and the other 3 lookup pair (value and key) need to be specified
    fn build_mpt_table_entry_lookup<'d, const T: usize>(
        meta: &mut VirtualCells<'d, F>,
        control_pair: (u64, u64),
        gadget_id: Column<Advice>,
        ctrl_id: Column<Advice>,        
    ) -> Vec<(Expression<F>, Expression<F>)> {

        vec![
            (Expression::Constant(F::from(control_pair.0)),meta.query_advice(gadget_id, Rotation::cur())),
            (Expression::Constant(F::from(control_pair.1)),meta.query_advice(ctrl_id, Rotation::cur())),
            
        ]
    }

    pub fn bind_mpt_circuit(
        &self,
        meta: &mut ConstraintSystem<F>,
        gadget_id: Column<Advice>,
        ctrl_id: Column<Advice>,
        address_index: Column<Advice>,
        root_index: [Column<Advice>; 2],
        old_value: [Column<Advice>; 2],
        new_value: [Column<Advice>; 2],
        key: [Column<Advice>; 2],
        proof_type: Column<Advice>,
    ) {
        let config = &self.config;

        let build_entry_lookup_common = |
            meta: &mut VirtualCells<'_, F>,
            control_pair: (u64, u64),
        |{
            [
                // positions
                (Expression::Constant(F::from(control_pair.0)),meta.query_advice(gadget_id, Rotation::cur())),
                (Expression::Constant(F::from(control_pair.1)),meta.query_advice(ctrl_id, Rotation::cur())),
                // indexs
                (meta.query_advice(config.address, Rotation::cur()), meta.query_advice(address_index, Rotation::cur())),
                (meta.query_advice(config.old_root, Rotation::cur()), meta.query_advice(root_index[0], Rotation::cur())),
                (meta.query_advice(config.new_root, Rotation::cur()), meta.query_advice(root_index[1], Rotation::cur())),
            ]
        };

        let build_entry_lookup_value = |
            meta: &mut VirtualCells<'_, F>,
        |{
            [
                // values
                (meta.query_advice(config.old_value, Rotation::cur()), meta.query_advice(old_value[0], Rotation::cur())),
                (meta.query_advice(config.new_value, Rotation::cur()), meta.query_advice(new_value[0], Rotation::cur())),
            ]
        };

        let build_entry_lookup_rep_value = |
            meta: &mut VirtualCells<'_, F>,
        |{
            [
                // values rep
                (meta.query_advice(config.old_value_2.rep_hi, Rotation::cur()), meta.query_advice(old_value[0], Rotation::cur())),
                (meta.query_advice(config.old_value_2.rep_lo, Rotation::cur()), meta.query_advice(old_value[1], Rotation::cur())),
                (meta.query_advice(config.new_value_2.rep_hi, Rotation::cur()), meta.query_advice(new_value[0], Rotation::cur())),
                (meta.query_advice(config.new_value_2.rep_lo, Rotation::cur()), meta.query_advice(new_value[1], Rotation::cur())),
            ]
        };

        let build_entry_lookup_account_key = |
            meta: &mut VirtualCells<'_, F>,
        |{
            [
                (Expression::Constant(F::one()), meta.query_advice(proof_type, Rotation::cur())),
            ]
        };

        let build_entry_lookup_storage_key = |
            meta: &mut VirtualCells<'_, F>,
        |{
            [
                (meta.query_advice(config.storage_key_2.rep_hi, Rotation::cur()), meta.query_advice(key[0], Rotation::cur())),
                (meta.query_advice(config.storage_key_2.rep_lo, Rotation::cur()), meta.query_advice(key[1], Rotation::cur())),
            ]
        };

        let build_entry_lookup_not_exist = |
            meta: &mut VirtualCells<'_, F>,
        |{
            [
                // it lookup the mpt gadget above target gadget (only the hash type of old trie is looked up, 
                // it is mpt_table's responsibiliy to ensure old_root == new_root here)                
                (Expression::Constant(F::from(super::HashType::Empty as u64)), meta.query_advice(ctrl_id, Rotation::prev())),
            ]
        };


        // all lookup into account fields raised for gadget id = OP_ACCOUNT (3)
        meta.lookup_any("mpt nonce entry lookup", |meta| {
            let s_enable = meta.query_advice(config.proof_sel[0], Rotation::cur());

            build_entry_lookup_common(meta, (3, 0)).into_iter()
            .chain(build_entry_lookup_value(meta))
            .chain(build_entry_lookup_account_key(meta))
            .map(|(fst, snd)|(fst * s_enable.clone(), snd))
            .collect()
        });

        meta.lookup_any("mpt balance entry lookup", |meta| {
            let s_enable = meta.query_advice(config.proof_sel[1], Rotation::cur());

            build_entry_lookup_common(meta, (3, 1)).into_iter()
            .chain(build_entry_lookup_value(meta))
            .chain(build_entry_lookup_account_key(meta))
            .map(|(fst, snd)|(fst * s_enable.clone(), snd))
            .collect()
        });

        meta.lookup_any("mpt codehash entry lookup", |meta| {
            let s_enable = meta.query_advice(config.proof_sel[2], Rotation::cur());

            build_entry_lookup_common(meta, (3, 2)).into_iter()
            .chain(build_entry_lookup_rep_value(meta))
            .chain(build_entry_lookup_account_key(meta))
            .map(|(fst, snd)|(fst * s_enable.clone(), snd))
            .collect()
        });        

        meta.lookup_any("mpt account not exist entry lookup", |meta| {
            let s_enable = meta.query_advice(config.proof_sel[3], Rotation::cur());

            build_entry_lookup_common(meta, (3, 0)).into_iter()
            .chain(build_entry_lookup_not_exist(meta))
            .map(|(fst, snd)|(fst * s_enable.clone(), snd))
            .collect()
        }); 

        meta.lookup_any("mpt account destroy entry lookup", |meta| {
            let s_enable = meta.query_advice(config.proof_sel[4], Rotation::cur());

            // TODO: not handle AccountDestructed yet (this entry has no lookup: i.e. no verification)
            build_entry_lookup_common(meta, (3, 2)).into_iter()
            .map(|(fst, snd)|(fst * s_enable.clone(), snd))
            .collect()
        });

        // all lookup into storage raised for gadget id = OP_STORAGE (4)
        meta.lookup_any("mpt storage entry lookup", |meta| {
            let s_enable = meta.query_advice(config.proof_sel[5], Rotation::cur());

            build_entry_lookup_common(meta, (4, 0)).into_iter()
            .chain(build_entry_lookup_rep_value(meta))
            .chain(build_entry_lookup_storage_key(meta))
            .map(|(fst, snd)|(fst * s_enable.clone(), snd))
            .collect()
        });

        meta.lookup_any("mpt storage not exist entry lookup", |meta| {
            let s_enable = meta.query_advice(config.proof_sel[6], Rotation::cur());

            build_entry_lookup_common(meta, (4, 0)).into_iter()
            .chain(build_entry_lookup_storage_key(meta))
            .chain(build_entry_lookup_not_exist(meta))
            .map(|(fst, snd)|(fst * s_enable.clone(), snd))
            .collect()
        });

    }

    pub fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {

        let config = &self.config;
        RangeCheckChip::construct(config.range_check_u8.clone()).load(layouter)?;

        layouter.assign_region(|| "mpt table", |mut region|{

            for (offset, entry) in self.entries.iter().enumerate() {

                config.sel.enable(&mut region, offset)?;
                for (index, col) in config.proof_sel.as_slice().iter().copied().enumerate() {
                    region.assign_advice(
                        || format!("assign for proof type enabler {}", offset),
                        col,
                        offset,
                        || Value::known(if F::from(index as u64 + 1) == entry.base[0] {F::one()} else {F::zero()}),
                    )?;                    
                }

                for (val, col) in entry.base.as_slice().iter().zip([
                    config.proof_type,
                    config.address,
                    config.storage_key,
                    config.old_value,
                    config.new_value,                    
                    config.old_root,
                    config.new_root,
                ].as_slice()){

                    region.assign_advice(
                        || format!("assign for mpt table offset {}", offset),
                        *col,
                        offset,
                        || Value::known(*val),
                    )?;                    
                }

                config.storage_key_2.assign(&mut region, offset, &(entry.storage_key.limb_0(), entry.storage_key.limb_1()))?;
                config.new_value_2.assign(&mut region, offset, &(entry.new_value.limb_0(), entry.new_value.limb_1()))?;
                config.old_value_2.assign(&mut region, offset, &(entry.old_value.limb_0(), entry.old_value.limb_1()))?;

                config.key_rep.assign(&mut region, offset, 
                    RepCfg::<16, 8>::le_value_to_limbs(entry.storage_key.limb_0()).as_slice().iter()
                    .chain(RepCfg::<16, 8>::le_value_to_limbs(entry.storage_key.limb_1()).as_slice().iter())
                )?;

                config.new_val_rep.assign(&mut region, offset, 
                    RepCfg::<16, 8>::le_value_to_limbs(entry.new_value.limb_0()).as_slice().iter()
                    .chain(RepCfg::<16, 8>::le_value_to_limbs(entry.new_value.limb_1()).as_slice().iter())
                )?;

                config.old_val_rep.assign(&mut region, offset, 
                    RepCfg::<16, 8>::le_value_to_limbs(entry.old_value.limb_0()).as_slice().iter()
                    .chain(RepCfg::<16, 8>::le_value_to_limbs(entry.old_value.limb_1()).as_slice().iter())
                )?;

            }

            Ok(())
        })?;

        Ok(())
    }

}