

use super::{CtrlTransitionKind, HashType};
use crate::operation::KeyValue;
use halo2_proofs::{
    arithmetic::{Field, FieldExt},
    circuit::{Layouter, Value},
    plonk::{
        Advice, Column, ConstraintSystem, Error, Expression, Selector,
    },
};

mod range_check;
mod byte32;
mod value_rep;

use byte32::Config as PairRepConfig;
use range_check::{Config as RangeCheckCfg, Chip as RangeCheckChip};
use value_rep::Config as RepCfg;

type RepConfig = RepCfg<32, 8>;
type RangeCheckConfig = RangeCheckCfg<8>;

/*
  The defination is greped from state-circuit
 */

pub(crate) enum MPTProofType {
    NonceChanged = 1,
    BalanceChanged,
    CodeHashExists,
    AccountDestructed,
    AccountDoesNotExist,
    StorageChanged,
}

#[derive(Clone, Debug)]
pub(crate) struct Config {
    sel: Selector,

    address: Column<Advice>,
    storage_key: Column<Advice>,
    proof_type: Column<Advice>,
    new_root: Column<Advice>,
    old_root: Column<Advice>,
    new_value: Column<Advice>,
    old_value: Column<Advice>,

    // the rep for current single field values
    // notice we do not include old value, which is in fact expressed
    // by old_root intrinsically
    key_rep: RepConfig,
    new_val_rep: RepConfig,

    range_check_u8: RangeCheckConfig,      

    change_aux: Column<Advice>, //used for marking if an entry include change of state (read or write)

    // turn into pair represent (hi, lo)
    storage_key_2: PairRepConfig,
    new_value_2: PairRepConfig,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct MPTEntry<F: Field> {
    base: [F; 7],
    storage_key: KeyValue<F>,
    new_value: KeyValue<F>,
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

        let change_aux = meta.advice_column();

        let range_check_u8 = RangeCheckChip::<F, 8>::configure(meta);

        let key_rep = RepConfig::configure_rlc(meta, sel, storage_key, randomness.clone(), &range_check_u8, None);
        let new_val_rep = RepConfig::configure_rlc(meta, sel, new_value, randomness.clone(), &range_check_u8, None);

        let storage_key_2 = PairRepConfig::configure(meta, sel, &key_rep.limbs);
        let new_value_2 = PairRepConfig::configure(meta, sel, &new_val_rep.limbs);

        Config {
            sel,
            address, storage_key, new_value, old_value, proof_type, new_root, old_root,
            change_aux,
            range_check_u8,
            key_rep, new_val_rep,
            storage_key_2, new_value_2,
        }

    }

    pub fn bind_mpt_circuit(
        &self,
        meta: &mut ConstraintSystem<F>,
        circuit_exports: &[Column<Advice>; 8],
    ) {

    }

    pub fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {

        let config = &self.config;
        RangeCheckChip::construct(config.range_check_u8.clone()).load(layouter)?;

        layouter.assign_region(|| "mpt table", |mut region|{

            for (offset, entry) in self.entries.iter().enumerate() {

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

                config.key_rep.assign(&mut region, offset, 
                    RepCfg::<16, 8>::le_value_to_limbs(entry.storage_key.limb_0()).as_slice().iter()
                    .chain(RepCfg::<16, 8>::le_value_to_limbs(entry.storage_key.limb_1()).as_slice().iter())
                )?;

                config.new_val_rep.assign(&mut region, offset, 
                    RepCfg::<16, 8>::le_value_to_limbs(entry.new_value.limb_0()).as_slice().iter()
                    .chain(RepCfg::<16, 8>::le_value_to_limbs(entry.new_value.limb_1()).as_slice().iter())
                )?;

            }

            Ok(())
        })?;

        Ok(())
    }

}