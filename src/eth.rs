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


use super::{CtrlTransitionKind, HashType};
use super::mpt;
use crate::operation::Account;
use ff::Field;
use halo2::{
    arithmetic::FieldExt,
    circuit::{Chip, Layouter, Region},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector, TableColumn},
    poly::Rotation,
};

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

const CIRCUIT_ROW : usize = 4;
const LAST_ROW : usize = CIRCUIT_ROW - 1;

impl<'d, Fp: FieldExt> AccountChip<'d, Fp> {

    fn lagrange_polynomial_for_row<const T: usize>(ref_n: Expression<Fp>) -> Expression<Fp> {
        super::lagrange_polynomial::<Fp, T, LAST_ROW>(ref_n)
    }    

    fn configure(
        meta: &mut ConstraintSystem<Fp>,
        s_enable: Column<Advice>,
        ctrl_type: Column<Advice>,
        exported: Column<Advice>,
        free_cols: &[Column<Advice>],
        hash_table : &mpt::HashTable,
    ) -> <Self as Chip<Fp>>::Config {

        let input = free_cols[0];
        let intermediate = free_cols[1];

        // first hash lookup
        meta.lookup(|meta| {
            // only enable on row 1, 3
            let s_enable = meta.query_advice(s_enable, Rotation::cur());
            let ctrl_type = meta.query_advice(ctrl_type, Rotation::cur());
            let enable_rows = Self::lagrange_polynomial_for_row::<1>(ctrl_type.clone()) + Self::lagrange_polynomial_for_row::<3>(ctrl_type);
            let enable = enable_rows * s_enable;

            vec![
                (enable.clone() * meta.query_advice(input, Rotation::cur()), hash_table.0),
                (enable.clone() * meta.query_advice(input, Rotation::prev()), hash_table.1),
                (enable * meta.query_advice(intermediate, Rotation::cur()), hash_table.2),
            ]
        });

        // second hash lookup
        meta.lookup(|meta| {
            // only enable on row 1, 3
            let s_enable = meta.query_advice(s_enable, Rotation::cur());
            let ctrl_type = meta.query_advice(ctrl_type, Rotation::cur());
            let enable_rows = Self::lagrange_polynomial_for_row::<1>(ctrl_type.clone()) + Self::lagrange_polynomial_for_row::<3>(ctrl_type);
            let enable = enable_rows * s_enable;

            vec![
                (enable.clone() * meta.query_advice(intermediate, Rotation::cur()), hash_table.0),
                (enable.clone() * meta.query_advice(exported, Rotation::cur()), hash_table.1),
                (enable * meta.query_advice(exported, Rotation::prev()), hash_table.2),
            ]
        });


        meta.create_gate("account calc", |meta| {
            let s_enable = meta.query_advice(s_enable, Rotation::cur());
            let ctrl_type = meta.query_advice(ctrl_type, Rotation::cur());
            let exported_equal1 = meta.query_advice(exported, Rotation::cur()) - meta.query_advice(exported, Rotation::prev());
            let exported_equal2 = meta.query_advice(exported, Rotation::cur()) - meta.query_advice(exported, Rotation::next());

            // equalities in the circuit
            // (notice the value for leafExtendedFinal can be omitted)
            vec![
                s_enable.clone() * Self::lagrange_polynomial_for_row::<2>(ctrl_type.clone()) * exported_equal1.clone(), // equality of hash2
                s_enable.clone() * Self::lagrange_polynomial_for_row::<0>(ctrl_type.clone()) * exported_equal1, // equality of account trie leaf
                s_enable * Self::lagrange_polynomial_for_row::<3>(ctrl_type.clone()) * exported_equal2, // equality of state trie root
            ]
        });

        AccountChipConfig {
            input,
            intermediate,
            exported,
        }
    }

    fn assign(&self, region: &mut Region<'_, Fp>) -> Result<usize, Error> {

        Ok(self.offset + CIRCUIT_ROW)
    }
}