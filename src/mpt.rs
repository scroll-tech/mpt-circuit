//! The constraint system matrix for operations an arity-2 Merkle Patricia Tree
//! see the desination on <https://>
//
//  Base on a purposed layout, we have divided the circuit into several chips,
//  a chip can be deployed at any position (offset of rows) of the circuit and
//  it would help assign some cols needed which it has configured
//
//  Now we have two type of chips:
//
//  + PathChip: verify the data layout inside a block (several rows) to be valid according
//  + OpChip: verify an operation is valid: i.e: the change from old to new hash type is correct, and the new key match with the provided path bits
//
//  A MPTOpGadget is formed by 2 PathChip and one OpChip to validate an opeartion (insert / update) on the MPT tree

//  The lookup table is formed by <left, right, hash> for hash and
//  <state1, state2> for states transitions / changes
//
//  ### The layout of PathChip is like:
//  |-----||------------------|---------|---------|-------|----------------|------------------|----------------|----------------|--------|
//  | row ||     sibling      |  path   |  s_data |  key  |     HashType   |       val        |     HashTable (left, right, hash)        |
//  |-----||------------------|---------|---------|-------|----------------|------------------|----------------|----------------|--------|
//  |  2  ||                  |<padding>|    0    |       |      Start     |      root        |                                          |
//  |  3  ||      elem_1      | cbit_1  |    1    |       |       Mid      |     digest_1     |  digest_1/elem_1 digest_1/elem_1  root   |
//  |  4  ||      elem_2      | cbit_2  |    1    |       |     LeafExt    |     digest_2     |  digest_2/elem_2 digest_2/elem_2 digest_1|
//  |  5  ||      elem_3      | cbit_3  |    1    |       |  LeafExtFinal  |     digest_3     |  digest_3/elem_2 digest_3/elem_2 digest_2|
//  |  6  ||     <padding>    |leaf_res |    1    |Leafkey|      Empty     |      leaf        |        Leafkey leaf digest_3             |
//  |-----||------------------|---------|---------|-------|----------------|------------------|----------------|----------------|--------|
//
//  col sibling and path is considered as "external" (so chip do not response for assigning them)
//  we lookup following hash calculations from hash table:
//  * <val_col, sibling_col, val_col@roation::(-1)]> if HashType is Mid
//  * <Leafkey, val, val_col@roation::(-1)> if HashType is Leaf
//
//  And lookup the transition of hash_type from transition table
//
//  The HashType decide which rows should be involved in lookup, rows with special HashType
//  like LeafExt/LeafExtFinal require additional constraints rather than hashing
//  We have also additional gates for the "extended Leaf" scheme
//
//  ### The layout of OpChip is like:
//  |-----||------------------|------------------|---------|-------|--------|
//  | row ||    OldHashType   |    NewHashType   |  path   |accKey | depth  |
//  |-----||------------------|------------------|---------|-------|--------|
//  |  2  ||       Start      |     Start        |         |       |        |
//  |  3  ||        Mid       |      Mid         | cbit_0  |       |   1    |
//  |  4  ||        Mid       |      Mid         | cbit_1  |       |   2    |
//  |  5  ||      LeafExt     |      Mid         | cbit_2  |       |   4    |
//  |  6  ||   LeafExtFinal   |      Mid         | cbit_3  |       |   8    |
//  |  7  ||       Empty      |      Leaf        | LeafRes |Leafkey|   16   |
//  |-----||------------------|------------------|---------|-------|--------|
//
//  OpChip would:
//  * constraint the matching old <-> New hashType by lookup from operation table ☑
//  * constraint s_data row to be boolean ☑
//  * inducing a depth column for accumulating path ☑
//  * constraint path as bit except when one of the hashtype is leaf ☑
//  * verify the acckey column by accumulating the path bit and LeafPath bits ☑
//
//  while assignation, OpChip response to assign sibling, acckey and path

use super::{CtrlTransitionKind, HashType};
use crate::operation::{MPTPath, SingleOp};
use ff::Field;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Chip, Layouter, Region},
    plonk::{
        Advice, Column, ConstraintSystem, Error, Expression, Selector, TableColumn, VirtualCells,
    },
    poly::Rotation,
};
use lazy_static::lazy_static;

#[derive(Clone, Debug)]
pub(crate) struct MPTOpTables(pub TableColumn, pub TableColumn, pub TableColumn);

lazy_static! {
    static ref OPMAP : Vec<(HashType, HashType)> = {
        vec![
            (HashType::Start, HashType::Start),
            (HashType::Empty, HashType::Leaf),
            (HashType::Leaf, HashType::Empty),
            (HashType::Leaf, HashType::Leaf),
            (HashType::Middle, HashType::Middle),
            (HashType::LeafExt, HashType::Middle),
            (HashType::LeafExtFinal, HashType::Middle),
            (HashType::Middle, HashType::LeafExt),
            (HashType::Middle, HashType::LeafExtFinal),
        ]
    };
    static ref TRANSMAP : Vec<(HashType, HashType)> = {
        vec![
            (HashType::Start, HashType::Leaf),
            (HashType::Start, HashType::Middle),
            (HashType::Start, HashType::Empty),
            (HashType::Start, HashType::LeafExt),
            (HashType::Start, HashType::LeafExtFinal),
            (HashType::Middle, HashType::Middle),
            (HashType::Middle, HashType::Empty), //insert new leaf under a node
            (HashType::Middle, HashType::Leaf),
            (HashType::Middle, HashType::LeafExt),
            (HashType::Middle, HashType::LeafExtFinal),
            (HashType::LeafExt, HashType::LeafExt),
            (HashType::LeafExt, HashType::LeafExtFinal),
//            (HashType::LeafExtFinal, HashType::Leaf),
            (HashType::LeafExtFinal, HashType::Empty),
        ]
    };
}

impl MPTOpTables {
    pub fn configure_create<Fp: Field>(meta: &mut ConstraintSystem<Fp>) -> Self {
        Self(
            meta.lookup_table_column(),
            meta.lookup_table_column(),
            meta.lookup_table_column(),
        )
    }

    pub fn fill_constant<Fp: FieldExt>(
        &self,
        layouter: &mut impl Layouter<Fp>,
        rules: impl Iterator<Item = (u32, u32, u32)> + Clone,
    ) -> Result<(), Error> {
        layouter.assign_table(
            || "trans table",
            |mut table| {
                // default: 0, 0, 0
                table.assign_cell(|| "default", self.0, 0, || Ok(Fp::zero()))?;
                table.assign_cell(|| "default", self.1, 0, || Ok(Fp::zero()))?;
                table.assign_cell(|| "default", self.2, 0, || Ok(Fp::zero()))?;

                for (offset, item) in rules.clone().enumerate() {
                    let offset = offset + 1;
                    table.assign_cell(|| "cur", self.0, offset, || Ok(Fp::from(item.0 as u64)))?;

                    table.assign_cell(|| "next", self.1, offset, || Ok(Fp::from(item.1 as u64)))?;

                    table.assign_cell(|| "mark", self.2, offset, || Ok(Fp::from(item.2 as u64)))?;
                }
                Ok(())
            },
        )
    }
}

// TODO: hash table maybe advice?
#[derive(Clone, Debug)]
pub(crate) struct HashTable(pub Column<Advice>, pub Column<Advice>, pub Column<Advice>);

impl HashTable {
    pub fn configure_create<Fp: Field>(meta: &mut ConstraintSystem<Fp>) -> Self {
        Self(
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        )
    }

    fn configure_assign(cols: &[Column<Advice>]) -> Self {
        Self(cols[0], cols[1], cols[2])
    }

    /// a helper entry to fill hash table, mostly for test purpose
    pub fn fill<'d, Fp: FieldExt>(
        &self,
        layouter: &mut impl Layouter<Fp>,
        hashing_records: impl Iterator<Item = &'d (Fp, Fp, Fp)> + Clone,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "hash table",
            |mut table| {
                // default: 0, 0, 0
                table.assign_advice(|| "default", self.0, 0, || Ok(Fp::zero()))?;
                table.assign_advice(|| "default", self.1, 0, || Ok(Fp::zero()))?;
                table.assign_advice(|| "default", self.2, 0, || Ok(Fp::zero()))?;

                hashing_records
                    .clone()
                    .enumerate()
                    .try_for_each(|(offset, val)| {
                        let (lh, rh, h) = val;
                        let offset = offset + 1;

                        table.assign_advice(|| "left", self.0, offset, || Ok(*lh))?;

                        table.assign_advice(|| "right", self.1, offset, || Ok(*rh))?;

                        table.assign_advice(|| "result", self.2, offset, || Ok(*h))?;

                        Ok(())
                    })
            },
        )?;

        Ok(())
    }
}

#[derive(Clone, Debug)]
struct MPTOpConfig {
    s_row: Selector,
    s_enable: Column<Advice>,
    s_data: Column<Advice>,
    depth: Column<Advice>,
    old_hash_type: Column<Advice>,
    new_hash_type: Column<Advice>,
    sibling: Column<Advice>,
    acc_key: Column<Advice>,
    path: Column<Advice>,
    old_val: Column<Advice>,
    new_val: Column<Advice>,

    old_hash_table: HashTable,
    new_hash_table: HashTable,

    tables: MPTOpTables,
}

#[derive(Clone, Debug)]
pub(crate) struct MPTOpGadget {
    op: OpChipConfig,
    old_path: PathChipConfig,
    new_path: PathChipConfig,
    old_hash_table: HashTable,
    new_hash_table: HashTable,
    tables: MPTOpTables,
    s_enable: Column<Advice>,
}

impl MPTOpGadget {
    pub fn min_free_cols() -> usize {
        6
    }

    /// if the gadget would be used only once, this entry is more easy
    pub fn configure_simple<Fp: FieldExt>(
        meta: &mut ConstraintSystem<Fp>,
        sel: Selector,
        exported: [Column<Advice>; 4],
        free: &[Column<Advice>],
    ) -> Self {
        let tables = MPTOpTables::configure_create(meta);
        let hash_tbls = (
            HashTable::configure_create(meta),
            HashTable::configure_create(meta),
        );

        Self::configure(meta, sel, exported, free, tables, hash_tbls)
    }

    /// create gadget from assigned cols, we need:
    /// + circuit selector * 1
    /// + exported col * 4 (MUST by following sequence: layout_flag, s_enable, old_val, new_val)
    /// + free col * 6
    /// notice the gadget has bi-direction exporting (on top it exporting mpt root and bottom exporting leaf)
    pub fn configure<Fp: FieldExt>(
        meta: &mut ConstraintSystem<Fp>,
        sel: Selector,
        exported: [Column<Advice>; 4],
        free: &[Column<Advice>],
        tables: MPTOpTables,
        hash_tbls: (HashTable, HashTable), //(old, new)
    ) -> Self {
        assert!(free.len() >= 6, "require at least 6 free cols");

        let g_config = MPTOpConfig {
            tables,
            s_row: sel,
            s_data: free[0],
            depth: free[1],
            new_hash_type: free[2],
            sibling: free[3],
            acc_key: free[4],
            path: free[5],
            old_hash_type: exported[0],
            s_enable: exported[1],
            old_val: exported[2],
            new_val: exported[3],

            old_hash_table: hash_tbls.0,
            new_hash_table: hash_tbls.1,
        };

        meta.create_gate("flag boolean", |meta| {
            let s_row = meta.query_selector(g_config.s_row);
            let s_enable = meta.query_advice(g_config.s_enable, Rotation::cur());
            // s_enable ∈ {0, 1}
            vec![s_row * (Expression::Constant(Fp::one()) - s_enable.clone()) * s_enable]
        });

        Self {
            s_enable: g_config.s_enable,
            op: OpChip::<Fp>::configure(meta, &g_config),
            old_path: PathChip::<Fp>::configure(meta, &g_config, true),
            new_path: PathChip::<Fp>::configure(meta, &g_config, false),
            old_hash_table: g_config.old_hash_table.clone(),
            new_hash_table: g_config.new_hash_table.clone(),
            tables: g_config.tables.clone(),
        }
    }

    pub fn transition_rules() -> impl Iterator<Item = (u32, u32, u32)> + Clone {
        let i1 = TRANSMAP
            .iter()
            .map(|(a, b)| (*a as u32, *b as u32, CtrlTransitionKind::Mpt as u32));
        let i2 = OPMAP
            .iter()
            .map(|(a, b)| (*a as u32, *b as u32, CtrlTransitionKind::Operation as u32));
        i1.chain(i2)
    }

    pub fn init<Fp: FieldExt>(&self, layouter: &mut impl Layouter<Fp>) -> Result<(), Error> {
        self.tables
            .fill_constant(layouter, Self::transition_rules())
    }

    pub fn init_hash_table<'d, Fp: FieldExt>(
        &self,
        layouter: &mut impl Layouter<Fp>,
        data: impl Iterator<Item = &'d SingleOp<Fp>> + Clone,
    ) -> Result<(), Error> {
        self.old_hash_table
            .fill(layouter, data.clone().flat_map(|op| &op.old.hash_traces))?;
        self.new_hash_table
            .fill(layouter, data.flat_map(|op| &op.new.hash_traces))?;
        Ok(())
    }

    /// assign data and enable flag for MPT circuit
    pub fn assign<Fp: FieldExt>(
        &self,
        region: &mut Region<'_, Fp>,
        offset: usize,
        data: &SingleOp<Fp>,
    ) -> Result<usize, Error> {
        let old_path_chip = PathChip::<Fp>::construct(self.old_path.clone(), offset, &data.old);
        let new_path_chip = PathChip::<Fp>::construct(self.new_path.clone(), offset, &data.new);
        let op_chip = OpChip::<Fp>::construct(self.op.clone(), offset, data);

        // caution: we made double assignations on key cell so sequence is important
        let op_end = op_chip.assign(region)?;
        let old_end = old_path_chip.assign(region)?;
        let new_end = new_path_chip.assign(region)?;

        assert_eq!(op_end, old_end);
        assert_eq!(op_end, new_end);

        for offset in offset..op_end {
            region.assign_advice(
                || "enable MPT circuit",
                self.s_enable,
                offset,
                || Ok(Fp::one()),
            )?;
        }

        Ok(op_end)
    }
}

fn lagrange_polynomial_for_hashtype<Fp: ff::PrimeField, const T: usize>(
    ref_n: Expression<Fp>,
) -> Expression<Fp> {
    super::lagrange_polynomial::<Fp, T, 5 /* last Type: Leaf */>(ref_n)
}

#[derive(Clone, Debug)]
struct PathChipConfig {
    s_data: Column<Advice>,
    hash_type: Column<Advice>,
    key: Column<Advice>,
    val: Column<Advice>,
}

/// chip for verify mutiple merkle path in MPT
/// it do not need any auxiliary cols
struct PathChip<'d, F> {
    offset: usize,
    config: PathChipConfig,
    data: &'d MPTPath<F>,
}

impl<Fp: FieldExt> Chip<Fp> for PathChip<'_, Fp> {
    type Config = PathChipConfig;
    type Loaded = MPTPath<Fp>;

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        self.data
    }
}

impl<'d, Fp: FieldExt> PathChip<'d, Fp> {
    fn configure(
        meta: &mut ConstraintSystem<Fp>,
        g_config: &MPTOpConfig,
        from_old: bool,
    ) -> <Self as Chip<Fp>>::Config {
        let s_data = g_config.s_data;
        let s_enable = g_config.s_enable;
        let hash_type = if from_old {
            g_config.old_hash_type
        } else {
            g_config.new_hash_type
        };
        let val = if from_old {
            g_config.old_val
        } else {
            g_config.new_val
        };
        //notice only one cell is used and we assign the unused cell in sibling for the purpose
        let key = if from_old {
            g_config.sibling
        } else {
            g_config.acc_key
        };

        let hash_table = if from_old {
            &g_config.old_hash_table
        } else {
            &g_config.new_hash_table
        };

        let s_row = g_config.s_row;
        let sibling = g_config.sibling;
        let path = g_config.path;
        let left =
            |meta: &mut VirtualCells<'_, Fp>| meta.query_advice(hash_table.0, Rotation::cur());
        let right =
            |meta: &mut VirtualCells<'_, Fp>| meta.query_advice(hash_table.1, Rotation::cur());
        let hash =
            |meta: &mut VirtualCells<'_, Fp>| meta.query_advice(hash_table.2, Rotation::cur());
        let trans_table = &g_config.tables;

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
        meta.lookup_any("mpt node hash", |meta| {
            let hash_type = meta.query_advice(hash_type, Rotation::cur());
            let s_path = meta.query_selector(s_row)
                * meta.query_advice(s_enable, Rotation::cur())
                * lagrange_polynomial_for_hashtype::<_, 2>(hash_type); //Middle

            let path_bit = meta.query_advice(path, Rotation::cur());
            let val_col = meta.query_advice(val, Rotation::cur());
            let sibling_col = meta.query_advice(sibling, Rotation::cur());
            let right_lookup = s_path.clone()
                * (path_bit.clone() * (val_col.clone() - sibling_col.clone())
                    + sibling_col.clone());
            let left_lookup =
                s_path.clone() * (path_bit * (sibling_col - val_col.clone()) + val_col);
            let hash_lookup = s_path * meta.query_advice(val, Rotation::prev());

            vec![
                (left_lookup, left(meta)),
                (right_lookup, right(meta)),
                (hash_lookup, hash(meta)),
            ]
        });

        meta.lookup_any("mpt leaf hash", |meta| {
            let hash_type = meta.query_advice(hash_type, Rotation::cur());
            let s_leaf = meta.query_advice(s_enable, Rotation::cur())
                * lagrange_polynomial_for_hashtype::<_, 5>(hash_type); //Leaf

            let key_col = s_leaf.clone() * meta.query_advice(key, Rotation::cur());
            let val_leaf_col = s_leaf.clone() * meta.query_advice(val, Rotation::cur());
            let hash_lookup = s_leaf * meta.query_advice(val, Rotation::prev());

            vec![
                (key_col, left(meta)),
                (val_leaf_col, right(meta)),
                (hash_lookup, hash(meta)),
            ]
        });

        //transition
        meta.lookup("mpt type trans", |meta| {
            let s_data = meta.query_advice(s_enable, Rotation::cur())
                * meta.query_advice(s_data, Rotation::cur());
            let hash = s_data.clone() * meta.query_advice(hash_type, Rotation::cur());
            let prev_hash = s_data.clone() * meta.query_advice(hash_type, Rotation::prev());

            vec![
                (prev_hash, trans_table.0),
                (hash, trans_table.1),
                (
                    s_data * Expression::Constant(Fp::from(CtrlTransitionKind::Mpt as u64)),
                    trans_table.2,
                ),
            ]
        });

        meta.create_gate("s_data open", |meta| {
            let enable = meta.query_selector(s_row) * meta.query_advice(s_enable, Rotation::cur());
            let s_data_not_opened =
                Expression::Constant(Fp::one()) - meta.query_advice(s_data, Rotation::cur());
            let hash_type = meta.query_advice(hash_type, Rotation::cur());
            // verify s_data is open when hash_type is not "start"
            // start is zero so we do not brother a lagrange poly
            vec![enable * hash_type * s_data_not_opened]
        });

        meta.create_gate("leaf extended", |meta| {
            let enable = meta.query_selector(s_row) * meta.query_advice(s_enable, Rotation::cur());
            let hash_type = meta.query_advice(hash_type, Rotation::cur());
            let s_extended = lagrange_polynomial_for_hashtype::<_, 3>(hash_type); //LeafExt
            let sibling = meta.query_advice(sibling, Rotation::cur());
            // + sibling must be 0 when hash_type is leaf extended, or malice
            //   advisor can make arbital sibling which would halt the process of L2
            // + value of val col in leaf-extended row must equal to the previous
            vec![
                enable.clone() * s_extended.clone() * sibling,
                enable
                    * s_extended
                    * (meta.query_advice(val, Rotation::cur())
                        - meta.query_advice(val, Rotation::prev())),
            ]
        });

        meta.create_gate("last leaf extended", |meta| {
            let enable = meta.query_selector(s_row) * meta.query_advice(s_enable, Rotation::cur());
            let hash_type = meta.query_advice(hash_type, Rotation::cur());
            let s_last_extended = lagrange_polynomial_for_hashtype::<_, 4>(hash_type); //LeafExtFinal

            // + sibling must be previous value of val when hash_type is leaf extended final
            // (notice the value for leafExtendedFinal can be omitted)
            vec![
                enable
                    * s_last_extended
                    * (meta.query_advice(sibling, Rotation::cur())
                        - meta.query_advice(val, Rotation::prev())),
            ]
        });

        PathChipConfig {
            s_data,
            hash_type,
            val,
            key,
        }
    }

    fn construct(
        config: PathChipConfig,
        offset: usize,
        data: &'d <Self as Chip<Fp>>::Loaded,
    ) -> Self {
        Self {
            config,
            offset,
            data,
        }
    }

    fn assign(&self, region: &mut Region<'_, Fp>) -> Result<usize, Error> {
        let config = &self.config;
        let mut offset = self.offset;
        let key: Fp = self.data.key;
        let vals = &self.data.hashes;
        let hash_types = &self.data.hash_types;
        assert_eq!(hash_types.len(), vals.len());

        for (hash_type, val) in hash_types.iter().zip(vals.iter()) {
            region.assign_advice(|| "val", config.val, offset, || Ok(*val))?;
            region.assign_advice(
                || format!("hash_type {}", *hash_type as u32),
                config.hash_type,
                offset,
                || Ok(Fp::from(*hash_type as u64)),
            )?;
            region.assign_advice(
                || "sel",
                config.s_data,
                offset,
                || {
                    Ok(match hash_type {
                        HashType::Start => Fp::zero(),
                        _ => Fp::one(),
                    })
                },
            )?;
            match hash_type {
                HashType::Empty | HashType::Leaf => region
                    .assign_advice(|| "key", config.key, offset, || Ok(key))
                    .map(|_| ()),
                _ => Ok(()),
            }?;
            offset += 1;
        }

        Ok(offset)
    }
}

#[derive(Clone, Debug)]
struct OpChipConfig {
    sibling: Column<Advice>,
    path: Column<Advice>,
    depth: Column<Advice>,
    acc_key: Column<Advice>,
}

/// chip for verify mutiple merkle path in MPT
/// it do not need any auxiliary cols
struct OpChip<'d, F> {
    offset: usize,
    config: OpChipConfig,
    data: &'d SingleOp<F>,
}

impl<Fp: FieldExt> Chip<Fp> for OpChip<'_, Fp> {
    type Config = OpChipConfig;
    type Loaded = SingleOp<Fp>;

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        self.data
    }
}

impl<'d, Fp: FieldExt> OpChip<'d, Fp> {
    fn configure(
        meta: &mut ConstraintSystem<Fp>,
        g_config: &MPTOpConfig,
    ) -> <Self as Chip<Fp>>::Config {
        let path = g_config.path;
        let old_hash_type = g_config.old_hash_type;
        let new_hash_type = g_config.new_hash_type;
        let acc_key = g_config.acc_key;
        let sibling = g_config.sibling;
        let depth_aux = g_config.depth;

        let s_row = g_config.s_row;
        let s_enable = g_config.s_enable;
        let s_data = g_config.s_data;
        let type_table = &g_config.tables;

        //old - new
        meta.lookup("op update trans", |meta| {
            let old_hash = meta.query_advice(s_enable, Rotation::cur())
                * meta.query_advice(old_hash_type, Rotation::cur());
            let new_hash = meta.query_advice(s_enable, Rotation::cur())
                * meta.query_advice(new_hash_type, Rotation::cur());

            vec![
                (old_hash, type_table.0),
                (new_hash, type_table.1),
                (
                    // notice we have (0, 0) as one of the rules so we do not conditionally disable the constant here
                    Expression::Constant(Fp::from(CtrlTransitionKind::Operation as u64)),
                    type_table.2,
                ),
            ]
        });

        meta.create_gate("s_data boolean", |meta| {
            let enable = meta.query_selector(s_row) * meta.query_advice(s_enable, Rotation::cur());
            let s_data = meta.query_advice(s_data, Rotation::cur());
            // s_data ∈ {0, 1}
            vec![enable * (Expression::Constant(Fp::one()) - s_data.clone()) * s_data]
        });

        meta.create_gate("path bit", |meta| {
            let enable = meta.query_selector(s_row) * meta.query_advice(s_enable, Rotation::cur());
            let new_hash_type = meta.query_advice(new_hash_type, Rotation::cur());
            let old_hash_type = meta.query_advice(old_hash_type, Rotation::cur());
            let leaf_type = Expression::Constant(Fp::from(HashType::Leaf as u64));

            let path = meta.query_advice(path, Rotation::cur());
            let path_bit = (Expression::Constant(Fp::one()) - path.clone()) * path;

            // if (new_hash_type or old_hash_type is not leaf) path ∈ {0, 1}
            vec![
                enable
                    * path_bit
                    * (new_hash_type - leaf_type.clone())
                    * (old_hash_type - leaf_type),
            ]
        });

        meta.create_gate("depth", |meta| {
            let enable = meta.query_selector(s_row) * meta.query_advice(s_enable, Rotation::cur());
            let s_data = meta.query_advice(s_data, Rotation::cur());
            let s_data_not_open = Expression::Constant(Fp::one()) - s_data.clone();
            let depth_aux_start = meta.query_advice(depth_aux, Rotation::cur())
                - Expression::Constant(Fp::one().double().invert().unwrap());
            let depth_aux_common = meta.query_advice(depth_aux, Rotation::cur())
                - meta.query_advice(depth_aux, Rotation::prev())
                    * Expression::Constant(Fp::from(2u64));

            // for any row which s_data not 0: depth_aux == depth_aux.prev * 2
            // for row which s_data is 0, depth_aux must be 1/2
            vec![
                enable.clone() * s_data_not_open * depth_aux_start,
                enable * s_data * depth_aux_common,
            ]
        });

        meta.create_gate("calc key", |meta| {
            let enable = meta.query_selector(s_row) * meta.query_advice(s_enable, Rotation::cur());
            let s_data = meta.query_advice(s_data, Rotation::cur());
            let s_data_not_open = Expression::Constant(Fp::one()) - s_data.clone();
            let path_cur = meta.query_advice(path, Rotation::cur())
                * meta.query_advice(depth_aux, Rotation::cur());
            let key_cur = meta.query_advice(acc_key, Rotation::cur());

            // for any row which s_data is not 0: acc_key = path * depth + acc_key.prev
            // for row which s_data is 0, acc_key must be 0
            vec![
                enable.clone() * s_data_not_open * key_cur.clone(),
                enable
                    * s_data
                    * (path_cur + meta.query_advice(acc_key, Rotation::prev()) - key_cur),
            ]
        });

        OpChipConfig {
            path,
            sibling,
            depth: depth_aux,
            acc_key,
        }
    }

    fn construct(
        config: OpChipConfig,
        offset: usize,
        data: &'d <Self as Chip<Fp>>::Loaded,
    ) -> Self {
        Self {
            config,
            offset,
            data,
        }
    }

    fn assign(&self, region: &mut Region<'_, Fp>) -> Result<usize, Error> {
        let config = &self.config;
        let paths = &self.data.path;
        let siblings = &self.data.siblings;
        assert_eq!(paths.len(), siblings.len());
        let mut offset = self.offset;
        region.assign_advice(|| "path padding", config.path, offset, || Ok(Fp::zero()))?;
        region.assign_advice(
            || "acckey padding",
            config.acc_key,
            offset,
            || Ok(Fp::zero()),
        )?;
        region.assign_advice(
            || "depth padding",
            config.depth,
            offset,
            || Ok(Fp::one().double().invert().unwrap()),
        )?;
        region.assign_advice(
            || "sibling padding",
            config.sibling,
            offset,
            || Ok(Fp::zero()),
        )?;
        offset += 1;

        let mut cur_depth = Fp::one();
        let mut acc_key = Fp::zero();

        for (path, sibling) in paths.iter().zip(siblings.iter()) {
            acc_key = *path * cur_depth + acc_key;

            region.assign_advice(|| "path", config.path, offset, || Ok(*path))?;
            region.assign_advice(|| "acckey", config.acc_key, offset, || Ok(acc_key))?;
            region.assign_advice(|| "depth", config.depth, offset, || Ok(cur_depth))?;
            region.assign_advice(|| "sibling", config.sibling, offset, || Ok(*sibling))?;

            cur_depth = cur_depth.double();
            offset += 1;
        }

        Ok(offset)
    }
}

#[cfg(test)]
mod test {
    #![allow(unused_imports)]

    use super::*;
    use crate::{serde::Row, test_utils::*};
    use halo2_proofs::{
        circuit::{Cell, Region, SimpleFloorPlanner},
        dev::{MockProver, VerifyFailure},
        plonk::{Circuit, Expression},
    };

    const MAX_PATH_DEPTH: usize = 16;
    const MAX_KEY: usize = (2 as usize).pow(MAX_PATH_DEPTH as u32);

    impl MPTOpConfig {
        /// assign all required cols directly
        pub fn create(meta: &mut ConstraintSystem<Fp>) -> Self {
            Self {
                s_row: meta.complex_selector(),
                s_enable: meta.advice_column(),
                s_data: meta.advice_column(),
                sibling: meta.advice_column(),
                depth: meta.advice_column(),
                acc_key: meta.advice_column(),
                path: meta.advice_column(),
                old_hash_type: meta.advice_column(),
                new_hash_type: meta.advice_column(),
                old_val: meta.advice_column(),
                new_val: meta.advice_column(),
                old_hash_table: HashTable::configure_create(meta),
                new_hash_table: HashTable::configure_create(meta),
                tables: MPTOpTables::configure_create(meta),
            }
        }

        /// simply flush a row with 0 value to avoid gate poisoned / cell error in debug prover,
        pub fn flush_row(&self, region: &mut Region<'_, Fp>, offset: usize) -> Result<(), Error> {
            region.assign_advice(|| "flushing", self.s_enable, offset, || Ok(Fp::zero()))?;
            region.assign_advice(|| "flushing", self.s_data, offset, || Ok(rand_fp()))?;
            region.assign_advice(|| "flushing", self.depth, offset, || Ok(rand_fp()))?;
            region.assign_advice(|| "flushing", self.sibling, offset, || Ok(rand_fp()))?;
            region.assign_advice(|| "flushing", self.acc_key, offset, || Ok(rand_fp()))?;
            region.assign_advice(|| "flushing", self.path, offset, || Ok(rand_fp()))?;
            region.assign_advice(|| "flushing", self.old_hash_type, offset, || Ok(rand_fp()))?;
            region.assign_advice(|| "flushing", self.new_hash_type, offset, || Ok(rand_fp()))?;
            region.assign_advice(|| "flushing", self.old_val, offset, || Ok(rand_fp()))?;
            region.assign_advice(|| "flushing", self.new_val, offset, || Ok(rand_fp()))?;
            Ok(())
        }
    }

    #[derive(Clone, Debug)]
    struct MPTTestConfig {
        global: MPTOpConfig,
        chip: PathChipConfig,
    }

    // express for a single path block
    #[derive(Clone, Default)]
    struct TestPathCircuit<const USE_OLD: bool> {
        key: Fp,
        path: Vec<Fp>,
        siblings: Vec<Fp>,
        data: MPTPath<Fp>,
    }

    impl<const USE_OLD: bool> Circuit<Fp> for TestPathCircuit<USE_OLD> {
        type Config = MPTTestConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            let g_config = MPTOpConfig::create(meta);
            let chip = PathChip::configure(meta, &g_config, USE_OLD);

            MPTTestConfig {
                global: g_config,
                chip,
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            let offset: usize = 1;
            let chip_cfg = config.chip.clone();
            let mpt_chip = PathChip::<Fp>::construct(chip_cfg.clone(), offset, &self.data);
            layouter.assign_region(
                || "main",
                |mut region| {
                    let config = &config.global;
                    config.flush_row(&mut region, 0)?;
                    let mut working_offset = offset;
                    config.flush_row(&mut region, working_offset)?; // also flush the firt row of working region
                    region.assign_advice(
                        || "enable",
                        config.s_enable,
                        working_offset,
                        || Ok(Fp::one()),
                    )?;
                    config.s_row.enable(&mut region, working_offset)?;
                    working_offset += 1;
                    let next_offset = working_offset + self.siblings.len();
                    //need to fill some other cols
                    for (index, offset) in (working_offset..next_offset).enumerate() {
                        config.s_row.enable(&mut region, offset)?;
                        region.assign_advice(
                            || "enable",
                            config.s_enable,
                            offset,
                            || Ok(Fp::one()),
                        )?;
                        region.assign_advice(
                            || "sibling",
                            config.sibling,
                            offset,
                            || Ok(self.siblings[index]),
                        )?;
                        region.assign_advice(
                            || "path",
                            config.path,
                            offset,
                            || Ok(self.path[index]),
                        )?;
                    }

                    let chip_next_offset = mpt_chip.assign(&mut region)?;
                    assert_eq!(chip_next_offset, next_offset);

                    //also test flush some more rows
                    for offset in next_offset..(next_offset + 3) {
                        config.s_row.enable(&mut region, offset)?;
                        config.flush_row(&mut region, offset)?;
                    }

                    Ok(())
                },
            )?;

            config.global.tables.fill_constant(
                &mut layouter,
                TRANSMAP
                    .iter()
                    .map(|(a, b)| (*a as u32, *b as u32, CtrlTransitionKind::Mpt as u32)),
            )?;
            if USE_OLD {
                config
                    .global
                    .old_hash_table
                    .fill(&mut layouter, self.data.hash_traces.iter())
            } else {
                config
                    .global
                    .new_hash_table
                    .fill(&mut layouter, self.data.hash_traces.iter())
            }?;

            Ok(())
        }
    }

    impl From<SingleOp<Fp>> for TestPathCircuit<true> {
        fn from(op: SingleOp<Fp>) -> Self {
            Self {
                key: op.key,
                path: op.path,
                siblings: op.siblings,
                data: op.old,
            }
        }
    }

    impl From<SingleOp<Fp>> for TestPathCircuit<false> {
        fn from(op: SingleOp<Fp>) -> Self {
            Self {
                key: op.key,
                path: op.path,
                siblings: op.siblings,
                data: op.new,
            }
        }
    }

    impl<const USE_OLD: bool> TestPathCircuit<USE_OLD> {
        //decompose key to path bits, start from smallest, return the
        //two parts which reside on path and the leaf
        fn decompose_path(key: u32, len: usize) -> (Vec<bool>, u32) {
            let mut path_bits = Vec::new();
            assert!(MAX_PATH_DEPTH >= len, "more siblings than max depth");

            let mut res_path = key;

            for _ in 0..len {
                let has_bit = (res_path & 1) != 0;
                path_bits.push(has_bit);
                res_path /= 2;
            }

            (path_bits, res_path)
        }

        fn create_rand(layers: usize) -> Self {
            let leaf = rand_fp();
            let mut siblings = Vec::new();
            for _ in 0..layers {
                siblings.push(rand_fp());
            }
            let key = u32::from_be_bytes(rand_bytes_array()) % MAX_KEY as u32;
            let (path_bits, rev_path) = Self::decompose_path(key, layers);
            let data =
                MPTPath::<Fp>::create(&path_bits, &siblings, Fp::from(key as u64), leaf, mock_hash);
            siblings.push(Fp::zero());
            let mut path: Vec<Fp> = path_bits
                .into_iter()
                .map(|not_zero| if not_zero { Fp::one() } else { Fp::zero() })
                .collect();
            path.push(Fp::from(rev_path as u64));

            Self {
                key: Fp::from(key as u64),
                data,
                path,
                siblings,
            }
        }
    }

    #[test]
    fn single_path() {
        let k = 5; //at least 32 rows for constant table use many space

        let circuit = TestPathCircuit::<true>::create_rand(3);
        #[cfg(feature = "print_layout")]
        print_layout!("layouts/path_layout_old.png", k, &circuit);

        let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));

        let circuit = TestPathCircuit::<false>::create_rand(3);
        #[cfg(feature = "print_layout")]
        print_layout!("layouts/path_layout_new.png", k, &circuit);

        let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn geth_case_path() {
        let ops = Row::fold_flattern_rows(Row::from_lines(TEST_FILE).unwrap());

        let k = 5;
        for op in ops {
            let single_op: SingleOp<Fp> = op.as_slice().into();
            let circuit = TestPathCircuit::<true>::from(single_op);
            let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
            assert_eq!(prover.verify(), Ok(()));

            let single_op: SingleOp<Fp> = op.as_slice().into();
            let circuit = TestPathCircuit::<false>::from(single_op);
            let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
            assert_eq!(prover.verify(), Ok(()));
        }
    }

    #[derive(Clone, Debug)]
    struct OpTestConfig {
        global: MPTOpConfig,
        chip: OpChipConfig,
    }

    // express for a single path block
    #[derive(Clone, Default)]
    struct TestOpCircuit {
        data: SingleOp<Fp>,
        old_hash_types: Vec<HashType>,
        new_hash_types: Vec<HashType>,
    }

    impl Circuit<Fp> for TestOpCircuit {
        type Config = OpTestConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            let g_config = MPTOpConfig::create(meta);
            let chip = OpChip::configure(meta, &g_config);

            OpTestConfig {
                global: g_config,
                chip,
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            let offset: usize = 1;
            let chip_cfg = config.chip.clone();
            let op_chip = OpChip::<Fp>::construct(chip_cfg.clone(), offset, &self.data);
            layouter.assign_region(
                || "main",
                |mut region| {
                    let config = &config.global;
                    config.flush_row(&mut region, 0)?;
                    let next_offset = offset + self.old_hash_types.len();
                    //need to fill some other cols
                    for (index, offset) in (offset..next_offset).enumerate() {
                        config.s_row.enable(&mut region, offset)?;
                        region.assign_advice(
                            || "enable",
                            config.s_enable,
                            offset,
                            || Ok(Fp::one()),
                        )?;
                        region.assign_advice(
                            || "s_data",
                            config.s_data,
                            offset,
                            || Ok(if index == 0 { Fp::zero() } else { Fp::one() }),
                        )?;
                        region.assign_advice(
                            || "old hash_type",
                            config.old_hash_type,
                            offset,
                            || Ok(Fp::from(self.old_hash_types[index] as u64)),
                        )?;
                        region.assign_advice(
                            || "new hash_type",
                            config.new_hash_type,
                            offset,
                            || Ok(Fp::from(self.new_hash_types[index] as u64)),
                        )?;
                    }

                    let chip_next_offset = op_chip.assign(&mut region)?;
                    assert_eq!(chip_next_offset, next_offset);

                    //also test flush some more rows
                    for offset in next_offset..(next_offset + 3) {
                        config.s_row.enable(&mut region, offset)?;
                        config.flush_row(&mut region, offset)?;
                    }

                    Ok(())
                },
            )?;

            config.global.tables.fill_constant(
                &mut layouter,
                OPMAP
                    .iter()
                    .map(|(a, b)| (*a as u32, *b as u32, CtrlTransitionKind::Operation as u32)),
            )?;
            Ok(())
        }
    }

    impl TestOpCircuit {
        fn from_op(op: SingleOp<Fp>) -> Self {
            Self {
                old_hash_types: op.old.hash_types,
                new_hash_types: op.new.hash_types,
                data: SingleOp::<Fp> {
                    path: op.path,
                    siblings: op.siblings,
                    ..Default::default()
                },
            }
        }
    }

    lazy_static! {

        static ref DEMOCIRCUIT1: TestOpCircuit = {
            TestOpCircuit {
                data: SingleOp::<Fp>{
                    siblings: vec![Fp::zero()],
                    path: vec![Fp::from(4u64)], //the key is 0b100u64
                    ..Default::default()
                },
                old_hash_types: vec![HashType::Start, HashType::Empty],
                new_hash_types: vec![HashType::Start, HashType::Leaf],
            }
        };

        static ref DEMOCIRCUIT2: TestOpCircuit = {
            TestOpCircuit {
                data: SingleOp::<Fp>{
                    siblings: vec![Fp::from(11u64), rand_fp()],
                    path: vec![Fp::one(), Fp::from(8u64)], //the key is 0b10001u64
                    ..Default::default()
                },
                old_hash_types: vec![HashType::Start, HashType::LeafExtFinal, HashType::Empty],
                new_hash_types: vec![HashType::Start, HashType::Middle, HashType::Leaf],
            }
        };

        static ref DEMOCIRCUIT3: TestOpCircuit = {
            TestOpCircuit {
                data: SingleOp::<Fp>{
                    siblings: vec![Fp::from(11u64), Fp::zero(), Fp::from(22u64), rand_fp()],
                    path: vec![Fp::one(), Fp::zero(), Fp::one(), Fp::from(5u64)], //the key is 0b101101u64
                    ..Default::default()
                },
                old_hash_types: vec![
                    HashType::Start,
                    HashType::Middle,
                    HashType::LeafExt,
                    HashType::LeafExtFinal,
                    HashType::Empty,
                ],
                new_hash_types: vec![
                    HashType::Start,
                    HashType::Middle,
                    HashType::Middle,
                    HashType::Middle,
                    HashType::Leaf,
                ],
            }
        };
    }

    #[test]
    fn single_op() {
        let k = 5; //at least 32 rows for constant table use many space

        #[cfg(feature = "print_layout")]
        print_layout!("layouts/op_layout.png", k, &*DEMOCIRCUIT3);

        let prover = MockProver::<Fp>::run(k, &*DEMOCIRCUIT3, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));

        let prover = MockProver::<Fp>::run(k, &*DEMOCIRCUIT2, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));

        let prover = MockProver::<Fp>::run(k, &*DEMOCIRCUIT1, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn geth_case_op() {
        let ops = Row::fold_flattern_rows(Row::from_lines(TEST_FILE).unwrap());

        let k = 5;
        for op in ops {
            let circuit = TestOpCircuit::from_op(op.as_slice().into());
            let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
            assert_eq!(prover.verify(), Ok(()));
        }
    }

    #[derive(Clone, Debug)]
    struct GadgetTestConfig {
        gadget: MPTOpGadget,
        sel: Selector,
        free_cols: [Column<Advice>; 10],
    }

    // express for a single path block
    #[derive(Clone, Default)]
    struct MPTTestCircuit {
        data: SingleOp<Fp>,
    }

    impl Circuit<Fp> for MPTTestCircuit {
        type Config = GadgetTestConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            let sel = meta.complex_selector();
            let free_cols = [(); 10].map(|_| meta.advice_column());
            let exported_cols = [free_cols[0], free_cols[1], free_cols[2], free_cols[3]];

            GadgetTestConfig {
                gadget: MPTOpGadget::configure_simple(meta, sel, exported_cols, &free_cols[4..]),
                free_cols,
                sel,
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            config.gadget.init(&mut layouter)?;
            config
                .gadget
                .init_hash_table(&mut layouter, [&self.data].into_iter())?;

            layouter.assign_region(
                || "mpt",
                |mut region| {
                    //flush first row, just avoid Cell error ...
                    config.free_cols.iter().try_for_each(|col| {
                        region
                            .assign_advice(|| "flushing", *col, 0, || Ok(Fp::zero()))
                            .map(|_| ())
                    })?;
                    let end = config.gadget.assign(&mut region, 1, &self.data)?;
                    for offset in 1..end {
                        config.sel.enable(&mut region, offset)?;
                    }

                    Ok(())
                },
            )?;

            Ok(())
        }
    }

    impl From<SingleOp<Fp>> for MPTTestCircuit {
        fn from(data: SingleOp<Fp>) -> Self {
            Self { data }
        }
    }

    #[test]
    fn geth_case_gadget() {
        let ops = Row::fold_flattern_rows(Row::from_lines(TEST_FILE).unwrap());

        let k = 5;
        for (_index, op) in ops.into_iter().enumerate() {
            let single_op: SingleOp<Fp> = op.as_slice().into();
            let circuit = MPTTestCircuit::from(single_op);

            #[cfg(feature = "print_layout")]
            {
                let path = format!("layouts/mptgadget_layout_{}.png", _index);
                print_layout!(&path, k, &circuit);
            }

            let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
            assert_eq!(prover.verify(), Ok(()));
        }
    }
}
