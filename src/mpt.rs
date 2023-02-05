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
//  | row ||     sibling      |  path   |  s_path |  key  |     HashType   |       val        |     HashTable (left, right, hash)        |
//  |-----||------------------|---------|---------|-------|----------------|------------------|----------------|----------------|--------|
//  |  2  ||                  |<padding>|    0    |       |      Start     |      root        |                                          |
//  |  3  ||      elem_1      | cbit_1  |    1    |       |       Mid      |     digest_1     |  digest_1/elem_1 digest_1/elem_1  root   |
//  |  4  ||      elem_2      | cbit_2  |    1    |       |     LeafExt    |     digest_2     |  digest_2/elem_2 digest_2/elem_2 digest_1|
//  |  5  ||      elem_3      | cbit_3  |    1    |       |  LeafExtFinal  |     digest_3     |  digest_3/elem_2 digest_3/elem_2 digest_2|
//  |  6  ||     <padding>    |leaf_res |    0    |Leafkey|      Empty     |      leaf        |        Leafkey leaf digest_3             |
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
//  |  2  ||       Start      |     Start        |         |       |  1/2   |
//  |  3  ||        Mid       |      Mid         | cbit_0  |       |   1    |
//  |  4  ||        Mid       |      Mid         | cbit_1  |       |   2    |
//  |  5  ||      LeafExt     |      Mid         | cbit_2  |       |   4    |
//  |  6  ||   LeafExtFinal   |      Mid         | cbit_3  |       |   8    |
//  |  7  ||       Empty      |      Leaf        | LeafRes |  key* |   16   |
//  |-----||------------------|------------------|---------|-------|--------|
//
//  OpChip would:
//  * constraint the matching old <-> New hashType by lookup from operation table ☑
//  * constraint s_path row to be boolean ☑
//  * inducing a depth column for accumulating path ☑
//  * constraint path as bit except when one of the hashtype is leaf ☑
//  * verify the acckey column by accumulating the path bit and LeafPath bits ☑
//
//  while assignation, OpChip response to assign sibling, acckey and path
#![allow(clippy::map_identity)]

use super::{CtrlTransitionKind, HashType};
use crate::operation::{MPTPath, SingleOp};
use halo2_proofs::{
    arithmetic::{Field, FieldExt},
    circuit::{Chip, Layouter, Region, Value},
    plonk::{
        Advice, Column, ConstraintSystem, Error, Expression, Selector, TableColumn, VirtualCells,
    },
    poly::Rotation,
};
use lazy_static::lazy_static;

#[derive(Clone, Debug)]
pub(crate) struct MPTOpTables(
    TableColumn,      // op mark
    [TableColumn; 3], // op rules
);

lazy_static! {
    static ref OPMAP : Vec<(HashType, HashType, HashType)> = {
        vec![
            (HashType::Start, HashType::Start, HashType::Start),
            (HashType::Empty, HashType::Empty, HashType::Empty),
            (HashType::Empty, HashType::Leaf, HashType::Leaf),
            (HashType::Leaf, HashType::Empty, HashType::Leaf),
            (HashType::Leaf, HashType::Leaf, HashType::Leaf),
            (HashType::Middle, HashType::Middle, HashType::Middle),
            (HashType::LeafExt, HashType::Middle, HashType::LeafExt),
            (HashType::LeafExt, HashType::LeafExt, HashType::LeafExt),
            (HashType::LeafExtFinal, HashType::Middle, HashType::LeafExtFinal),
            (HashType::LeafExtFinal, HashType::LeafExtFinal, HashType::LeafExtFinal),
            (HashType::Middle, HashType::LeafExt, HashType::LeafExt),
            (HashType::Middle, HashType::LeafExtFinal, HashType::LeafExtFinal),
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
            [0; 3].map(|_| meta.lookup_table_column()),
        )
    }

    pub fn build_lookup_any<Fp: FieldExt>(
        &self,
        enable: Expression<Fp>,
        rules: impl IntoIterator<Item = Expression<Fp>>,
        mark: u64,
    ) -> Vec<(Expression<Fp>, TableColumn)> {
        let mut ret: Vec<_> = rules
            .into_iter()
            .map(|exp| enable.clone() * exp)
            .zip(self.1)
            .collect();
        ret.push((enable * Expression::Constant(Fp::from(mark)), self.0));
        ret
    }

    pub fn build_lookup<Fp: FieldExt>(
        &self,
        enable: Expression<Fp>,
        old: Expression<Fp>,
        new: Expression<Fp>,
        mark: u64,
    ) -> Vec<(Expression<Fp>, TableColumn)> {
        self.build_lookup_any(enable, [old, new], mark)
    }

    pub fn fill_constant<Fp: FieldExt>(
        &self,
        layouter: &mut impl Layouter<Fp>,
        rules: impl Iterator<Item = ([u32; 3], u32)> + Clone,
    ) -> Result<(), Error> {
        layouter.assign_table(
            || "op table",
            |mut table| {
                // default line
                table.assign_cell(|| "default mark", self.0, 0, || Value::known(Fp::zero()))?;
                for i in 0..3 {
                    table.assign_cell(
                        || "default rule",
                        self.1[i],
                        0,
                        || Value::known(Fp::zero()),
                    )?;
                }

                for (offset, (items, mark)) in rules.clone().enumerate() {
                    let offset = offset + 1;
                    for (rule, col) in items.into_iter().zip(self.1) {
                        table.assign_cell(
                            || "rule item",
                            col,
                            offset,
                            || Value::known(Fp::from(rule as u64)),
                        )?;
                    }

                    table.assign_cell(
                        || "mark",
                        self.0,
                        offset,
                        || Value::known(Fp::from(mark as u64)),
                    )?;
                }
                Ok(())
            },
        )
    }
}

#[derive(Clone, Debug)]
pub(crate) struct HashTable(pub [Column<Advice>; 5]);

impl HashTable {
    pub fn configure_create<Fp: Field>(meta: &mut ConstraintSystem<Fp>) -> Self {
        Self([0; 5].map(|_| meta.advice_column()))
    }

    pub fn configure_assign(cols: &[Column<Advice>]) -> Self {
        Self([cols[0], cols[1], cols[2], cols[3], cols[4]])
    }

    pub fn commitment_index(&self) -> [usize; 5] {
        self.0.map(|col| col.index())
    }

    pub fn build_lookup<Fp: FieldExt>(
        &self,
        meta: &mut VirtualCells<'_, Fp>,
        enable: Expression<Fp>,
        fst: Expression<Fp>,
        snd: Expression<Fp>,
        hash: Expression<Fp>,
    ) -> Vec<(Expression<Fp>, Expression<Fp>)> {
        vec![
            (
                enable.clone() * hash,
                meta.query_advice(self.0[0], Rotation::cur()),
            ),
            (
                enable.clone() * fst,
                meta.query_advice(self.0[1], Rotation::cur()),
            ),
            (
                enable.clone() * snd,
                meta.query_advice(self.0[2], Rotation::cur()),
            ),
            (
                enable * Expression::Constant(Fp::zero()),
                meta.query_advice(self.0[3], Rotation::cur()),
            ),
            // TODO: also lookup from `self.0[4]` after https://github.com/scroll-tech/mpt-circuit/issues/9
            // has been resolved
        ]
    }

    /// a helper entry to fill hash table with specified rows, use padding record
    /// when hashing_records is not enough
    pub fn dev_fill_with_paddings<'d, Fp: FieldExt>(
        &self,
        layouter: &mut impl Layouter<Fp>,
        hashing_records: impl Iterator<Item = &'d (Fp, Fp, Fp)> + Clone,
        padding: (Fp, Fp, Fp),
        filled_rows: usize,
    ) -> Result<(), Error> {
        self.dev_fill(
            layouter,
            hashing_records
                .map(|i| i) //shrink the lifetime from 'd
                .chain(std::iter::repeat(&padding))
                .take(filled_rows),
        )
    }

    /// a helper entry to fill hash table, only for dev (in using cases)
    pub fn dev_fill<'d, Fp: FieldExt>(
        &self,
        layouter: &mut impl Layouter<Fp>,
        hashing_records: impl Iterator<Item = &'d (Fp, Fp, Fp)> + Clone,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "hash table",
            |mut table| {
                // default: 0, 0, 0
                for col in self.0 {
                    table.assign_advice(|| "default", col, 0, || Value::known(Fp::zero()))?;
                }

                hashing_records
                    .clone()
                    .enumerate()
                    .try_for_each(|(offset, val)| {
                        let (lh, rh, h) = val;
                        let offset = offset + 1;

                        table.assign_advice(|| "result", self.0[0], offset, || Value::known(*h))?;

                        table.assign_advice(|| "left", self.0[1], offset, || Value::known(*lh))?;

                        table.assign_advice(|| "right", self.0[2], offset, || Value::known(*rh))?;

                        table.assign_advice(
                            || "ctrl_pad",
                            self.0[3],
                            offset,
                            || Value::known(Fp::zero()),
                        )?;

                        table.assign_advice(
                            || "heading mark",
                            self.0[4],
                            offset,
                            || Value::known(Fp::one()),
                        )?;

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
    s_path: Column<Advice>,
    depth: Column<Advice>,
    ctrl_type: Column<Advice>,
    s_ctrl_type: [Column<Advice>; HASH_TYPE_CNT],
    old_hash_type: Column<Advice>,
    new_hash_type: Column<Advice>,
    s_hash_match_ctrl: [Column<Advice>; 2], //[old, new]
    s_hash_match_ctrl_aux: [Column<Advice>; 2],
    sibling: Column<Advice>,
    acc_key: Column<Advice>,
    path: Column<Advice>,
    old_val: Column<Advice>,
    new_val: Column<Advice>,
    key_aux: Column<Advice>,

    hash_table: HashTable,
    tables: MPTOpTables,
}

#[derive(Clone, Debug)]
pub(crate) struct MPTOpGadget {
    op: OpChipConfig,
    old_path: PathChipConfig,
    new_path: PathChipConfig,
    s_enable: Column<Advice>,

    pub hash_table: HashTable,
    pub tables: MPTOpTables,
}

impl MPTOpGadget {
    pub fn min_free_cols() -> usize {
        11
    }

    pub fn min_ctrl_types() -> usize {
        HASH_TYPE_CNT
    }

    /// if the gadget would be used only once, this entry is more easy
    pub fn configure_simple<Fp: FieldExt>(
        meta: &mut ConstraintSystem<Fp>,
        sel: Selector,
        exported: &[Column<Advice>],
        s_ctrl_type: &[Column<Advice>],
        free: &[Column<Advice>],
        root_index: Option<(Column<Advice>, Column<Advice>)>,
    ) -> Self {
        let tables = MPTOpTables::configure_create(meta);
        let hash_tbls = HashTable::configure_create(meta);

        Self::configure(
            meta,
            sel,
            exported,
            s_ctrl_type,
            free,
            root_index,
            tables,
            hash_tbls,
        )
    }

    /// create gadget from assigned cols, we need:
    /// + circuit selector * 1
    /// + exported col * 4 (MUST by following sequence: layout_flag, s_enable, old_val, new_val)
    /// + s_op_flags * 6 (corresponding 6 ctrl_types)
    /// + free col * 8
    /// notice the gadget has bi-direction exporting (on top it exporting mpt root and bottom exporting leaf)
    pub fn configure<Fp: FieldExt>(
        meta: &mut ConstraintSystem<Fp>,
        sel: Selector,
        exported: &[Column<Advice>],
        s_ctrl_type: &[Column<Advice>],
        free: &[Column<Advice>],
        root_index: Option<(Column<Advice>, Column<Advice>)>,
        tables: MPTOpTables,
        hash_tbl: HashTable,
    ) -> Self {
        assert!(free.len() >= 8, "require at least 8 free cols");

        let g_config = MPTOpConfig {
            tables,
            s_row: sel,
            s_path: free[0],
            depth: free[1],
            new_hash_type: free[2],
            old_hash_type: free[3],
            sibling: free[4],
            path: free[5],
            key_aux: free[6],
            s_hash_match_ctrl: [free[7], free[8]],
            s_hash_match_ctrl_aux: [free[9], free[10]],
            ctrl_type: exported[0],
            s_enable: exported[1],
            old_val: exported[2],
            new_val: exported[3],
            acc_key: exported[4],
            s_ctrl_type: s_ctrl_type[0..6].try_into().expect("same size"),
            hash_table: hash_tbl,
        };

        meta.create_gate("flag boolean", |meta| {
            let s_row = meta.query_selector(g_config.s_row);
            let s_enable = meta.query_advice(g_config.s_enable, Rotation::cur());
            // s_enable ∈ {0, 1}
            vec![s_row * (Expression::Constant(Fp::one()) - s_enable.clone()) * s_enable]
        });

        if let Some((old_root_index, new_root_index)) = root_index {
            meta.create_gate("root index", |meta| {
                let s_row = meta.query_selector(g_config.s_row);
                let s_enable = s_row
                    * meta.query_advice(g_config.s_enable, Rotation::cur())
                    * meta.query_advice(
                        g_config.s_ctrl_type[HashType::Start as usize],
                        Rotation::cur(),
                    );
                // constraint root index:
                // the old root in heading row (START) equal to the new_root_index_prev
                // the old root in heading row (START) also equal to the old_root_index_cur
                // the new root in heading row (START) equal must be equal to new_root_index_cur
                vec![
                    s_enable.clone()
                        * (meta.query_advice(g_config.old_val, Rotation::cur())
                            - meta.query_advice(new_root_index, Rotation::prev())),
                    s_enable.clone()
                        * (meta.query_advice(g_config.old_val, Rotation::cur())
                            - meta.query_advice(old_root_index, Rotation::cur())),
                    s_enable
                        * (meta.query_advice(g_config.new_val, Rotation::cur())
                            - meta.query_advice(new_root_index, Rotation::cur())),
                ]
            });
        }

        Self {
            s_enable: g_config.s_enable,
            op: OpChip::<Fp>::configure(meta, &g_config),
            old_path: PathChip::<Fp>::configure(meta, &g_config, true),
            new_path: PathChip::<Fp>::configure(meta, &g_config, false),
            hash_table: g_config.hash_table.clone(),
            tables: g_config.tables.clone(),
        }
    }

    pub fn transition_rules() -> impl Iterator<Item = ([u32; 3], u32)> + Clone {
        let i1 = TRANSMAP
            .iter()
            .copied()
            .map(|(a, b)| ([a as u32, b as u32, 0], CtrlTransitionKind::Mpt as u32));
        let i2 = OPMAP.iter().copied().map(|(a, b, c)| {
            (
                [a as u32, b as u32, c as u32],
                CtrlTransitionKind::Operation as u32,
            )
        });
        i1.chain(i2)
    }

    /*    pub fn init<Fp: FieldExt>(&self, layouter: &mut impl Layouter<Fp>) -> Result<(), Error> {
        self.tables
            .fill_constant(layouter, Self::transition_rules())
    }*/

    /// assign data and enable flag for MPT circuit
    pub fn assign<Fp: FieldExt>(
        &self,
        region: &mut Region<'_, Fp>,
        offset: usize,
        data: &SingleOp<Fp>,
    ) -> Result<usize, Error> {
        let ctrl_type = data.ctrl_type();
        let old_path_chip =
            PathChip::<Fp>::construct(self.old_path.clone(), offset, &data.old, Some(&ctrl_type));
        let new_path_chip =
            PathChip::<Fp>::construct(self.new_path.clone(), offset, &data.new, Some(&ctrl_type));
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
                || Value::known(Fp::one()),
            )?;
        }

        Ok(op_end)
    }
}

/*
fn lagrange_polynomial_for_hashtype<Fp: FieldExt, const T: usize>(
    ref_n: Expression<Fp>,
) -> Expression<Fp> {
    super::lagrange_polynomial::<Fp, T, 5 /* last Type: Leaf */>(ref_n)
}
*/

const HASH_TYPE_CNT: usize = 6;

#[derive(Clone, Debug)]
struct PathChipConfig {
    s_path: Column<Advice>,
    hash_type: Column<Advice>,
    s_hash_type: [Column<Advice>; HASH_TYPE_CNT],
    s_match_ctrl_type: Column<Advice>,
    s_match_ctrl_aux: Column<Advice>,
    val: Column<Advice>,
}

/// chip for verify mutiple merkle path in MPT
/// it do not need any auxiliary cols
struct PathChip<'d, F: FieldExt> {
    offset: usize,
    config: PathChipConfig,
    data: &'d MPTPath<F>,
    ref_ctrl_type: Option<&'d [HashType]>,
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
        let s_path = g_config.s_path;
        let s_enable = g_config.s_enable;
        let s_hash_type = g_config.s_ctrl_type;
        let hash_type = if from_old {
            g_config.old_hash_type
        } else {
            g_config.new_hash_type
        };
        let s_match_ctrl_type = if from_old {
            g_config.s_hash_match_ctrl[0]
        } else {
            g_config.s_hash_match_ctrl[1]
        };
        let s_match_ctrl_aux = if from_old {
            g_config.s_hash_match_ctrl_aux[0]
        } else {
            g_config.s_hash_match_ctrl_aux[1]
        };
        let val = if from_old {
            g_config.old_val
        } else {
            g_config.new_val
        };
        //let key = g_config.acc_key;
        let ext_sibling_val = val;
        let key_immediate = g_config.key_aux;
        let hash_table = &g_config.hash_table;

        let s_row = g_config.s_row;
        let sibling = g_config.sibling;
        let path = g_config.path;
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
            let s_hash_type_not_match = Expression::Constant(Fp::one())
                - meta.query_advice(s_match_ctrl_type, Rotation::cur());
            let s_path = meta.query_advice(s_enable, Rotation::cur())
                * (meta.query_advice(s_hash_type[HashType::Middle as usize], Rotation::cur())
                    + s_hash_type_not_match.clone()
                        * meta.query_advice(
                            s_hash_type[HashType::LeafExt as usize],
                            Rotation::cur(),
                        )
                    + s_hash_type_not_match
                        * meta.query_advice(
                            s_hash_type[HashType::LeafExtFinal as usize],
                            Rotation::cur(),
                        )); //hash type is Middle: i.e ctrl type is Middle or (Ext and ExtFinal and not match)

            let path_bit = meta.query_advice(path, Rotation::cur());
            let val_col = meta.query_advice(val, Rotation::cur());
            let sibling_col = meta.query_advice(sibling, Rotation::cur());
            let node_hash = meta.query_advice(val, Rotation::prev());

            hash_table.build_lookup(
                meta,
                s_path,
                path_bit.clone() * (sibling_col.clone() - val_col.clone()) + val_col.clone(),
                path_bit * (val_col - sibling_col.clone()) + sibling_col,
                node_hash,
            )
        });

        // calculate part of the leaf hash: hash(key_immediate, val) = hash_of_key_node
        meta.lookup_any("mpt leaf hash", |meta| {
            let s_leaf = meta.query_advice(s_enable, Rotation::cur())
                * meta.query_advice(s_match_ctrl_type, Rotation::cur())
                * meta.query_advice(s_hash_type[HashType::Leaf as usize], Rotation::cur()); //(actually) Leaf

            let key_immediate = meta.query_advice(key_immediate, Rotation::cur());
            let leaf_val = meta.query_advice(val, Rotation::cur());
            let leaf_hash = meta.query_advice(val, Rotation::prev());
            hash_table.build_lookup(meta, s_leaf, key_immediate, leaf_val, leaf_hash)
        });

        //transition, notice the start status is ensured outside of the gadget
        meta.lookup("mpt type trans", |meta| {
            let s_not_begin = Expression::Constant(Fp::one())
                - meta.query_advice(s_hash_type[HashType::Start as usize], Rotation::cur()); //not Start

            let s_block_enable = meta.query_advice(s_enable, Rotation::cur()) * s_not_begin;

            trans_table.build_lookup(
                s_block_enable,
                meta.query_advice(hash_type, Rotation::prev()),
                meta.query_advice(hash_type, Rotation::cur()),
                CtrlTransitionKind::Mpt as u64,
            )
        });

        meta.create_gate("leaf extended", |meta| {
            let enable = meta.query_selector(s_row) * meta.query_advice(s_enable, Rotation::cur());
            let s_extended = meta.query_advice(s_match_ctrl_type, Rotation::cur())
                * meta.query_advice(s_hash_type[HashType::LeafExt as usize], Rotation::cur()); //(actually) LeafExt
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
            let s_last_extended = meta.query_advice(s_match_ctrl_type, Rotation::cur())
                * meta.query_advice(
                    s_hash_type[HashType::LeafExtFinal as usize],
                    Rotation::cur(),
                ); //(actually) LeafExtFinal

            // + sibling must be previous value of val when hash_type is leaf extended final
            // (notice the value for leafExtendedFinal can be omitted)
            vec![
                enable
                    * s_last_extended
                    * (meta.query_advice(sibling, Rotation::cur())
                        - meta.query_advice(val, Rotation::prev())),
            ]
        });

        // prove the silbing is really a leaf when extended
        meta.lookup_any("extended sibling proof 1", |meta| {
            let s_last_extended = meta.query_advice(s_enable, Rotation::cur())
                * meta.query_advice(s_match_ctrl_type, Rotation::cur())
                * meta.query_advice(
                    s_hash_type[HashType::LeafExtFinal as usize],
                    Rotation::cur(),
                ); //(actually) LeafExtFinal
            let key_proof = meta.query_advice(sibling, Rotation::next()); //key is written here
            let key_proof_immediate = meta.query_advice(key_immediate, Rotation::cur());

            hash_table.build_lookup(
                meta,
                s_last_extended,
                Expression::Constant(Fp::one()),
                key_proof,
                key_proof_immediate,
            )
        });

        meta.lookup_any("extended sibling proof 2", |meta| {
            let s_last_extended = meta.query_advice(s_enable, Rotation::cur())
                * meta.query_advice(s_match_ctrl_type, Rotation::cur())
                * meta.query_advice(
                    s_hash_type[HashType::LeafExtFinal as usize],
                    Rotation::cur(),
                ); //(actually) LeafExtFinal
            let extended_sibling = meta.query_advice(sibling, Rotation::cur());
            let key_proof_immediate = meta.query_advice(key_immediate, Rotation::cur());
            let key_proof_value = meta.query_advice(ext_sibling_val, Rotation::cur());

            hash_table.build_lookup(
                meta,
                s_last_extended,
                key_proof_immediate,
                key_proof_value,
                extended_sibling,
            )
        });

        PathChipConfig {
            s_path,
            hash_type,
            s_hash_type,
            s_match_ctrl_type,
            s_match_ctrl_aux,
            val,
        }
    }

    fn construct(
        config: PathChipConfig,
        offset: usize,
        data: &'d <Self as Chip<Fp>>::Loaded,
        ref_ctrl_type: Option<&'d [HashType]>,
    ) -> Self {
        Self {
            config,
            offset,
            data,
            ref_ctrl_type,
        }
    }

    fn assign(&self, region: &mut Region<'_, Fp>) -> Result<usize, Error> {
        let config = &self.config;
        let offset = self.offset;
        let vals = &self.data.hashes;
        let hash_types = &self.data.hash_types;
        assert_eq!(hash_types.len(), vals.len());

        for (index, (hash_type, val)) in hash_types.iter().copied().zip(vals.iter()).enumerate() {
            region.assign_advice(|| "val", config.val, offset + index, || Value::known(*val))?;
            region.assign_advice(
                || format!("hash_type {}", hash_type as u32),
                config.hash_type,
                offset + index,
                || Value::known(Fp::from(hash_type as u64)),
            )?;
            region.assign_advice(
                || format!("hash_type {}", hash_type as u32),
                config.hash_type,
                offset + index,
                || Value::known(Fp::from(hash_type as u64)),
            )?;
            region.assign_advice(
                || "sel",
                config.s_path,
                offset + index,
                || {
                    Value::known(match hash_type {
                        HashType::Start | HashType::Empty | HashType::Leaf => Fp::zero(),
                        _ => Fp::one(),
                    })
                },
            )?;
        }

        let ref_ctrl_type = self
            .ref_ctrl_type
            .unwrap_or(&self.data.hash_types)
            .iter()
            .copied();
        for (index, (hash_type, ref_type)) in
            hash_types.iter().copied().zip(ref_ctrl_type).enumerate()
        {
            region.assign_advice(
                || "hash_type match aux",
                config.s_match_ctrl_aux,
                offset + index,
                || {
                    Value::known(
                        Fp::from(ref_type as u64 - hash_type as u64)
                            .invert()
                            .unwrap_or_else(Fp::zero),
                    )
                },
            )?;
            region.assign_advice(
                || "hash_type match",
                config.s_match_ctrl_type,
                offset + index,
                || {
                    Value::known(if hash_type == ref_type {
                        Fp::one()
                    } else {
                        Fp::zero()
                    })
                },
            )?;
        }

        Ok(offset + hash_types.len())
    }
}

#[derive(Clone, Debug)]
struct OpChipConfig {
    ctrl_type: Column<Advice>,
    s_ctrl_type: [Column<Advice>; HASH_TYPE_CNT],
    sibling: Column<Advice>,
    path: Column<Advice>,
    depth: Column<Advice>,
    acc_key: Column<Advice>,
    key_aux: Column<Advice>,
}

/// chip for verify mutiple merkle path in MPT
/// it do not need any auxiliary cols
struct OpChip<'d, F: FieldExt> {
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
        let key_aux = g_config.key_aux;
        let ctrl_type = g_config.ctrl_type;
        let s_ctrl_type = g_config.s_ctrl_type;

        let s_row = g_config.s_row;
        let s_enable = g_config.s_enable;
        let s_path = g_config.s_path;

        let type_table = &g_config.tables;

        let hash_table = &g_config.hash_table;

        //old - new
        meta.lookup("op update trans", |meta| {
            type_table.build_lookup(
                meta.query_advice(s_enable, Rotation::cur()),
                meta.query_advice(old_hash_type, Rotation::cur()),
                meta.query_advice(new_hash_type, Rotation::cur()),
                CtrlTransitionKind::Operation as u64,
            )
        });

        meta.create_gate("s_path and path bit", |meta| {
            let enable = meta.query_selector(s_row) * meta.query_advice(s_enable, Rotation::cur());
            let s_path = meta.query_advice(s_path, Rotation::cur());
            let s_path_not_opened = Expression::Constant(Fp::one()) - s_path.clone();

            let path = meta.query_advice(path, Rotation::cur());
            let path_bit = (Expression::Constant(Fp::one()) - path.clone()) * path;

            let hash_type = meta.query_advice(old_hash_type, Rotation::cur());
            let not_path_type = (hash_type.clone()
                - Expression::Constant(Fp::from(HashType::Empty as u64)))
                * (hash_type.clone() - Expression::Constant(Fp::from(HashType::Leaf as u64)))
                * (hash_type - Expression::Constant(Fp::from(HashType::Start as u64)));

            // s_path ∈ {0, 1}
            // s_path is not open when hash_type is "start" / "leaf" / "empty"
            // when s_path is 1, path ∈ {0, 1}
            vec![
                enable.clone()
                    * (Expression::Constant(Fp::one()) - s_path.clone())
                    * s_path.clone(),
                enable.clone() * not_path_type * s_path_not_opened,
                enable * s_path * path_bit,
            ]
        });

        meta.create_gate("depth", |meta| {
            let enable = meta.query_selector(s_row) * meta.query_advice(s_enable, Rotation::cur());
            let s_begin = meta.query_advice(s_ctrl_type[HashType::Start as usize], Rotation::cur()); //Start
            let path = meta.query_advice(path, Rotation::cur());
            let depth_aux_start = meta.query_advice(depth_aux, Rotation::cur())
                - Expression::Constant(Fp::one().double().invert().unwrap());
            let depth_aux_common = meta.query_advice(depth_aux, Rotation::cur())
                - meta.query_advice(depth_aux, Rotation::prev())
                    * Expression::Constant(Fp::from(2u64));
            let key_acc = meta.query_advice(acc_key, Rotation::cur())
                - (meta.query_advice(acc_key, Rotation::prev())
                    + path * meta.query_advice(depth_aux, Rotation::cur()));

            // for any row which is not s_begin: depth_aux == depth_aux.prev * 2
            // for row at the beginning, depth_aux must be 1/2
            // for row at the beginning, acc_key must be 0
            // for row not beginning, acc_key is path * depth_aux + acc_key_prev
            vec![
                enable.clone() * s_begin.clone() * depth_aux_start,
                enable.clone()
                    * (Expression::Constant(Fp::one()) - s_begin.clone())
                    * depth_aux_common,
                enable.clone() * s_begin.clone() * meta.query_advice(acc_key, Rotation::cur()),
                enable * (Expression::Constant(Fp::one()) - s_begin) * key_acc,
            ]
        });

        meta.lookup_any("mpt key pre calc", |meta| {
            let s_leaf = meta.query_advice(s_enable, Rotation::cur())
                * meta.query_advice(s_ctrl_type[HashType::Leaf as usize], Rotation::cur()); //Leaf

            let key = meta.query_advice(acc_key, Rotation::cur());
            let key_immediate = meta.query_advice(key_aux, Rotation::cur());
            hash_table.build_lookup(
                meta,
                s_leaf,
                Expression::Constant(Fp::one()),
                key,
                key_immediate,
            )
        });

        OpChipConfig {
            ctrl_type,
            s_ctrl_type,
            path,
            sibling,
            depth: depth_aux,
            acc_key,
            key_aux,
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
        let ctrl_type = self.data.ctrl_type();
        let mut offset = self.offset;
        region.assign_advice(
            || "path padding",
            config.path,
            offset,
            || Value::known(Fp::zero()),
        )?;
        region.assign_advice(
            || "acckey padding",
            config.acc_key,
            offset,
            || Value::known(Fp::zero()),
        )?;
        region.assign_advice(
            || "depth padding",
            config.depth,
            offset,
            || Value::known(Fp::one().double().invert().unwrap()),
        )?;
        region.assign_advice(
            || "sibling padding",
            config.sibling,
            offset,
            || Value::known(Fp::zero()),
        )?;
        region.assign_advice(
            || "op type start",
            config.ctrl_type,
            offset,
            || Value::known(Fp::from(ctrl_type[0] as u64)),
        )?;
        region.assign_advice(
            || "enabling s_op",
            config.s_ctrl_type[ctrl_type[0] as usize],
            offset,
            || Value::known(Fp::one()),
        )?;

        region.assign_advice(
            || "sibling padding",
            config.sibling,
            offset,
            || Value::known(Fp::zero()),
        )?;

        offset += 1;

        let mut cur_depth = Fp::one();
        let mut acc_key = Fp::zero();

        let extend_proof = self.data.extended_proof();

        for (index, (path, sibling)) in paths.iter().zip(siblings.iter()).enumerate() {
            acc_key = *path * cur_depth + acc_key;

            region.assign_advice(|| "path", config.path, offset, || Value::known(*path))?;
            region.assign_advice(
                || "acckey",
                config.acc_key,
                offset,
                || Value::known(acc_key),
            )?;
            region.assign_advice(|| "depth", config.depth, offset, || Value::known(cur_depth))?;
            region.assign_advice(
                || "sibling",
                config.sibling,
                offset,
                || Value::known(*sibling),
            )?;
            // currently we simply fill key_aux col with extend_proof (if any)
            region.assign_advice(
                || "ext proof key immediate",
                config.key_aux,
                offset,
                || Value::known(extend_proof.map(|pf| pf.1).unwrap_or_default()),
            )?;
            region.assign_advice(
                || "ctrl type",
                config.ctrl_type,
                offset,
                || Value::known(Fp::from(ctrl_type[index + 1] as u64)),
            )?;
            region.assign_advice(
                || "enabling s_op",
                config.s_ctrl_type[ctrl_type[index + 1] as usize],
                offset,
                || Value::known(Fp::one()),
            )?;

            cur_depth = cur_depth.double();
            offset += 1;
        }

        // final line
        let ctrl_type = *ctrl_type.last().expect("always has at least 2 rows");
        region.assign_advice(
            || "op type",
            config.ctrl_type,
            offset,
            || Value::known(Fp::from(ctrl_type as u64)),
        )?;
        region.assign_advice(
            || "enabling s_op",
            config.s_ctrl_type[ctrl_type as usize],
            offset,
            || Value::known(Fp::one()),
        )?;
        region.assign_advice(
            || "path",
            config.path,
            offset,
            || Value::known(self.data.key_residual),
        )?;
        region.assign_advice(
            || "key final",
            config.acc_key,
            offset,
            || Value::known(self.data.key),
        )?;
        region.assign_advice(
            || "key hash aux: immediate",
            config.key_aux,
            offset,
            || Value::known(self.data.key_immediate),
        )?;
        region.assign_advice(|| "depth", config.depth, offset, || Value::known(cur_depth))?;
        region.assign_advice(
            || "sibling last (key for extended or padding)",
            config.sibling,
            offset,
            || Value::known(extend_proof.map(|pf| pf.0).unwrap_or_default()),
        )?;

        Ok(offset + 1)
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
    const MAX_KEY: usize = 2_usize.pow(MAX_PATH_DEPTH as u32);

    impl MPTOpConfig {
        /// assign all required cols directly
        pub fn create(meta: &mut ConstraintSystem<Fp>) -> Self {
            Self {
                s_row: meta.complex_selector(),
                s_enable: meta.advice_column(),
                ctrl_type: meta.advice_column(),
                s_ctrl_type: [(); HASH_TYPE_CNT].map(|_| meta.advice_column()),
                s_hash_match_ctrl: [(); 2].map(|_| meta.advice_column()),
                s_hash_match_ctrl_aux: [(); 2].map(|_| meta.advice_column()),
                s_path: meta.advice_column(),
                sibling: meta.advice_column(),
                depth: meta.advice_column(),
                acc_key: meta.advice_column(),
                path: meta.advice_column(),
                old_hash_type: meta.advice_column(),
                new_hash_type: meta.advice_column(),
                old_val: meta.advice_column(),
                new_val: meta.advice_column(),
                key_aux: meta.advice_column(),
                hash_table: HashTable::configure_create(meta),
                tables: MPTOpTables::configure_create(meta),
            }
        }

        /// simply flush a row with 0 value to avoid gate poisoned / cell error in debug prover,
        pub fn flush_row(&self, region: &mut Region<'_, Fp>, offset: usize) -> Result<(), Error> {
            for rand_flush_col in [
                self.s_path,
                self.ctrl_type,
                self.depth,
                self.sibling,
                self.key_aux,
                self.acc_key,
                self.path,
                self.old_hash_type,
                self.new_hash_type,
                self.old_val,
                self.new_val,
            ] {
                region.assign_advice(
                    || "rand flushing",
                    rand_flush_col,
                    offset,
                    || Value::known(rand_fp()),
                )?;
            }

            for zero_flush_col in [self.s_enable]
                .into_iter()
                .chain(self.s_ctrl_type)
                .chain(self.s_hash_match_ctrl)
                .chain(self.s_hash_match_ctrl_aux)
            {
                region.assign_advice(
                    || "zero flushing",
                    zero_flush_col,
                    offset,
                    || Value::known(Fp::zero()),
                )?;
            }

            Ok(())
        }
    }

    #[derive(Clone, Debug)]
    struct MPTTestConfig {
        global: MPTOpConfig,
        chip: PathChipConfig,
    }

    // express for a single path block
    #[derive(Clone)]
    struct TestPathCircuit<const USE_OLD: bool> {
        key_immediate: Fp,
        key_residue: Fp,
        path: Vec<Fp>,
        siblings: Vec<Fp>,
        data: MPTPath<Fp>,
    }

    impl<const USE_OLD: bool> Circuit<Fp> for TestPathCircuit<USE_OLD> {
        type Config = MPTTestConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            self.clone()
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
            let mpt_chip = PathChip::<Fp>::construct(chip_cfg, offset, &self.data, None);
            layouter.assign_region(
                || "main",
                |mut region| {
                    let config = &config.global;
                    config.flush_row(&mut region, 0)?;
                    let mut working_offset = offset;
                    //enable, flush the whole of working region and ctrl flag
                    for (index, hash_type) in self.data.hash_types.iter().copied().enumerate() {
                        config.s_row.enable(&mut region, working_offset + index)?;
                        config.flush_row(&mut region, working_offset + index)?;
                        region.assign_advice(
                            || "enable",
                            config.s_ctrl_type[hash_type as usize],
                            working_offset + index,
                            || Value::known(Fp::one()),
                        )?;
                    }
                    region.assign_advice(
                        || "enable",
                        config.s_enable,
                        working_offset,
                        || Value::known(Fp::one()),
                    )?;

                    working_offset += 1;
                    let next_offset = working_offset + self.siblings.len();
                    //need to fill some other cols
                    for (index, offset) in (working_offset..next_offset).enumerate() {
                        region.assign_advice(
                            || "enable",
                            config.s_enable,
                            offset,
                            || Value::known(Fp::one()),
                        )?;
                        region.assign_advice(
                            || "sibling",
                            config.sibling,
                            offset,
                            || Value::known(self.siblings[index]),
                        )?;
                        region.assign_advice(
                            || "path",
                            config.path,
                            offset,
                            || Value::known(self.path[index]),
                        )?;
                    }

                    for (col, val, tip) in [
                        (config.s_enable, Fp::one(), "enable"),
                        (config.path, self.key_residue, "path"),
                        (config.sibling, Fp::zero(), "sibling"),
                        (config.key_aux, self.key_immediate, "key"),
                    ] {
                        region.assign_advice(|| tip, col, next_offset, || Value::known(val))?;
                    }

                    let next_offset = next_offset + 1;
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
                    .map(|(a, b)| ([*a as u32, *b as u32, 0], CtrlTransitionKind::Mpt as u32)),
            )?;

            config
                .global
                .hash_table
                .dev_fill(&mut layouter, self.data.hash_traces.iter())?;

            Ok(())
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
            let data = MPTPath::<Fp>::create_with_hasher(
                &path_bits,
                &siblings,
                Fp::from(key as u64),
                Some(leaf),
                mock_hash,
            );
            let path: Vec<Fp> = path_bits
                .into_iter()
                .map(|not_zero| if not_zero { Fp::one() } else { Fp::zero() })
                .collect();

            Self {
                key_immediate: data.key_immediate().unwrap(),
                key_residue: Fp::from(rev_path as u64),
                data,
                path,
                siblings,
            }
        }
    }

    #[test]
    fn path_gadget_degrees() {
        let mut cs: ConstraintSystem<Fp> = Default::default();
        TestPathCircuit::<true>::configure(&mut cs);

        println!("mpt path gadget degree: {}", cs.degree());
        assert!(cs.degree() <= 9);
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

    #[derive(Clone, Debug)]
    struct OpTestConfig {
        global: MPTOpConfig,
        chip: OpChipConfig,
    }

    // express for a single path block
    #[derive(Clone)]
    struct TestOpCircuit {
        data: SingleOp<Fp>,
    }

    impl Circuit<Fp> for TestOpCircuit {
        type Config = OpTestConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            self.clone()
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
            let op_chip = OpChip::<Fp>::construct(chip_cfg, offset, &self.data);
            layouter.assign_region(
                || "main",
                |mut region| {
                    let config = &config.global;
                    let next_offset = offset + self.data.old.hash_types.len();
                    //flush working region and ctrl flags
                    for offset in 0..next_offset {
                        config.flush_row(&mut region, offset)?;
                    }

                    //need to fill some other cols
                    for (index, offset) in (offset..next_offset).enumerate() {
                        config.s_row.enable(&mut region, offset)?;
                        region.assign_advice(
                            || "enable",
                            config.s_enable,
                            offset,
                            || Value::known(Fp::one()),
                        )?;
                        region.assign_advice(
                            || "s_path",
                            config.s_path,
                            offset,
                            || {
                                Value::known(match self.data.old.hash_types[index] {
                                    HashType::Empty | HashType::Leaf | HashType::Start => {
                                        Fp::zero()
                                    }
                                    _ => Fp::one(),
                                })
                            },
                        )?;
                        region.assign_advice(
                            || "old hash_type",
                            config.old_hash_type,
                            offset,
                            || Value::known(Fp::from(self.data.old.hash_types[index] as u64)),
                        )?;
                        region.assign_advice(
                            || "new hash_type",
                            config.new_hash_type,
                            offset,
                            || Value::known(Fp::from(self.data.new.hash_types[index] as u64)),
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
                OPMAP.iter().map(|(a, b, c)| {
                    (
                        [*a as u32, *b as u32, *c as u32],
                        CtrlTransitionKind::Operation as u32,
                    )
                }),
            )?;

            // op chip now need hash table (for key hash lookup)
            config.global.hash_table.dev_fill(
                &mut layouter,
                self.data
                    .old
                    .hash_traces
                    .iter()
                    .chain([(Fp::one(), self.data.key, Fp::zero())].iter()), //dummy for key calc
            )?;

            Ok(())
        }
    }

    impl TestOpCircuit {
        fn from_op(op: SingleOp<Fp>) -> Self {
            Self { data: op }
        }
    }

    #[test]
    fn op_gadget_degrees() {
        let mut cs: ConstraintSystem<Fp> = Default::default();
        TestOpCircuit::configure(&mut cs);

        println!("mpt op gadget degree: {}", cs.degree());
        assert!(cs.degree() <= 9);
    }

    lazy_static! {

        static ref DEMOCIRCUIT1: TestOpCircuit = {
            TestOpCircuit {
                data: SingleOp::<Fp>{
                    siblings: Vec::new(),
                    path: Vec::new(),
                    key: Fp::from(4u64),
                    key_residual: Fp::from(4u64),
                    old: MPTPath::<Fp>{
                        hash_traces: vec![(Fp::one(), Fp::from(4u64), Fp::zero())],
                        hash_types: vec![HashType::Start, HashType::Empty],
                        ..Default::default()
                    },
                    new: MPTPath::<Fp> {
                        hash_types: vec![HashType::Start, HashType::Leaf],
                        ..Default::default()
                    },
                    ..Default::default()
                },
            }
        };

        static ref DEMOCIRCUIT2: TestOpCircuit = {
            TestOpCircuit {
                data: SingleOp::<Fp>{
                    siblings: vec![Fp::from(11u64)],
                    path: vec![Fp::one()],
                    key: Fp::from(17u64), //0b10001u64
                    key_residual: Fp::from(8u64),
                    old: MPTPath::<Fp>{
                        hash_traces: vec![(Fp::one(), Fp::from(9u64), Fp::zero())],
                        hash_types: vec![HashType::Start, HashType::LeafExtFinal, HashType::Empty],
                        ..Default::default()
                    },
                    new: MPTPath::<Fp> {
                        hash_types: vec![HashType::Start, HashType::Middle, HashType::Leaf],
                        ..Default::default()
                    },
                    ..Default::default()
                },
            }
        };

        static ref DEMOCIRCUIT3: TestOpCircuit = {
            TestOpCircuit {
                data: SingleOp::<Fp>{
                    siblings: vec![Fp::from(11u64), Fp::zero(), Fp::from(22u64)],
                    path: vec![Fp::one(), Fp::zero(), Fp::one()],
                    key: Fp::from(45u64), //0b101101u64
                    key_residual: Fp::from(5u64),
                    old: MPTPath::<Fp>{
                        hash_traces: vec![(Fp::one(), Fp::from(45u64), Fp::zero())],
                        hash_types: vec![
                            HashType::Start,
                            HashType::Middle,
                            HashType::LeafExt,
                            HashType::LeafExtFinal,
                            HashType::Empty,
                        ],
                        ..Default::default()
                    },
                    new: MPTPath::<Fp> {
                        hash_types: vec![
                            HashType::Start,
                            HashType::Middle,
                            HashType::Middle,
                            HashType::Middle,
                            HashType::Leaf,
                        ],
                        ..Default::default()
                    },
                    ..Default::default()
                },
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
    fn rand_case_op() {
        let op = SingleOp::<Fp>::create_rand_op(3, None, None, mock_hash);

        let k = 5;
        let circuit = TestOpCircuit { data: op };
        let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[derive(Clone, Debug)]
    struct GadgetTestConfig {
        gadget: MPTOpGadget,
        sel: Selector,
        free_cols: Vec<Column<Advice>>,
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
            let free_cols: Vec<_> = (0..(8 + //exported
                MPTOpGadget::min_ctrl_types() +
                MPTOpGadget::min_free_cols()))
                .map(|_| meta.advice_column())
                .collect();
            let exported_cols = &free_cols[0..8];
            let op_flag_cols = &free_cols[8..8 + MPTOpGadget::min_ctrl_types()];

            GadgetTestConfig {
                gadget: MPTOpGadget::configure_simple(
                    meta,
                    sel,
                    exported_cols,
                    op_flag_cols,
                    &free_cols[8 + MPTOpGadget::min_ctrl_types()..],
                    None,
                ),
                free_cols,
                sel,
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            config
                .gadget
                .tables
                .fill_constant(&mut layouter, MPTOpGadget::transition_rules())?;
            config
                .gadget
                .hash_table
                .dev_fill(&mut layouter, self.data.hash_traces())?;

            layouter.assign_region(
                || "mpt",
                |mut region| {
                    //flush all row required by data, just avoid Cell error ...
                    for offset in 0..(1 + self.data.use_rows()) {
                        config.free_cols.iter().try_for_each(|col| {
                            region
                                .assign_advice(
                                    || "flushing",
                                    *col,
                                    offset,
                                    || Value::known(Fp::zero()),
                                )
                                .map(|_| ())
                        })?;
                    }

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
    fn gadget_degrees() {
        let mut cs: ConstraintSystem<Fp> = Default::default();
        MPTTestCircuit::configure(&mut cs);

        println!("mpt full gadget degree: {}", cs.degree());
        assert!(cs.degree() <= 9);
    }

    #[test]
    fn rand_case_gadget() {
        let op = SingleOp::<Fp>::create_rand_op(5, None, None, mock_hash);

        let k = 6;
        let circuit = MPTTestCircuit::from(op);

        #[cfg(feature = "print_layout")]
        {
            let path = "layouts/mptgadget_layout.png";
            print_layout!(&path, k, &circuit);
        }

        let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
