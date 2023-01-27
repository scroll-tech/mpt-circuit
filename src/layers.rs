//! Organize gadgets on single op and put them into a multi-layer circuits which verify many operations in a time
//! basically we export some col inside an gadget and make layout which organize mutiple of them
//! see <https://hackmd.io/PcoaHMh6RXS-Js1OYzutMQ>
//
// ### Any gadgets dedicated to specified op on MPT can be wrapped like:
//
// | ---- | --------- | --------- | --------- | --------- | --------- | --- | ------- | --------|--------|-------- |
// | Rows |   series  |  op_type  | ctrl_type |  1_enable |  2_enable | ... | data_0  | data_1  | data_2 |root_aux |
// | ---- | --------- | --------- | --------- | --------- | --------- | --- | ------- | --------|--------|-------- |
// |  1   |     1     |     1     |   start   |     1     |     0     |     |   old1  |   root1 |        |  root1  |
// |  2   |     1     |     1     |   leaf    |     1     |     0     |     |         |         |        |  root1  |
// |  3   |     1     |     2     |    ...    |     0     |     1     |     |         |         |        |  root1  |
// |  4   |     1     |     3     |   leaf    |     0     |     0     |     |         |         |        |  root1  |
// |  5   |     2     |     1     |   start   |     1     |     0     |     |  root1  |   root2 |        |  root2  |
// | ---- | --------- | --------- | --------- | --------- | --------- | --- | ------- | --------|--------|-------- |
//
// The series indicate an op and op_type indicate specified operation step, each step has its own layout
// on the circuit and enabled by a flag, sequence of operations would be laid on continuous rows in the
// circuit and we also call the rows for one step an "op block".

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector, TableColumn},
    poly::Rotation,
};

// help organize an op block, the transition of steps is controlled by a constant lookup table
// notice LayerGadget require constant constraintion (query one fixed_col and call enable_constant on it)
#[derive(Clone, Debug)]
pub(crate) struct LayerGadget {
    sel: Selector,
    series: Column<Advice>,
    op_type: Column<Advice>,
    // instead of the map, we simply use an array to save steps involved inside an op block
    // notice it is the response that step gadget constraint it to be boolean, and enable
    // its flag when assigned
    s_stepflags: Vec<Column<Advice>>,
    ctrl_type: Column<Advice>,
    // the s_ctrl_type is supposed to be a series of integers start from 0 and each of the number
    // is represented the corresponding items in s_ctrl_type array in which the number is just
    // its index
    s_ctrl_type: Vec<Column<Advice>>,
    // the 3 exported value now can be represented by 2-field and the additional
    // field is marked as "ext" (most value still use 1 field only)
    data_0: Column<Advice>,
    data_1: Column<Advice>,
    data_2: Column<Advice>,

    data_0_ext: Column<Advice>,
    data_1_ext: Column<Advice>,
    data_2_ext: Column<Advice>,

    old_root_index: Column<Advice>,
    new_root_index: Column<Advice>,
    address_index: Column<Advice>,

    free_cols: Vec<Column<Advice>>,

    op_delta_aux: Column<Advice>,

    control_table: [TableColumn; 5],
}

pub(crate) type OpBorder = ((u32, u32), (u32, u32));

impl LayerGadget {
    pub fn exported_cols(&self, step: u32) -> [Column<Advice>; 8] {
        [
            self.ctrl_type,
            self.s_stepflags[step as usize],
            self.data_0,
            self.data_1,
            self.data_2,
            self.data_0_ext,
            self.data_1_ext,
            self.data_2_ext,
        ]
    }

    pub fn get_ctrl_type_flags(&self) -> &[Column<Advice>] {
        &self.s_ctrl_type
    }

    pub fn get_free_cols(&self) -> &[Column<Advice>] {
        &self.free_cols
    }

    // obtain the index col for start and end root value
    pub fn get_root_indexs(&self) -> (Column<Advice>, Column<Advice>) {
        (self.old_root_index, self.new_root_index)
    }

    // obtain the index col for address value
    pub fn get_address_index(&self) -> Column<Advice> {
        self.address_index
    }

    pub fn get_gadget_index(&self) -> Column<Advice> {
        self.op_type
    }

    pub fn public_sel(&self) -> Selector {
        self.sel
    }

    pub fn configure<Fp: FieldExt>(
        meta: &mut ConstraintSystem<Fp>,
        steps: usize,
        required_cols: usize,
        minium_ctrl_types: usize,
    ) -> Self {
        assert!(steps > 0, "at least one step is required");
        assert!(minium_ctrl_types > 0, "at least one ctrl type is required");
        let s_stepflags: Vec<_> = (0..steps).map(|_| meta.advice_column()).collect();
        let free_cols: Vec<_> = (0..required_cols).map(|_| meta.advice_column()).collect();
        let s_ctrl_type: Vec<_> = (0..minium_ctrl_types)
            .map(|_| meta.advice_column())
            .collect();
        let sel = meta.complex_selector();
        let series = meta.advice_column();
        let op_type = meta.advice_column();
        let ctrl_type = meta.advice_column();
        let data_0 = meta.advice_column();
        let data_1 = meta.advice_column();
        let data_2 = meta.advice_column();
        let data_0_ext = meta.advice_column();
        let data_1_ext = meta.advice_column();
        let data_2_ext = meta.advice_column();
        let old_root_index = meta.advice_column();
        let new_root_index = meta.advice_column();
        let address_index = meta.advice_column();
        let op_delta_aux = meta.advice_column();
        let control_table = [(); 5].map(|_| meta.lookup_table_column());

        // require permutation with constants
        meta.enable_equality(series);
        meta.enable_equality(op_type);
        meta.enable_equality(ctrl_type);

        meta.create_gate("series", |meta| {
            let sel = meta.query_selector(sel);
            let series_delta = meta.query_advice(series, Rotation::cur())
                - meta.query_advice(series, Rotation::prev());
            // delta ∈ {0, 1}
            vec![sel * (Expression::Constant(Fp::one()) - series_delta.clone()) * series_delta]
        });

        meta.create_gate("op transition", |meta| {
            let sel = meta.query_selector(sel);
            let op_delta = meta.query_advice(op_type, Rotation::cur())
                - meta.query_advice(op_type, Rotation::prev());
            let op_delta_aux = meta.query_advice(op_delta_aux, Rotation::cur());
            // map op_delta_aux so we can obtain 1 while delta is not zero
            vec![
                sel * (Expression::Constant(Fp::one()) - op_delta_aux * op_delta.clone())
                    * op_delta,
            ]
        });

        meta.create_gate("s_ctrl flags", |meta| {
            let sel = meta.query_selector(sel);
            // setting op flags:
            // all flags is boolean
            // one and at most one flag must be enabled
            // the enabled flas must match with op_type
            let s_ctrl: Vec<_> = s_ctrl_type
                .iter()
                .copied()
                .map(|col| meta.query_advice(col, Rotation::cur()))
                .collect();

            let bool_cond = s_ctrl.clone().into_iter().map(|col_exp| {
                sel.clone() * col_exp.clone() * (Expression::Constant(Fp::one()) - col_exp)
            });

            let one_flag_cond = s_ctrl
                .clone()
                .into_iter()
                .reduce(|exp, col_exp| exp + col_exp)
                .map(|sum_exp| sel.clone() * (Expression::Constant(Fp::one()) - sum_exp));

            let ctrl_type_cond = s_ctrl
                .into_iter()
                .enumerate()
                .map(|(idx, col_exp)| Expression::Constant(Fp::from(idx as u64)) * col_exp)
                .reduce(|exp, col_exp_with_idx| exp + col_exp_with_idx)
                .map(|w_sum_exp| {
                    sel.clone() * (meta.query_advice(ctrl_type, Rotation::cur()) - w_sum_exp)
                });

            let constraints = bool_cond
                .chain(one_flag_cond)
                .chain(ctrl_type_cond)
                .collect::<Vec<_>>();
            if constraints.is_empty() {
                vec![sel * Expression::Constant(Fp::zero())]
            } else {
                constraints
            }
        });

        meta.create_gate("index identical", |meta| {
            // constrain all index cols so the value in identical inside a block
            // and gadgets can add more constraint to the indexs

            let sel = meta.query_selector(sel);
            let series_delta = meta.query_advice(series, Rotation::cur())
                - meta.query_advice(series, Rotation::prev());

            Vec::from([old_root_index, new_root_index, address_index].map(|col| {
                sel.clone()
                    * (Expression::Constant(Fp::one()) - series_delta.clone())
                    * (meta.query_advice(col, Rotation::cur())
                        - meta.query_advice(col, Rotation::prev()))
            }))
        });

        meta.create_gate("flags", |meta| {
            let sel = meta.query_selector(sel);
            let total_flag = s_stepflags
                .iter()
                .fold(None, |acc, col| match acc {
                    Some(exp) => Some(exp + meta.query_advice(*col, Rotation::cur())),
                    None => Some(meta.query_advice(*col, Rotation::cur())),
                })
                .unwrap();

            let mut exps = Vec::new();
            //constrain all op type with its col
            for (step_index, col) in s_stepflags.iter().enumerate() {
                exps.push(
                    sel.clone()
                        * meta.query_advice(*col, Rotation::cur())
                        * (meta.query_advice(op_type, Rotation::cur())
                            - Expression::Constant(Fp::from(step_index as u64))),
                );
            }

            // notice all flag is constrainted to boolean, and total_flag is 1, so one and at most one col must be true
            // and only that flag whose op_type is corresponding to its step code can be true
            exps.push(sel * (Expression::Constant(Fp::one()) - total_flag));
            exps
        });

        // the main lookup for constrainting row layout
        // lookup opened under 2 conditions:
        // 1. series has zero-delta and op_type has non-zero delta
        // 2. series has non-zero-delta
        // under these condition the transition of op_type and ctrl_type would be
        // lookup from control_table
        meta.lookup("layer intra-block border rule", |meta| {
            // condition 1 (intra-block transition) is only actived when series has not change
            let series_delta_zero = Expression::Constant(Fp::one())
                - meta.query_advice(series, Rotation::cur())
                + meta.query_advice(series, Rotation::prev());
            let op_delta = meta.query_advice(op_type, Rotation::cur())
                - meta.query_advice(op_type, Rotation::prev());
            let enable =
                meta.query_advice(op_delta_aux, Rotation::cur()) * op_delta * series_delta_zero;

            let op_cur = enable.clone() * meta.query_advice(op_type, Rotation::cur());
            let ctrl_cur = enable.clone() * meta.query_advice(ctrl_type, Rotation::cur());
            let op_prev = enable.clone() * meta.query_advice(op_type, Rotation::prev());
            let ctrl_prev = enable * meta.query_advice(ctrl_type, Rotation::prev());

            vec![
                (op_cur, control_table[0]),
                (ctrl_cur, control_table[1]),
                (op_prev, control_table[2]),
                (ctrl_prev, control_table[3]),
                (Expression::Constant(Fp::zero()), control_table[4]),
            ]
        });

        meta.lookup("layer inter-block border rule", |meta| {
            // condition 2 (inter-block transition)
            let series_delta = meta.query_advice(series, Rotation::cur())
                - meta.query_advice(series, Rotation::prev());
            let enable = meta.query_selector(sel) * series_delta;

            let op_cur = enable.clone() * meta.query_advice(op_type, Rotation::cur());
            let ctrl_cur = enable.clone() * meta.query_advice(ctrl_type, Rotation::cur());
            let op_prev = enable.clone() * meta.query_advice(op_type, Rotation::prev());
            let ctrl_prev = enable * meta.query_advice(ctrl_type, Rotation::prev());

            vec![
                (op_cur, control_table[0]),
                (ctrl_cur, control_table[1]),
                (op_prev, control_table[2]),
                (ctrl_prev, control_table[3]),
                (Expression::Constant(Fp::one()), control_table[4]),
            ]
        });

        Self {
            sel,
            series,
            s_stepflags,
            s_ctrl_type,
            op_type,
            ctrl_type,
            data_0,
            data_1,
            data_2,
            data_0_ext,
            data_1_ext,
            data_2_ext,
            free_cols,
            old_root_index,
            new_root_index,
            address_index,
            op_delta_aux,
            control_table,
        }
    }

    // an unique transition (start_op_code, 0) -> (<op type>, <ctrl type>) would be put in inter-op-block table
    // automatically to specify how the circuit starts
    pub fn start_op_code(&self) -> u32 {
        self.s_stepflags.len() as u32
    }

    // LayerGadget must be first assigned, with other gadgets start from the offset it has returned
    pub fn assign<Fp: FieldExt>(
        &self,
        region: &mut Region<'_, Fp>,
        max_rows: usize,
        init_root: Fp,
    ) -> Result<usize, Error> {
        // current we flush the first row, and start other circuits's assignation from row 1
        self.free_cols.iter().try_for_each(|col| {
            region
                .assign_advice(|| "flushing", *col, 0, || Value::known(Fp::zero()))
                .map(|_| ())
        })?;
        self.s_stepflags.iter().try_for_each(|col| {
            region
                .assign_advice(|| "flushing", *col, 0, || Value::known(Fp::zero()))
                .map(|_| ())
        })?;
        region.assign_advice_from_constant(|| "init series", self.series, 0, Fp::zero())?;
        region.assign_advice_from_constant(|| "init series", self.series, 1, Fp::one())?;
        region.assign_advice_from_constant(
            || "init op",
            self.op_type,
            0,
            Fp::from(self.start_op_code() as u64),
        )?;
        region.assign_advice_from_constant(|| "init ctrl", self.ctrl_type, 0, Fp::zero())?;
        region.assign_advice(
            || "start root",
            self.new_root_index,
            0,
            || Value::known(init_root),
        )?;
        for col in [self.old_root_index, self.address_index] {
            region.assign_advice(|| "index flush", col, 0, || Value::known(Fp::zero()))?;
        }

        for offset in 1..max_rows {
            self.sel.enable(region, offset)?;
        }

        // flush one more row
        self.free_cols.iter().try_for_each(|col| {
            region
                .assign_advice(
                    || "flushing last",
                    *col,
                    max_rows,
                    || Value::known(Fp::zero()),
                )
                .map(|_| ())
        })?;
        // begin padding and final flush for data_rows
        for col in [self.data_0, self.data_1, self.data_2] {
            region.assign_advice(|| "begin padding", col, 0, || Value::known(Fp::zero()))?;

            region.assign_advice(
                || "last row flushing",
                col,
                max_rows,
                || Value::known(Fp::zero()),
            )?;
        }
        region.assign_advice(
            || "terminalte series",
            self.series,
            max_rows,
            || Value::known(Fp::zero()),
        )?;

        Ok(1)
    }

    // pace has to be called before a working gadget is assigned on the specified offset, the rows
    // that working gadget would occpuy, and the result of the new root which gadget has output,
    // must be known before
    pub fn pace_op<Fp: FieldExt>(
        &self,
        region: &mut Region<'_, Fp>,
        offset: usize,
        op_type: (u32, u32), //op before -> op now
        rows: usize,
    ) -> Result<(), Error> {
        let mut prev_op = op_type.0;
        let op_delta = Fp::from(op_type.1 as u64) - Fp::from(op_type.0 as u64);
        for offset in offset..(offset + rows) {
            region.assign_advice(
                || "op type",
                self.op_type,
                offset,
                || Value::known(Fp::from(op_type.1 as u64)),
            )?;
            region.assign_advice(
                || "op delta aux",
                self.op_delta_aux,
                offset,
                || {
                    Value::known(if prev_op == op_type.1 {
                        Fp::zero()
                    } else {
                        op_delta.invert().unwrap()
                    })
                },
            )?;
            // flush all cols to avoid unassigned error
            self.free_cols.iter().try_for_each(|col| {
                region
                    .assign_advice(
                        || "flushing free",
                        *col,
                        offset,
                        || Value::known(Fp::zero()),
                    )
                    .map(|_| ())
            })?;
            // flush all cols to avoid unassigned error
            self.s_ctrl_type.iter().try_for_each(|col| {
                region
                    .assign_advice(
                        || "flushing op type flag",
                        *col,
                        offset,
                        || Value::known(Fp::zero()),
                    )
                    .map(|_| ())
            })?;
            [
                self.data_0,
                self.data_1,
                self.data_2,
                self.data_0_ext,
                self.data_1_ext,
                self.data_2_ext,
            ]
            .iter()
            .try_for_each(|col| {
                region
                    .assign_advice(
                        || "flushing exported",
                        *col,
                        offset,
                        || Value::known(Fp::zero()),
                    )
                    .map(|_| ())
            })?;
            self.s_stepflags.iter().try_for_each(|col| {
                region
                    .assign_advice(|| "flushing", *col, offset, || Value::known(Fp::zero()))
                    .map(|_| ())
            })?;

            prev_op = op_type.1;
        }

        Ok(())
    }

    // complete block is called AFTER all working gadget has been assigned on the specified offset,
    // this entry fill whole block with series and index value
    pub fn complete_block<Fp: FieldExt>(
        &self,
        region: &mut Region<'_, Fp>,
        offset: usize,
        op_series: usize,
        roots: Option<(Fp, Fp)>,
        address: Option<Fp>,
        rows: usize,
    ) -> Result<(), Error> {
        for offset in offset..(offset + rows) {
            region.assign_advice(
                || "series pacing",
                self.series,
                offset,
                || Value::known(Fp::from(op_series as u64)),
            )?;
            region.assign_advice(
                || "old root index",
                self.old_root_index,
                offset,
                || Value::known(roots.map(|(v, _)| v).unwrap_or_default()),
            )?;
            region.assign_advice(
                || "new root index",
                self.new_root_index,
                offset,
                || Value::known(roots.map(|(_, v)| v).unwrap_or_default()),
            )?;
            region.assign_advice(
                || "address root index",
                self.address_index,
                offset,
                || Value::known(address.unwrap_or_default()),
            )?;
        }
        Ok(())
    }

    // set all transition rules
    // + end_op: is the last op code in your assignation, often just (<padding gadget's op type, usually 0>, 0)
    pub fn set_op_border<Fp: FieldExt>(
        &self,
        layouter: &mut impl Layouter<Fp>,
        inter_op: &[OpBorder],
        intra_op: &[OpBorder],
        start_op: (u32, u32),
    ) -> Result<(), Error> {
        self.set_op_border_ex(layouter, inter_op, intra_op, &[start_op])
    }

    // set all transition rules
    // + start_op: all possible starting op code and ctrl code
    pub fn set_op_border_ex<Fp: FieldExt>(
        &self,
        layouter: &mut impl Layouter<Fp>,
        inter_op: &[OpBorder],
        intra_op: &[OpBorder],
        start_op: &[(u32, u32)],
    ) -> Result<(), Error> {
        layouter.assign_table(
            || "op trans",
            |mut table| {
                //default lookup (0, 0, 0, 0, 0) and (0, 0, 0, 0, 1)
                table.assign_cell(
                    || "default",
                    self.control_table[0],
                    0,
                    || Value::known(Fp::zero()),
                )?;
                table.assign_cell(
                    || "default",
                    self.control_table[1],
                    0,
                    || Value::known(Fp::zero()),
                )?;
                table.assign_cell(
                    || "default",
                    self.control_table[2],
                    0,
                    || Value::known(Fp::zero()),
                )?;
                table.assign_cell(
                    || "default",
                    self.control_table[3],
                    0,
                    || Value::known(Fp::zero()),
                )?;
                table.assign_cell(
                    || "default",
                    self.control_table[4],
                    0,
                    || Value::known(Fp::zero()),
                )?;

                table.assign_cell(
                    || "default op cur",
                    self.control_table[0],
                    1,
                    || Value::known(Fp::zero()),
                )?;
                table.assign_cell(
                    || "default ctrl cur",
                    self.control_table[1],
                    1,
                    || Value::known(Fp::zero()),
                )?;
                table.assign_cell(
                    || "default op prev",
                    self.control_table[2],
                    1,
                    || Value::known(Fp::zero()),
                )?;
                table.assign_cell(
                    || "default ctrl prev",
                    self.control_table[3],
                    1,
                    || Value::known(Fp::zero()),
                )?;
                table.assign_cell(
                    || "mark",
                    self.control_table[4],
                    1,
                    || Value::known(Fp::one()),
                )?;

                let mut offset = 2;

                for start_case in start_op {
                    //marking the start op, which decided how the circuit is start
                    table.assign_cell(
                        || "start op",
                        self.control_table[0],
                        offset,
                        || Value::known(Fp::from(start_case.0 as u64)),
                    )?;
                    table.assign_cell(
                        || "start ctrl",
                        self.control_table[1],
                        offset,
                        || Value::known(Fp::from(start_case.1 as u64)),
                    )?;
                    table.assign_cell(
                        || "marking op",
                        self.control_table[2],
                        offset,
                        || Value::known(Fp::from(self.start_op_code() as u64)),
                    )?;
                    table.assign_cell(
                        || "marking ctrl",
                        self.control_table[3],
                        offset,
                        || Value::known(Fp::zero()),
                    )?;
                    table.assign_cell(
                        || "mark",
                        self.control_table[4],
                        offset,
                        || Value::known(Fp::one()),
                    )?;
                    offset += 1;
                }

                for ((op_cur, ctrl_cur), (op_prev, ctrl_prev)) in inter_op {
                    table.assign_cell(
                        || "op cur",
                        self.control_table[0],
                        offset,
                        || Value::known(Fp::from(*op_cur as u64)),
                    )?;
                    table.assign_cell(
                        || "ctrl cur",
                        self.control_table[1],
                        offset,
                        || Value::known(Fp::from(*ctrl_cur as u64)),
                    )?;
                    table.assign_cell(
                        || "op prev",
                        self.control_table[2],
                        offset,
                        || Value::known(Fp::from(*op_prev as u64)),
                    )?;
                    table.assign_cell(
                        || "ctrl prev",
                        self.control_table[3],
                        offset,
                        || Value::known(Fp::from(*ctrl_prev as u64)),
                    )?;
                    table.assign_cell(
                        || "mark",
                        self.control_table[4],
                        offset,
                        || Value::known(Fp::one()),
                    )?;
                    offset += 1;
                }

                for ((op_cur, ctrl_cur), (op_prev, ctrl_prev)) in intra_op {
                    table.assign_cell(
                        || "op cur",
                        self.control_table[0],
                        offset,
                        || Value::known(Fp::from(*op_cur as u64)),
                    )?;
                    table.assign_cell(
                        || "ctrl cur",
                        self.control_table[1],
                        offset,
                        || Value::known(Fp::from(*ctrl_cur as u64)),
                    )?;
                    table.assign_cell(
                        || "op prev",
                        self.control_table[2],
                        offset,
                        || Value::known(Fp::from(*op_prev as u64)),
                    )?;
                    table.assign_cell(
                        || "ctrl prev",
                        self.control_table[3],
                        offset,
                        || Value::known(Fp::from(*ctrl_prev as u64)),
                    )?;
                    table.assign_cell(
                        || "mark",
                        self.control_table[4],
                        offset,
                        || Value::known(Fp::zero()),
                    )?;
                    offset += 1;
                }

                Ok(())
            },
        )?;

        Ok(())
    }
}

// padding gadget keep start and end root identical, it often act as the "terminal" circuit to fill the rest space
// in the region, it has only one ctrl type equal to 0,
#[derive(Clone, Debug)]
pub(crate) struct PaddingGadget {
    s_enable: Column<Advice>,
    ctrl_type: Column<Advice>,
    s_ctrl_type: Column<Advice>,
}

impl PaddingGadget {
    pub fn configure<Fp: FieldExt>(
        _meta: &mut ConstraintSystem<Fp>,
        _sel: Selector,
        exported: &[Column<Advice>],
        s_ctrl_type: &[Column<Advice>],
    ) -> Self {
        Self {
            ctrl_type: exported[0],
            s_enable: exported[1],
            s_ctrl_type: s_ctrl_type[0],
        }
    }

    pub fn padding<Fp: FieldExt>(
        &self,
        region: &mut Region<'_, Fp>,
        offset: usize,
        rows: usize,
    ) -> Result<(), Error> {
        for offset in offset..(offset + rows) {
            region.assign_advice(
                || "ctrl type",
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
            region.assign_advice(
                || "enable padding",
                self.s_enable,
                offset,
                || Value::known(Fp::one()),
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    #![allow(unused_imports)]

    use super::*;
    use crate::{operation::*, serde::Row, test_utils::*};
    use halo2_proofs::{
        circuit::{Cell, Region, SimpleFloorPlanner},
        dev::{MockProver, VerifyFailure},
        plonk::{Circuit, Expression},
    };

    #[derive(Clone, Debug)]
    struct NullCircuitConfig {
        layer: LayerGadget,
        padding: PaddingGadget,
    }

    #[derive(Clone, Default)]
    struct NullCircuit {
        root: Fp,
        blocks: Vec<usize>,
    }

    impl Circuit<Fp> for NullCircuit {
        type Config = NullCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            let layer = LayerGadget::configure(meta, 1, 3, 1);
            let padding = PaddingGadget::configure(
                meta,
                layer.sel,
                layer.exported_cols(0).as_slice(),
                layer.get_ctrl_type_flags(),
            );

            let cst = meta.fixed_column();
            meta.enable_constant(cst);

            NullCircuitConfig { layer, padding }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            layouter.assign_region(
                || "main",
                |mut region| {
                    let r = self.root;
                    let rows = self.blocks.iter().sum();
                    let mut start = config.layer.assign(&mut region, rows, r)?;
                    let mut last_op = config.layer.start_op_code();

                    for (index, rows) in self.blocks.iter().enumerate() {
                        config
                            .layer
                            .pace_op(&mut region, start, (last_op, 0), *rows)?;
                        config.padding.padding(&mut region, start, *rows)?;
                        config.layer.complete_block(
                            &mut region,
                            start,
                            index + 1,
                            Some((r, r)),
                            None,
                            *rows,
                        )?;
                        start += rows;
                        last_op = 0;
                    }

                    Ok(())
                },
            )?;

            // no intra transition,
            // for inter-block, (0, 0 -> 0, 0) is default so we do not need it
            config.layer.set_op_border(&mut layouter, &[], &[], (0, 0))
        }
    }

    #[test]
    fn layer_null() {
        let k = 4;
        let circuit = NullCircuit {
            root: rand_fp(),
            blocks: vec![2, 3, 4],
        };

        #[cfg(feature = "print_layout")]
        print_layout!("layouts/layer_null_layout.png", k, &circuit);

        let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));

        let circuit = NullCircuit {
            root: rand_fp(),
            blocks: vec![5],
        };

        let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[derive(Clone, Debug)]
    struct MultiOpCircuitConfig {
        layer: LayerGadget,
        padding0: PaddingGadget,
        padding1: PaddingGadget,
    }

    #[derive(Clone, Default)]
    struct MultiOpCircuit {
        root: Fp,
        blocks: Vec<(usize, usize)>,
    }

    impl Circuit<Fp> for MultiOpCircuit {
        type Config = MultiOpCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            let layer = LayerGadget::configure(meta, 3, 2, 1);
            let padding0 = PaddingGadget::configure(
                meta,
                layer.sel,
                layer.exported_cols(0).as_slice(),
                layer.get_ctrl_type_flags(),
            );
            let padding1 = PaddingGadget::configure(
                meta,
                layer.sel,
                layer.exported_cols(2).as_slice(),
                layer.get_ctrl_type_flags(),
            );

            let cst = meta.fixed_column();
            meta.enable_constant(cst);

            MultiOpCircuitConfig {
                layer,
                padding0,
                padding1,
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
                    let r = self.root;
                    let rows = self.blocks.iter().fold(0, |acc, x| acc + x.0 + x.1);
                    let mut start = config.layer.assign(&mut region, rows, r)?;
                    let mut last_op = config.layer.start_op_code();

                    for (index, rows) in self.blocks.iter().enumerate() {
                        let block_start = start;
                        let (op0, op1) = *rows;
                        config
                            .layer
                            .pace_op(&mut region, start, (last_op, 0), op0)?;
                        config.padding0.padding(&mut region, start, op0)?;
                        last_op = 0;
                        start += op0;
                        config
                            .layer
                            .pace_op(&mut region, start, (last_op, 2), op1)?;
                        config.padding1.padding(&mut region, start, op1)?;
                        last_op = 2;
                        start += op1;
                        config.layer.complete_block(
                            &mut region,
                            block_start,
                            index + 1,
                            Some((r, r)),
                            None,
                            op0 + op1,
                        )?;
                    }

                    Ok(())
                },
            )?;

            config.layer.set_op_border(
                &mut layouter,
                &[((0, 0), (2, 0))],
                &[((2, 0), (0, 0))],
                (0, 0),
            )
        }
    }

    #[test]
    fn gadget_degrees() {
        let mut cs: ConstraintSystem<Fp> = Default::default();
        MultiOpCircuit::configure(&mut cs);

        println!("layer gadget degree: {}", cs.degree());
        assert!(cs.degree() <= 9);
    }

    #[test]
    fn layer_multi() {
        let k = 4;
        let circuit = MultiOpCircuit {
            root: rand_fp(),
            blocks: vec![(1, 1), (1, 2), (2, 2)],
        };

        let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
