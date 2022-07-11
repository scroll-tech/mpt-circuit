//! Organize gadgets on single op and put them into a multi-layer circuits which verify many operations in a time
//! basically we export some col inside an gadget and make layout which organize mutiple of them
//! see <https://hackmd.io/PcoaHMh6RXS-Js1OYzutMQ>
//
// ### Any gadgets dedicated to specified op on MPT can be wrapped like:
//
// | ---- | --------- | --------- | --------- | --------- | --------- | --- | ------- | -------- |-------- |
// | Rows |   series  |  op_type  | ctrl_type |  1_enable |  2_enable | ... | old_root| new_root |root_aux |
// | ---- | --------- | --------- | --------- | --------- | --------- | --- | ------- | -------- |-------- |
// |  1   |     1     |     1     |   start   |     1     |     0     |     |   old1  |   root1  |  root1  |
// |  2   |     1     |     1     |   leaf    |     1     |     0     |     |         |          |  root1  |
// |  3   |     1     |     2     |    ...    |     0     |     1     |     |         |          |  root1  |
// |  4   |     1     |     3     |   leaf    |     0     |     0     |     |         |          |  root1  |
// |  5   |     2     |     1     |   start   |     1     |     0     |     |  root1  |   root2  |  root2  |
// | ---- | --------- | --------- | --------- | --------- | --------- | --- | ------- | -------- |-------- |
//
// The series indicate an op and op_type indicate specified operation step, each step has its own layout
// on the circuit and enabled by a flag, sequence of operations would be laid on continuous rows in the
// circuit and we also call the rows for one step an "op block".

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, Region},
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
    old_root: Column<Advice>,
    new_root: Column<Advice>,

    free_cols: Vec<Column<Advice>>,
    root_aux: Column<Advice>,
    op_delta_aux: Column<Advice>,

    control_table: [TableColumn; 5],
}

pub(crate) type OpBorder = ((u32, u32), (u32, u32));

impl LayerGadget {
    pub fn exported_cols(&self, step: u32) -> [Column<Advice>; 4] {
        [
            self.ctrl_type,
            self.s_stepflags[step as usize],
            self.old_root,
            self.new_root,
        ]
    }

    pub fn get_free_cols(&self) -> &[Column<Advice>] {
        &self.free_cols
    }

    // obtain the col which can control the start and end value (top and bottom of the enabled cells)
    pub fn get_root_control(&self) -> Column<Advice> {
        self.root_aux
    }

    pub fn public_sel(&self) -> Selector {
        self.sel
    }

    pub fn configure<Fp: FieldExt>(
        meta: &mut ConstraintSystem<Fp>,
        steps: usize,
        required_cols: usize,
    ) -> Self {
        let s_stepflags: Vec<Column<Advice>> = (0..steps).map(|_| meta.advice_column()).collect();
        let free_cols = (0..required_cols).map(|_| meta.advice_column()).collect();
        let sel = meta.complex_selector();
        let series = meta.advice_column();
        let op_type = meta.advice_column();
        let ctrl_type = meta.advice_column();
        let old_root = meta.advice_column();
        let new_root = meta.advice_column();
        let root_aux = meta.advice_column();
        let op_delta_aux = meta.advice_column();
        let control_table = [(); 5].map(|_| meta.lookup_table_column());

        // require permutation with constants
        meta.enable_equality(series);
        meta.enable_equality(op_type);
        meta.enable_equality(ctrl_type);

        meta.enable_equality(root_aux);

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

        meta.create_gate("root aux", |meta| {
            let sel = meta.query_selector(sel);
            let series_delta = meta.query_advice(series, Rotation::cur())
                - meta.query_advice(series, Rotation::prev());
            let root_aux_start = meta.query_advice(root_aux, Rotation::cur())
                - meta.query_advice(new_root, Rotation::cur());
            let root_aux_common = meta.query_advice(root_aux, Rotation::cur())
                - meta.query_advice(root_aux, Rotation::prev());

            // root continue: if series change then root_aux == new_root else root_aux = root_aux.prev ("root and depth" gate in the old code)
            // root inherit: if series change then old_root == root_aux.prev ("op continue" gate in the old code)
            vec![
                sel.clone()
                    * (series_delta.clone() * root_aux_start
                        + (Expression::Constant(Fp::one()) - series_delta.clone())
                            * root_aux_common),
                sel * series_delta
                    * (meta.query_advice(old_root, Rotation::cur())
                        - meta.query_advice(root_aux, Rotation::prev())),
            ]
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
            op_type,
            ctrl_type,
            old_root,
            new_root,
            free_cols,
            root_aux,
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
                .assign_advice(|| "flushing", *col, 0, || Ok(Fp::zero()))
                .map(|_| ())
        })?;
        self.s_stepflags.iter().try_for_each(|col| {
            region
                .assign_advice(|| "flushing", *col, 0, || Ok(Fp::zero()))
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
        region.assign_advice(|| "root padding", self.new_root, 0, || Ok(Fp::zero()))?;
        region.assign_advice(|| "root padding", self.old_root, 0, || Ok(Fp::zero()))?;
        region.assign_advice(|| "start root", self.root_aux, 0, || Ok(init_root))?;

        for offset in 1..max_rows {
            self.sel.enable(region, offset)?;
        }

        // flush one more row
        self.free_cols.iter().try_for_each(|col| {
            region
                .assign_advice(|| "flushing last", *col, max_rows, || Ok(Fp::zero()))
                .map(|_| ())
        })?;
        region.assign_advice(
            || "root flushing",
            self.new_root,
            max_rows,
            || Ok(Fp::zero()),
        )?;
        region.assign_advice(
            || "root flushing",
            self.old_root,
            max_rows,
            || Ok(Fp::zero()),
        )?;
        region.assign_advice(
            || "terminalte series",
            self.series,
            max_rows,
            || Ok(Fp::zero()),
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
        op_series: usize,
        op_type: (u32, u32), //op before -> op now
        end_root: Fp,
        rows: usize,
    ) -> Result<(), Error> {
        let mut prev_op = op_type.0;
        let op_delta = Fp::from(op_type.1 as u64) - Fp::from(op_type.0 as u64);
        for offset in offset..(offset + rows) {
            region.assign_advice(
                || "series pacing",
                self.series,
                offset,
                || Ok(Fp::from(op_series as u64)),
            )?;
            region.assign_advice(|| "root aux", self.root_aux, offset, || Ok(end_root))?;
            region.assign_advice(
                || "op type",
                self.op_type,
                offset,
                || Ok(Fp::from(op_type.1 as u64)),
            )?;
            region.assign_advice(
                || "op delta aux",
                self.op_delta_aux,
                offset,
                || {
                    Ok(if prev_op == op_type.1 {
                        Fp::zero()
                    } else {
                        op_delta.invert().unwrap()
                    })
                },
            )?;
            // flush all cols to avoid unassigned error (exported col do not need to be flushed for each gadget must fill them)
            self.free_cols.iter().try_for_each(|col| {
                region
                    .assign_advice(|| "flushing", *col, offset, || Ok(Fp::zero()))
                    .map(|_| ())
            })?;
            self.s_stepflags.iter().try_for_each(|col| {
                region
                    .assign_advice(|| "flushing", *col, offset, || Ok(Fp::zero()))
                    .map(|_| ())
            })?;

            prev_op = op_type.1;
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
                table.assign_cell(|| "default", self.control_table[0], 0, || Ok(Fp::zero()))?;
                table.assign_cell(|| "default", self.control_table[1], 0, || Ok(Fp::zero()))?;
                table.assign_cell(|| "default", self.control_table[2], 0, || Ok(Fp::zero()))?;
                table.assign_cell(|| "default", self.control_table[3], 0, || Ok(Fp::zero()))?;
                table.assign_cell(|| "default", self.control_table[4], 0, || Ok(Fp::zero()))?;

                table.assign_cell(
                    || "default op cur",
                    self.control_table[0],
                    1,
                    || Ok(Fp::zero()),
                )?;
                table.assign_cell(
                    || "default ctrl cur",
                    self.control_table[1],
                    1,
                    || Ok(Fp::zero()),
                )?;
                table.assign_cell(
                    || "default op prev",
                    self.control_table[2],
                    1,
                    || Ok(Fp::zero()),
                )?;
                table.assign_cell(
                    || "default ctrl prev",
                    self.control_table[3],
                    1,
                    || Ok(Fp::zero()),
                )?;
                table.assign_cell(|| "mark", self.control_table[4], 1, || Ok(Fp::one()))?;

                let mut offset = 2;

                for start_case in start_op {
                    //marking the start op, which decided how the circuit is start
                    table.assign_cell(
                        || "start op",
                        self.control_table[0],
                        offset,
                        || Ok(Fp::from(start_case.0 as u64)),
                    )?;
                    table.assign_cell(
                        || "start ctrl",
                        self.control_table[1],
                        offset,
                        || Ok(Fp::from(start_case.1 as u64)),
                    )?;
                    table.assign_cell(
                        || "marking op",
                        self.control_table[2],
                        offset,
                        || Ok(Fp::from(self.start_op_code() as u64)),
                    )?;
                    table.assign_cell(
                        || "marking ctrl",
                        self.control_table[3],
                        offset,
                        || Ok(Fp::zero()),
                    )?;
                    table.assign_cell(
                        || "mark",
                        self.control_table[4],
                        offset,
                        || Ok(Fp::one()),
                    )?;
                    offset += 1;
                }

                for ((op_cur, ctrl_cur), (op_prev, ctrl_prev)) in inter_op {
                    table.assign_cell(
                        || "op cur",
                        self.control_table[0],
                        offset,
                        || Ok(Fp::from(*op_cur as u64)),
                    )?;
                    table.assign_cell(
                        || "ctrl cur",
                        self.control_table[1],
                        offset,
                        || Ok(Fp::from(*ctrl_cur as u64)),
                    )?;
                    table.assign_cell(
                        || "op prev",
                        self.control_table[2],
                        offset,
                        || Ok(Fp::from(*op_prev as u64)),
                    )?;
                    table.assign_cell(
                        || "ctrl prev",
                        self.control_table[3],
                        offset,
                        || Ok(Fp::from(*ctrl_prev as u64)),
                    )?;
                    table.assign_cell(
                        || "mark",
                        self.control_table[4],
                        offset,
                        || Ok(Fp::one()),
                    )?;
                    offset += 1;
                }

                for ((op_cur, ctrl_cur), (op_prev, ctrl_prev)) in intra_op {
                    table.assign_cell(
                        || "op cur",
                        self.control_table[0],
                        offset,
                        || Ok(Fp::from(*op_cur as u64)),
                    )?;
                    table.assign_cell(
                        || "ctrl cur",
                        self.control_table[1],
                        offset,
                        || Ok(Fp::from(*ctrl_cur as u64)),
                    )?;
                    table.assign_cell(
                        || "op prev",
                        self.control_table[2],
                        offset,
                        || Ok(Fp::from(*op_prev as u64)),
                    )?;
                    table.assign_cell(
                        || "ctrl prev",
                        self.control_table[3],
                        offset,
                        || Ok(Fp::from(*ctrl_prev as u64)),
                    )?;
                    table.assign_cell(
                        || "mark",
                        self.control_table[4],
                        offset,
                        || Ok(Fp::zero()),
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
    old_root: Column<Advice>,
    new_root: Column<Advice>,
}

impl PaddingGadget {
    pub fn configure<Fp: FieldExt>(
        meta: &mut ConstraintSystem<Fp>,
        sel: Selector,
        exported: [Column<Advice>; 4],
    ) -> Self {
        meta.create_gate("padding root", |meta| {
            let enable = meta.query_selector(sel) * meta.query_advice(exported[1], Rotation::cur());
            vec![
                enable
                    * (meta.query_advice(exported[2], Rotation::cur())
                        - meta.query_advice(exported[3], Rotation::cur())),
            ]
        });

        Self {
            ctrl_type: exported[0],
            s_enable: exported[1],
            old_root: exported[2],
            new_root: exported[3],
        }
    }

    pub fn padding<Fp: FieldExt>(
        &self,
        region: &mut Region<'_, Fp>,
        offset: usize,
        rows: usize,
        root: Fp,
    ) -> Result<(), Error> {
        for offset in offset..(offset + rows) {
            region.assign_advice(|| "ctrl type", self.ctrl_type, offset, || Ok(Fp::zero()))?;
            region.assign_advice(|| "enable padding", self.s_enable, offset, || Ok(Fp::one()))?;
            region.assign_advice(|| "root", self.old_root, offset, || Ok(root))?;
            region.assign_advice(|| "root", self.new_root, offset, || Ok(root))?;
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
            let layer = LayerGadget::configure(meta, 1, 3);
            let padding = PaddingGadget::configure(meta, layer.sel, layer.exported_cols(0));

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
                    let rows = self.blocks.iter().fold(0, |acc, x| acc + x);
                    let mut start = config.layer.assign(&mut region, rows, r)?;
                    let mut last_op = config.layer.start_op_code();

                    for (index, rows) in self.blocks.iter().enumerate() {
                        config.layer.pace_op(
                            &mut region,
                            start,
                            index + 1,
                            (last_op, 0),
                            r,
                            *rows,
                        )?;
                        config.padding.padding(&mut region, start, *rows, r)?;
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
            let layer = LayerGadget::configure(meta, 3, 2);
            let padding0 = PaddingGadget::configure(meta, layer.sel, layer.exported_cols(0));
            let padding1 = PaddingGadget::configure(meta, layer.sel, layer.exported_cols(2));

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
                        let (op0, op1) = *rows;
                        config.layer.pace_op(
                            &mut region,
                            start,
                            index + 1,
                            (last_op, 0),
                            r,
                            op0,
                        )?;
                        config.padding0.padding(&mut region, start, op0, r)?;
                        last_op = 0;
                        start += op0;
                        config.layer.pace_op(
                            &mut region,
                            start,
                            index + 1,
                            (last_op, 2),
                            r,
                            op1,
                        )?;
                        config.padding1.padding(&mut region, start, op1, r)?;
                        last_op = 2;
                        start += op1;
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
