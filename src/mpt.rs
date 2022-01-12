//! The constraint system matrix for an arity-2 Merkle Patricia Tree using lookup-table for hashing
//  The lookup table is formed by <left, right, hash> and the input can be 
//  <val_col@Rotation::(1), sibling_col, val_col]>
//  s_path act as selector for lookup arguments

//  |-----||--------|------------------|------------------|---------|----------------|----------------|--------|
//  | row || s_path |       val        |     sibling      |  path   |     left       |     right      |  hash  |
//  |-----||--------|------------------|------------------|---------|----------------|----------------|--------|
//  |  0  ||   1    |       root1      |      elem_11     | cbit_11 |                |                |        |
//  |  1  ||   1    |     digest_1     |      elem_12     | cbit_12 |digest_1/elem_11|digest_1/elem_11| hash1  |
//  |  2  ||   1    |     digest_2     |      elem_13     | cbit_13 |digest_1/elem_12|digest_1/elem_12| hash2  |
//  |  3  ||   0    |       leaf1      |                  |         |  leaf1/elem_13 |  leaf1/elem_13 | hash3  |
//  |  4  ||   1    |       root2      |                  |         |                |                |        |
//  |-----||--------|------------------|------------------|---------|----------------|----------------|--------|


use halo2::{
    circuit::{Chip, Layouter},
    plonk::{
        Advice, Column, TableColumn, ConstraintSystem, Error,
    },
    poly::Rotation,
    arithmetic::FieldExt,
};
use std::marker::PhantomData;

//use lazy_static::lazy_static;
//use rand::{thread_rng, Rng, SeedableRng};
//use rand_chacha::ChaCha8Rng;

struct MPTChip<F> {
    config: MPTChipConfig,
    _marker: PhantomData<F>
}

/// Config a chip for verify mutiple merkle path in MPT
#[derive(Clone, Debug)]
struct MPTChipConfig {
    left: TableColumn,
    right: TableColumn,
    hash: TableColumn,
}

impl<Fp: FieldExt> Chip<Fp> for MPTChip<Fp> {
    type Config = MPTChipConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<Fp: FieldExt> MPTChip<Fp> {

    fn configure(
        meta: &mut ConstraintSystem<Fp>,
        s_path: Column<Advice>,
        val: Column<Advice>,
        sibling: Column<Advice>,
        path: Column<Advice>,        
    ) -> <Self as Chip<Fp>>::Config {
        let left = meta.lookup_table_column();
        let right = meta.lookup_table_column();
        let hash = meta.lookup_table_column();

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
        meta.lookup(|meta|{
            let s_path = meta.query_advice(s_path, Rotation::cur());

            let path_bit = meta.query_advice(path, Rotation::cur());
            let val_col = meta.query_advice(val, Rotation::next());
            let sibling_col = meta.query_advice(sibling, Rotation::cur());
            let right_lookup = s_path.clone() * (path_bit.clone() * (val_col.clone() - sibling_col.clone()) + sibling_col.clone());
            let left_lookup = s_path.clone() * (path_bit * (sibling_col - val_col.clone()) + val_col);
            let hash_lookup = s_path * meta.query_advice(val, Rotation::cur());

            vec![(left_lookup, left), 
            (right_lookup, right), 
            (hash_lookup, hash)]
        });

        MPTChipConfig {
            left,
            right,
            hash,
        }
    }

    pub fn construct(config: MPTChipConfig) -> Self {
        MPTChip { 
            config,
            _marker: PhantomData,
        }
    }

    pub fn load(
        &self,
        layouter: &mut impl Layouter<Fp>,
        mut hashing_records: Vec<(Fp, Fp, Fp)>,
    ) -> Result<(), Error> {

        let left = self.config().left;
        let right = self.config().right;
        let hash = self.config().hash;
        hashing_records.push((Fp::zero(), Fp::zero(), Fp::zero()));

        layouter.assign_table(
            ||"hash table",
            |mut table|{

                hashing_records.iter().enumerate().try_for_each(|(offset, val)|{
                    let (lh, rh, h) = val;

                    table.assign_cell(
                        || "left",
                        left,
                        offset,
                        || Ok(*lh)
                    )?;

                    table.assign_cell(
                        || "right",
                        right,
                        offset,
                        || Ok(*rh)
                    )?;

                    table.assign_cell(
                        || "result",
                        hash,
                        offset,
                        || Ok(*h)
                    )?;                    

                    Ok(())
                })
            }
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    #![allow(unused_imports)]

    use super::*;
    use halo2::{
        circuit::{Region, Cell, SimpleFloorPlanner},
        dev::{MockProver, VerifyFailure},
        pairing::bn256::Fr as Fp, // why halo2-merkle tree use base field?
        plonk::{Selector, Circuit, Expression},
    };
    use ff::Field;
    use lazy_static::lazy_static;
    use rand_chacha::ChaCha8Rng;
    use rand::{random, SeedableRng};

    lazy_static! {
        static ref GAMMA: Fp = Fp::random(ChaCha8Rng::from_seed([101u8; 32]));
    }

    fn mock_hash(a: &Fp, b: &Fp) -> Fp {
        (a + *GAMMA) * (b + *GAMMA)
    }

    fn rand_bytes(n: usize) -> Vec<u8> {
        vec![random(); n]
    }

    fn rand_bytes_array<const N: usize>() -> [u8; N] {
        [(); N].map(|_| random())
    }

    fn rand_fp() -> Fp {
        let mut arr = rand_bytes_array::<32>();
        //avoiding failure in unwrap
        arr[31] &= 31;
        Fp::from_bytes(&arr).unwrap()
    }

    const MAX_PATH_DEPTH: usize = 16;
    const MAX_KEY: usize = (2 as usize).pow(MAX_PATH_DEPTH as u32);

    #[derive(Clone, Debug)]
    struct MPTTestConfig {
        s_row: Selector,
        s_path: Column<Advice>,
        val: Column<Advice>,
        sibling: Column<Advice>,
        path: Column<Advice>,        
        chip: MPTChipConfig,
    }

    #[derive(Clone, Default)]
    struct MPTTestSinglePathCircuit {
        pub leaf: Fp, //the hash of leaf
        pub siblings: Vec<Fp>, //siblings from top to bottom
        pub path: u32, //the path key simply expressed by u32
    }


    impl Circuit<Fp> for MPTTestSinglePathCircuit {
        type Config = MPTTestConfig;
        type FloorPlanner = SimpleFloorPlanner;
        
        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {

            let s_path = meta.advice_column();
            let val = meta.advice_column();
            let sibling = meta.advice_column();
            let path = meta.advice_column();
            let s_row = meta.selector();
            let one = Expression::Constant(Fp::one());

            meta.create_gate("boolean/bit", |meta| {
                let s_path_col = meta.query_advice(s_path, Rotation::cur());
                let path_col = meta.query_advice(path, Rotation::cur());
                let s_row = meta.query_selector(s_row);
                vec![s_row.clone() * s_path_col.clone() * (s_path_col.clone() - one.clone()),
                    s_row.clone() * s_path_col * path_col.clone() * (path_col - one.clone())]
            });

            MPTTestConfig {
                s_row,
                s_path,
                val,
                sibling,
                path,
                chip: MPTChip::configure(meta, s_path, val, sibling, path),
            }
        }

        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
            let fill_ret = layouter.assign_region(||"main", |mut region|
                self.fill_layer(&config, &mut region, mock_hash)
            )?;

            let mpt_chip = MPTChip::<Fp>::construct(config.chip);
            mpt_chip.load(&mut layouter, fill_ret.hashs)?;
            Ok(())
        }

    }

    struct LayerFillTrace {
        pub hashs : Vec<(Fp, Fp, Fp)>,
    }

    impl MPTTestSinglePathCircuit {

        //decompose path to bits, start from smallest, return the
        //two parts which reside on path and the leaf
        fn decompose_path(&self) -> (Vec<bool>, Vec<bool>) {
            let mut path_bits = Vec::new();
            assert!(MAX_PATH_DEPTH >= self.siblings.len(), "more siblings than max depth");

            for layer in 1..(MAX_PATH_DEPTH + 1) {
                let has_bit = (self.path & 2u32.pow((MAX_PATH_DEPTH - layer) as u32)) != 0;
                path_bits.push(has_bit);
            }

            let leaf_bits = path_bits.split_off(self.siblings.len());
            (path_bits, leaf_bits)
        }

        pub fn fill_layer<F: FnMut(&Fp, &Fp) -> Fp>(
            &self,
            config: &MPTTestConfig,
            region: &mut Region<'_, Fp>,
            mut hasher: F,
        ) -> Result<LayerFillTrace, Error> {

            // build all required data
            let mut path_trace = vec![self.leaf];
            let mut hash_trace = vec![];
            let (path_bits, _) = self.decompose_path();

            assert_eq!(path_bits.len(), self.siblings.len());

            for (sibling, bit) in self.siblings.iter().rev().zip(path_bits.iter().rev()) {
                let (l, r) = if *bit {
                    (sibling, path_trace.last().unwrap())
                }else {
                    (path_trace.last().unwrap(), sibling)
                };

                let h = hasher(l, r);
                hash_trace.push((*l, *r, h));
                path_trace.push(h);
            }

            path_trace.reverse();

            let mut offset = 0;
            for bit in path_bits {
                region.assign_advice(||"val", config.val, offset, ||Ok(path_trace[offset]))?;
                region.assign_advice(||"sibling", config.sibling, offset, ||Ok(self.siblings[offset]))?;
                region.assign_advice(||"path", config.path, offset, ||Ok(if bit {Fp::one()} else {Fp::zero()}))?;
                region.assign_advice(||"isfirst", config.s_path, offset, ||Ok(Fp::one()))?;
                offset += 1;
            }
            region.assign_advice(||"val", config.val, offset, ||Ok(path_trace[offset]))?;
            region.assign_advice(||"isfirst", config.s_path, offset, ||Ok(Fp::zero()))?;
            region.assign_advice(||"path", config.path, offset, ||Ok(Fp::from(42)))?;
            offset += 1;

            //enable all
            for row in 0..offset {
                config.s_row.enable(region, row)?;
            }

            Ok(LayerFillTrace{hashs: hash_trace})
        }
    }

    #[test]
    fn test_single_path(){
        let leaf = rand_fp();
        let mut siblings = Vec::new();
        for _ in 0..4 {
            siblings.push(rand_fp());
        }
        let path = u32::from_be_bytes(rand_bytes_array()) % MAX_KEY as u32;

        let circuit = MPTTestSinglePathCircuit {
            leaf,
            siblings,
            path,
        };
        let k = 4; //at least 16 rows

        // Generate layout graph
        /*
        use plotters::prelude::*;
        let root = BitMapBackend::new("layout.png", (1024, 768)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        //let root = root
            //.titled("Test Circuit Layout", ("sans-serif", 60))
            //.unwrap();
    
        halo2::dev::CircuitLayout::default()
            // You can optionally render only a section of the circuit.
            //.view_width(0..2)
            //.view_height(0..16)
            // You can hide labels, which can be useful with smaller areas.
            .show_labels(true)
            // Render the circuit onto your area!
            // The first argument is the size parameter for the circuit.
            .render(k, &circuit, &root)
            .unwrap();
        */
        
        let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}

