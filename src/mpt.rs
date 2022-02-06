//! The constraint system matrix for an arity-2 Merkle Patricia Tree using lookup-table
//! for verifying the Merkle path of mutiple leaf nodes
//
//  The lookup table is formed by <left, right, hash> and the input can be
//  * <val_col, sibling_col, val_col@roation::(-1)]> if HashType is Mid
//  * <Leafkey, val, val_col@roation::(-1)> if HashType is Leaf
//
//  The HashType decide which rows should be involved in lookup, rows with special HashType
//  like LeafExt/LeafExtFinal require additional constraints rather than hashing
//
//  The layout of chip for Merkle path is like:
//  |-----||----------------|------------------|------------------|-------|---------|----------------|----------------|--------|
//  | row ||     HashType   |       val        |     sibling      |  key  |  path   |     HashTable (left, right, hash)        |
//  |-----||----------------|------------------|------------------|-------|---------|----------------|----------------|--------|
//  |  0  ||                |      root1       |                  |       |         |                                          |
//  |  1  ||      Empty     |      leaf0       |                  |Leafkey|         |                                          |
//  |  2  ||                |      root2       |                  |       |         |                                          |
//  |  3  ||       Mid      |     digest_1     |      elem_11     |       | cbit_11 |digest_1/elem_11 digest_1/elem_11  hash1  |
//  |  4  ||     LeafExt    |     digest_2     |      elem_12     |       | cbit_12 |digest_2/elem_12 digest_2/elem_12  hash2  |
//  |  5  ||  LeafExtFinal  |     digest_3     |      elem_13     |       | cbit_13 |digest_3/elem_12 digest_3/elem_12  hash3  |
//  |  6  ||      Empty     |      leaf1       |                  |Leafkey|         |                                          |
//  |-----||----------------|------------------|------------------|-------|---------|----------------|----------------|--------|
//
//  We have also additional gates for the "extended Leaf" scheme
//

use super::HashType;
use halo2::{
    arithmetic::FieldExt,
    circuit::{Chip, Layouter},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector, TableColumn},
    poly::Rotation,
};
use std::marker::PhantomData;

fn lagrange_polynomial_for_hashtype<Fp: ff::PrimeField, const T: usize>(
    ref_n: Expression<Fp>,
) -> Expression<Fp> {
    let mut denominators = vec![
        Fp::from(T as u64) - Fp::from(HashType::Start as u64),
        Fp::from(T as u64) - Fp::from(HashType::Empty as u64),
        Fp::from(T as u64) - Fp::from(HashType::Middle as u64),
        Fp::from(T as u64) - Fp::from(HashType::LeafExt as u64),
        Fp::from(T as u64) - Fp::from(HashType::LeafExtFinal as u64),
        Fp::from(T as u64) - Fp::from(HashType::Leaf as u64),
    ];

    denominators.swap_remove(T);
    let denominator = denominators.into_iter().fold(Fp::one(), |acc, v| v * acc);
    assert_ne!(denominator, Fp::zero());

    let mut factors = vec![
        ref_n.clone() - Expression::Constant(Fp::zero()),
        ref_n.clone() - Expression::Constant(Fp::from(HashType::Empty as u64)),
        ref_n.clone() - Expression::Constant(Fp::from(HashType::Middle as u64)),
        ref_n.clone() - Expression::Constant(Fp::from(HashType::LeafExt as u64)),
        ref_n.clone() - Expression::Constant(Fp::from(HashType::LeafExtFinal as u64)),
        ref_n - Expression::Constant(Fp::from(HashType::Leaf as u64)),
    ];

    factors.swap_remove(T);
    factors.into_iter().fold(
        Expression::Constant(denominator.invert().unwrap()),
        |acc, f| acc * f,
    )
}

//use lazy_static::lazy_static;
//use rand::{thread_rng, Rng, SeedableRng};
//use rand_chacha::ChaCha8Rng;

pub(crate) struct MPTChip<F> {
    config: MPTChipConfig,
    _marker: PhantomData<F>,
}

/// Config a chip for verify mutiple merkle path in MPT
#[derive(Clone, Debug)]
pub(crate) struct MPTChipConfig {
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
    pub fn configure(
        meta: &mut ConstraintSystem<Fp>,
        s_row: Selector,
        hash_type: Column<Advice>,
        val: Column<Advice>,
        key: Column<Advice>,
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
        meta.lookup(|meta| {
            let hash_type = meta.query_advice(hash_type, Rotation::cur());
            let s_path = lagrange_polynomial_for_hashtype::<_, 2>(hash_type); //Middle

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
                (left_lookup, left),
                (right_lookup, right),
                (hash_lookup, hash),
            ]
        });

        meta.lookup(|meta| {
            let hash_type = meta.query_advice(hash_type, Rotation::cur());
            let s_leaf = lagrange_polynomial_for_hashtype::<_, 5>(hash_type); //Leaf

            let key_col = s_leaf.clone() * meta.query_advice(key, Rotation::cur());
            let val_leaf_col = s_leaf.clone() * meta.query_advice(val, Rotation::cur());
            let hash_lookup = s_leaf * meta.query_advice(val, Rotation::prev());

            vec![(key_col, left), (val_leaf_col, right), (hash_lookup, hash)]
        });

        meta.create_gate("leaf extended", |meta| {
            let sel = meta.query_selector(s_row);
            let hash_type = meta.query_advice(hash_type, Rotation::cur());
            let s_extended = lagrange_polynomial_for_hashtype::<_, 3>(hash_type); //LeafExt
            let sibling = meta.query_advice(sibling, Rotation::cur());
            // + sibling must be 0 when hash_type is leaf extended, or malice
            //   advisor can make arbital sibling which would halt the process of L2
            // + value in leaf-extended row must equal to the previous
            vec![
                sel.clone() * s_extended.clone() * sibling,
                sel * s_extended
                    * (meta.query_advice(val, Rotation::cur())
                        - meta.query_advice(val, Rotation::prev())),
            ]
        });

        meta.create_gate("last leaf extended", |meta| {
            let sel = meta.query_selector(s_row);
            let hash_type = meta.query_advice(hash_type, Rotation::cur());
            let s_last_extended = lagrange_polynomial_for_hashtype::<_, 4>(hash_type); //LeafExtFinal

            // + sibling must be previous val when hash_type is leaf extended final
            // (notice the value for leafExtendedFinal can be omitted)
            vec![
                sel * s_last_extended
                    * (meta.query_advice(sibling, Rotation::cur())
                        - meta.query_advice(val, Rotation::prev())),
            ]
        });

        MPTChipConfig { left, right, hash }
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
        hashing_records: Vec<(Fp, Fp, Fp)>,
    ) -> Result<(), Error> {
        let left = self.config().left;
        let right = self.config().right;
        let hash = self.config().hash;

        layouter.assign_table(
            || "hash table",
            |mut table| {
                hashing_records
                    .iter()
                    .enumerate()
                    .try_for_each(|(offset, val)| {
                        let (lh, rh, h) = val;

                        table.assign_cell(|| "left", left, offset, || Ok(*lh))?;

                        table.assign_cell(|| "right", right, offset, || Ok(*rh))?;

                        table.assign_cell(|| "result", hash, offset, || Ok(*h))?;

                        Ok(())
                    })
            },
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    #![allow(unused_imports)]

    use super::*;
    use crate::test_utils::*;
    use halo2::{
        circuit::{Cell, Region, SimpleFloorPlanner},
        dev::{MockProver, VerifyFailure},
        plonk::{Circuit, Expression},
    };

    const MAX_PATH_DEPTH: usize = 16;
    const MAX_KEY: usize = (2 as usize).pow(MAX_PATH_DEPTH as u32);

    #[derive(Clone, Debug)]
    struct MPTTestConfig {
        s_row: Selector,
        hash_type: Column<Advice>,
        key: Column<Advice>,
        val: Column<Advice>,
        sibling: Column<Advice>,
        path: Column<Advice>,
        chip: MPTChipConfig,
    }

    // express for a single path block
    #[derive(Clone, Default)]
    struct MPTTestSinglePathCircuit {
        key: u32,       //the key simply expressed by u32
        paths: Vec<Fp>, //include path bits and the resident part for leaf, it decide how many rows
        //would be used (len + 1)
        siblings: Vec<Fp>,         //siblings from top to bottom
        hash_types: Vec<HashType>, //hash types used from top to bottom (Start is not included)
        hash_vals: Vec<Fp>, //all hashs (include leaf vals) in the circuit, one element more than paths
        hash_traces: Vec<(Fp, Fp, Fp)>,
    }

    impl Circuit<Fp> for MPTTestSinglePathCircuit {
        type Config = MPTTestConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            let hash_type = meta.advice_column();
            let val = meta.advice_column();
            let key = meta.advice_column();
            let sibling = meta.advice_column();
            let path = meta.advice_column();
            let s_row = meta.selector();
            let one = Expression::Constant(Fp::one());

            meta.create_gate("boolean/bit", |meta| {
                let hash_type = meta.query_advice(hash_type, Rotation::cur());
                let s_path = lagrange_polynomial_for_hashtype::<_, 2>(hash_type);
                let path_col = meta.query_advice(path, Rotation::cur());
                let s_row = meta.query_selector(s_row);
                vec![s_row.clone() * s_path * path_col.clone() * (path_col - one.clone())]
            });

            MPTTestConfig {
                s_row,
                hash_type,
                val,
                key,
                sibling,
                path,
                chip: MPTChip::configure(meta, s_row, hash_type, val, key, sibling, path),
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            layouter.assign_region(
                || "main",
                |mut region| self.fill_layer(&config, &mut region, 0),
            )?;

            let mpt_chip = MPTChip::<Fp>::construct(config.chip);
            mpt_chip.load(&mut layouter, self.hash_traces.clone())?;
            Ok(())
        }
    }

    struct LayerFillTrace {
        pub hashs: Vec<(Fp, Fp, Fp)>,
    }

    impl MPTTestSinglePathCircuit {
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

        /// create a common path data layout (only contains middle and leaf type)
        /// the siblings do not contain the padding for leaf
        pub fn create(
            key: u32,
            leaf: Fp,
            mut siblings: Vec<Fp>,
            mut hasher: impl FnMut(&Fp, &Fp) -> Fp,
        ) -> Self {
            let leaf_hash = hasher(&Fp::from(key as u64), &leaf);
            let mut hash_traces = vec![(Fp::from(key as u64), leaf, leaf_hash)];
            let mut hash_vals = vec![leaf, leaf_hash];
            let (path_bits, res_key) = Self::decompose_path(key, siblings.len());
            let mut hash_types = Vec::new();
            let mut paths = Vec::new();

            assert_eq!(path_bits.len(), siblings.len());

            for (sibling, bit) in siblings.iter().rev().zip(path_bits.iter().rev()) {
                let (l, r) = if *bit {
                    (sibling, hash_vals.last().unwrap())
                } else {
                    (hash_vals.last().unwrap(), sibling)
                };

                let h = hasher(l, r);
                hash_traces.push((*l, *r, h));
                hash_vals.push(h);
                hash_types.push(HashType::Middle);
                paths.push(if *bit { Fp::one() } else { Fp::zero() });
            }

            hash_vals.reverse();
            hash_types.push(HashType::Leaf);
            paths.push(Fp::from(res_key as u64));
            siblings.push(Fp::zero());
            MPTTestSinglePathCircuit {
                key,
                paths,
                hash_vals,
                hash_types,
                siblings,
                hash_traces,
            }
        }

        pub fn fill_layer(
            &self,
            config: &MPTTestConfig,
            region: &mut Region<'_, Fp>,
            mut offset: usize,
        ) -> Result<usize, Error> {
            assert_eq!(self.paths.len(), self.siblings.len());
            assert_eq!(self.hash_types.len(), self.siblings.len());

            // each block has a padding row at the beginning
            region.assign_advice(|| "root", config.val, offset, || Ok(self.hash_vals[0]))?;
            region.assign_advice(
                || "hash_type start",
                config.hash_type,
                offset,
                || Ok(Fp::from(HashType::Start as u64)),
            )?;
            region.assign_advice(|| "path padding", config.path, offset, || Ok(Fp::zero()))?;

            if offset != 0 {
                config.s_row.enable(region, offset)?;
            }

            offset += 1;

            for (index, path) in self.paths.iter().enumerate() {
                region.assign_advice(
                    || "val",
                    config.val,
                    offset,
                    || Ok(self.hash_vals[index + 1]),
                )?;
                region.assign_advice(
                    || "sibling",
                    config.sibling,
                    offset,
                    || Ok(self.siblings[index]),
                )?;
                region.assign_advice(|| "path", config.path, offset, || Ok(*path))?;
                region.assign_advice(
                    || "hash_type",
                    config.hash_type,
                    offset,
                    || Ok(Fp::from(self.hash_types[index] as u64)),
                )?;
                //fill all row of key (in actual circuit only the last row has key value)
                region.assign_advice(
                    || "key",
                    config.key,
                    offset,
                    || Ok(Fp::from(self.key as u64)),
                )?;
                config.s_row.enable(region, offset)?;
                offset += 1;
            }

            Ok(offset)
        }
    }

    #[test]
    fn test_single_path() {
        let leaf = rand_fp();
        let mut siblings = Vec::new();
        for _ in 0..3 {
            siblings.push(rand_fp());
        }
        let key = u32::from_be_bytes(rand_bytes_array()) % MAX_KEY as u32;

        let circuit = MPTTestSinglePathCircuit::create(key, leaf, siblings, mock_hash);
        let k = 4; //at least 16 rows

        #[cfg(feature = "print_layout")]
        print_layout!("mpt_layout.png", k, &circuit);

        let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
