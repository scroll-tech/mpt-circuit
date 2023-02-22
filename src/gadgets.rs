use halo2_proofs::{
    arithmetic::Field,
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error},
};
use std::marker::PhantomData;

// mod account_node;
// mod account_parents;
// mod key;
mod poseidon;
mod storage_leaf;
mod storage_parents;

trait Gadget<F: Field> {
    type Config: Clone;
    type Witness;
    type Lookups;

    fn configure(meta: &mut ConstraintSystem<F>, lookups: &Self::Lookups)
        -> Self::Config;
    fn assign(&self, layouter: &mut impl Layouter<F>, witness: &Self::Witness)
        -> Result<(), Error>;
}

// #[derive(Default)]
// struct CircuitZero<F: Field, T: Default + Gadget<F, Dependencies = ()>> {
//     inner: T,
//     marker: PhantomData<F>,
// }

// impl<F: Field, T: Default + Gadget<F, Dependencies = ()>> Circuit<F> for CircuitZero<F, T> {
//     type Config = T::Config;
//     type FloorPlanner = SimpleFloorPlanner;

//     fn without_witnesses(&self) -> Self {
//         Self::default()
//     }

//     fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
//         T::configure(meta, &())
//     }

//     fn synthesize(
//         &self,
//         config: Self::Config,
//         mut layouter: impl Layouter<F>,
//     ) -> Result<(), Error> {
//         unimplemented!();
//     }
// }

// #[derive(Default)]
// struct RecursiveCircuit<F: Field, T: Default + Gadget<F>> {
//     inner: T,
//     marker: PhantomData<F>,
// }

// // impl<F: Field, T: Default + Gadget<F, Dependencies = ()>> Circuit<F> for RecursiveCircuit<F, T> {
// //     type Config = T::Config;
// //     type FloorPlanner = SimpleFloorPlanner;

// //     fn without_witnesses(&self) -> Self {
// //         Self::default()
// //     }

// //     fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
// //         T::configure(meta, &())
// //     }

// //     fn synthesize(
// //         &self,
// //         config: Self::Config,
// //         mut layouter: impl Layouter<F>,
// //     ) -> Result<(), Error> {
// //         unimplemented!();
// //     }
// // }

// impl<F: Field, T: Default + Gadget<F, Dependencies: Gadget<F>>> Circuit<F> for RecursiveCircuit<F, T> {
//     type Config = T::Config;
//     type FloorPlanner = SimpleFloorPlanner;

//     fn without_witnesses(&self) -> Self {
//         Self::default()
//     }

//     fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
//     	let dependencies = T::Dependencies::configure(meta);
//         T::configure(meta, &dependencies)
//     }

//     fn synthesize(
//         &self,
//         config: Self::Config,
//         mut layouter: impl Layouter<F>,
//     ) -> Result<(), Error> {
//         unimplemented!();
//     }
// }
