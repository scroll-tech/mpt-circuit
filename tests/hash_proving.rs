use ff::PrimeField;
use halo2_mpt_circuits::hash;
use halo2_proofs::dev::MockProver;
use halo2_proofs::pairing::bn256::{Bn256, Fr as Fp, G1Affine};
use halo2_proofs::plonk::keygen_vk;
use halo2_proofs::poly::commitment::Params;

#[test]
fn hash_circuit() {
    let message1 = [
        Fp::from_str_vartime("1").unwrap(),
        Fp::from_str_vartime("2").unwrap(),
    ];
    let message2 = [
        Fp::from_str_vartime("0").unwrap(),
        Fp::from_str_vartime("1").unwrap(),
    ];

    let k = 7;
    let circuit = hash::HashCircuit::<3> {
        inputs: [Some(message1), Some(message2), None],
    };
    let prover = MockProver::run(k, &circuit, vec![]).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn vk_validity() {
    let params = Params::<G1Affine>::unsafe_setup::<Bn256>(8);

    let circuit = hash::HashCircuit::<3> {
        inputs: [None, None, None],
    };
    let vk1 = keygen_vk(&params, &circuit).unwrap();

    let mut vk1_buf: Vec<u8> = Vec::new();
    vk1.write(&mut vk1_buf).unwrap();

    let circuit = hash::HashCircuit::<3> {
        inputs: [
            Some([
                Fp::from_str_vartime("1").unwrap(),
                Fp::from_str_vartime("2").unwrap(),
            ]),
            Some([
                Fp::from_str_vartime("0").unwrap(),
                Fp::from_str_vartime("1").unwrap(),
            ]),
            None,
        ],
    };
    let vk2 = keygen_vk(&params, &circuit).unwrap();

    let mut vk2_buf: Vec<u8> = Vec::new();
    vk2.write(&mut vk2_buf).unwrap();

    assert_eq!(vk1_buf, vk2_buf);
}
