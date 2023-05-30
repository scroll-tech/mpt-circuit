use crate::{
    constraint_builder::{AdviceColumn, ConstraintBuilder, Query, SecondPhaseAdviceColumn},
    gadgets::{
        byte_representation::{BytesLookup, RlcLookup},
        poseidon::PoseidonLookup,
    },
};
use halo2_proofs::arithmetic::FieldExt;

pub fn configure_word_rlc<F: FieldExt>(
    cb: &mut ConstraintBuilder<F>,
    [word_hash, high, low]: [AdviceColumn; 3],
    [rlc_word, rlc_high, rlc_low]: [SecondPhaseAdviceColumn; 3],
    poseidon: &impl PoseidonLookup,
    bytes: &impl BytesLookup,
    rlc: &impl RlcLookup,
    randomness: Query<F>,
) {
    cb.add_lookup(
        "old_high is 16 bytes",
        [high.current(), Query::from(15)],
        bytes.lookup(),
    );
    cb.add_lookup(
        "old_low is 16 bytes",
        [low.current(), Query::from(15)],
        bytes.lookup(),
    );
    cb.poseidon_lookup(
        "word_hash = poseidon(high, low)",
        [high.current(), low.current(), word_hash.current()],
        poseidon,
    );

    cb.add_lookup(
        "rlc_high = rlc(high)",
        [high.current(), rlc_high.current()],
        rlc.lookup(),
    );
    cb.add_lookup(
        "rlc_low = rlc(low)",
        [low.current(), rlc_low.current()],
        rlc.lookup(),
    );
    let randomness_raised_to_16 = randomness.clone().square().square().square().square();
    cb.assert_equal(
        "word_rlc = rlc(high) * randomness ^ 16 + rlc(low)",
        rlc_word.current(),
        rlc_high.current() * randomness_raised_to_16.clone() + rlc_low.current(),
    );
}
