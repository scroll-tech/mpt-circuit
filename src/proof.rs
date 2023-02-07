use ethers_core::types::{Address, U256};
use halo2_proofs::{arithmetic::FieldExt, halo2curves::bn256::Fr};
use itertools::{EitherOrBoth, Itertools};
use num_bigint::BigUint;
use num_traits::identities::Zero;

use crate::{
    operation::{Account, SMTPathParse},
    serde::{AccountData, HexBytes, SMTNode, SMTPath, SMTTrace, StateData},
    types::Claim,
    Hashable,
};

struct Proof {
    claim: Claim,
    account: AccountHashTraces,
    storage: Option<StorageHashTraces>,
}

struct AccountHashTraces {
    parent_nodes: Vec<(bool, Fr, Fr, Fr, bool, bool)>,
    old_account: Option<[HashTrace; 6]>,
    new_account: Option<[HashTrace; 6]>,
}

impl AccountHashTraces {
    fn new(
        key: Fr,
        paths: [SMTPath; 2],
        updates: [Option<AccountData>; 2],
        state_roots: [Fr; 2],
    ) -> Self {
        unimplemented!()
    }
}

struct StorageHashTraces {
    parent_nodes: Vec<(bool, Fr, Fr, Fr, bool, bool)>,
    old_storage: Option<[HashTrace; 4]>,
    new_storage: Option<[HashTrace; 4]>,
}

impl StorageHashTraces {
    fn new(key: Fr, paths: [&SMTPath; 2], updates: [Option<StateData>; 2]) -> Self {
        let [old_leaf, new_leaf] = paths.map(|p| p.leaf);
        let [old_update, new_update] = updates;
        let old_storage = old_leaf.map(|leaf| get_storage_leaf_hash_traces(old_update, leaf));
        let new_storage = new_leaf.map(|leaf| get_storage_leaf_hash_traces(new_update, leaf));
        Self {
            parent_nodes: get_internal_hash_traces(
                key,
                [old_storage, new_storage]
                    .map(|hash_traces| hash_traces.map(|x| x[3].out).unwrap_or_default()),
                paths.map(|x| x.path.as_slice()),
            ),
            old_storage,
            new_storage,
        }
    }

    fn roots(&self) -> [Fr; 2] {
        if let Some((direction, open, close, sibling, is_open_padding, is_close_padding)) =
            self.parent_nodes.last()
        {
            [
                get_root(*direction, *open, *sibling, *is_open_padding),
                get_root(*direction, *close, *sibling, *is_close_padding),
            ]
        } else {
            [Fr::zero(); 2]
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct HashTrace {
    left: Fr,
    right: Fr,
    out: Fr,
}

impl HashTrace {
    fn new(left: Fr, right: Fr) -> Self {
        Self {
            left,
            right,
            out: hash(left, right),
        }
    }
}

impl From<SMTTrace> for Proof {
    fn from(trace: SMTTrace) -> Self {
        dbg!(&trace);
        let claim = Claim::from(&trace);

        let (storage_roots, storage) = match (
            trace.common_state_root,
            trace.state_key,
            &trace.state_path,
            trace.state_update,
        ) {
            (Some(storage_root), None, [None, None], Some([None, None])) => {
                ([storage_root; 2].map(fr), None)
            }
            (None, Some(key), [Some(open), Some(close)], Some(storage_updates)) => {
                let storage = StorageHashTraces::new(fr(key), [open, close], storage_updates);
                (storage.roots(), Some(storage))
            }
            _ => unreachable!(),
        };

        let account = AccountHashTraces::new(
            fr(trace.account_key),
            trace.account_path,
            trace.account_update,
            storage_roots,
        );

        Self {
            claim,
            account,
            storage,
        }
    }
}

fn get_internal_hash_traces(
    key: Fr,
    leaf_hashes: [Fr; 2],
    paths: [&[SMTNode]; 2],
) -> Vec<(bool, Fr, Fr, Fr, bool, bool)> {
    let [open_hash_traces, close_hash_traces] = paths;
    let path_length = std::cmp::max(open_hash_traces.len(), close_hash_traces.len());

    let mut address_hash_traces = vec![];
    for (i, e) in open_hash_traces
        .iter()
        .zip_longest(close_hash_traces.iter())
        .enumerate()
    {
        address_hash_traces.push(match e {
            EitherOrBoth::Both(open, close) => {
                assert_eq!(open.sibling, close.sibling);
                (
                    key.bit(i),
                    fr(open.value),
                    fr(close.value),
                    fr(open.sibling),
                    false,
                    false,
                )
            }
            EitherOrBoth::Left(open) => (
                key.bit(i),
                fr(open.value),
                leaf_hashes[1],
                fr(open.sibling),
                false,
                true,
            ),
            EitherOrBoth::Right(close) => (
                key.bit(i),
                leaf_hashes[0],
                fr(close.value),
                fr(close.sibling),
                true,
                false,
            ),
        });
    }
    address_hash_traces.reverse();
    address_hash_traces
}

fn get_root(direction: bool, value: Fr, sibling: Fr, is_padding: bool) -> Fr {
    if is_padding {
        Fr::zero()
    } else if direction {
        hash(value, sibling)
    } else {
        hash(sibling, value)
    }
}

fn get_storage_leaf_hash_traces(state_data: Option<StateData>, leaf: SMTNode) -> [HashTrace; 4] {
    let mut hash_traces = [HashTrace::default(); 4];
    if let Some(state_data) = state_data {
        let (key_high, key_low) = split_word(u256_from_hex(state_data.key));
        let (value_high, value_low) = split_word(u256_from_hex(state_data.value));
        hash_traces[0] = HashTrace::new(key_high, key_low);
        hash_traces[1] = HashTrace::new(value_high, value_low);

        // Sanity check that the leaf matches the value hash, if present.
        assert_eq!(hash_traces[1].out, fr(leaf.value));
    }
    hash_traces[2] = HashTrace::new(Fr::one(), fr(leaf.sibling));
    hash_traces[3] = HashTrace::new(hash_traces[3].out, fr(leaf.value));

    hash_traces
}

fn fr(x: HexBytes<32>) -> Fr {
    Fr::from_bytes(&x.0).unwrap()
}

fn hash(x: Fr, y: Fr) -> Fr {
    Hashable::hash([x, y])
}

trait Bit {
    fn bit(&self, i: usize) -> bool;
}

impl Bit for Fr {
    fn bit(&self, i: usize) -> bool {
        let mut bytes = self.to_bytes();
        bytes.reverse();
        bytes
            .get(31 - i / 8)
            .map_or_else(|| false, |&byte| byte & (1 << (i % 8)) != 0)
    }
}

fn u256_from_hex(x: HexBytes<32>) -> U256 {
    U256::from_big_endian(&x.0)
}

fn split_word(x: U256) -> (Fr, Fr) {
    let mut bytes = [0; 32];
    x.to_big_endian(&mut bytes);
    let high_bytes: [u8; 16] = bytes[..16].try_into().unwrap();
    let low_bytes: [u8; 16] = bytes[16..].try_into().unwrap();

    let high = Fr::from_u128(u128::from_be_bytes(high_bytes));
    let low = Fr::from_u128(u128::from_be_bytes(low_bytes));
    (high, low)

    // TODO: what's wrong with this?
    // let [limb_0, limb_1, limb_2, limb_3] = key.0;
    // let key_high = Fr::from_u128(u128::from(limb_2) + u128::from(limb_3) << 64);
    // let key_low = Fr::from_u128(u128::from(limb_0) + u128::from(limb_1) << 64);
    // hash(key_high, key_low)
}

#[cfg(test)]
mod test {
    use super::*;

    const EMPTY_STORAGE_TRACE: &str = include_str!("../tests/empty_storage.json");

    #[test]
    fn check_empty_storage_write() {
        let trace: SMTTrace = serde_json::from_str(EMPTY_STORAGE_TRACE).unwrap();
        let proof = Proof::from(trace);
    }
}
