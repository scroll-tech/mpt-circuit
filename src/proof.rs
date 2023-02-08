use ethers_core::types::{Address, U256};
use halo2_proofs::{arithmetic::FieldExt, halo2curves::bn256::Fr};
use itertools::{EitherOrBoth, Itertools};
use num_bigint::BigUint;
use num_traits::identities::Zero;

use crate::{
    operation::{Account, SMTPathParse},
    serde::{AccountData, HexBytes, SMTNode, SMTPath, SMTTrace, StateData},
    types::Claim,
    util::{balance_convert, fr, hash, hi_lo, split_word, u256_from_hex, Bit},
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
        [old_update, new_update]: [Option<AccountData>; 2],
        [old_storage_root, new_storage_root]: [Fr; 2],
    ) -> Self {
        let [old_leaf, new_leaf] = paths.clone().map(|p| p.leaf);
        let old_account =
            old_leaf.map(|leaf| get_account_hash_traces(key, old_update, old_storage_root, leaf));
        let new_account =
            new_leaf.map(|leaf| get_account_hash_traces(key, new_update, new_storage_root, leaf));

        let parent_nodes = get_internal_hash_traces(
            key,
            [old_account, new_account]
                .map(|hash_traces| hash_traces.map(|x| x[3].out).unwrap_or_default()),
            &paths[0].path,
            &paths[1].path,
        );

        Self {
            parent_nodes,
            old_account,
            new_account,
        }
    }
}

struct StorageHashTraces {
    parent_nodes: Vec<(bool, Fr, Fr, Fr, bool, bool)>,
    old_storage: Option<[HashTrace; 4]>,
    new_storage: Option<[HashTrace; 4]>,
}

impl StorageHashTraces {
    fn new(key: Fr, paths: [&SMTPath; 2], updates: [Option<StateData>; 2]) -> Self {
        let [old_leaf, new_leaf] = paths.clone().map(|p| p.leaf);
        let [old_update, new_update] = updates;
        let old_storage = old_leaf.map(|leaf| get_storage_leaf_hash_traces(old_update, leaf));
        let new_storage = new_leaf.map(|leaf| get_storage_leaf_hash_traces(new_update, leaf));

        let parent_nodes = get_internal_hash_traces(
            key,
            [old_storage, new_storage]
                .map(|hash_traces| hash_traces.map(|x| x[3].out).unwrap_or_default()),
            &paths[0].path,
            &paths[1].path,
        );

        Self {
            parent_nodes,
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
            let old_root = self.old_storage.map_or_else(Fr::zero, |h| h[3].out);
            let new_root = self.new_storage.map_or_else(Fr::zero, |h| h[3].out);
            [old_root, new_root]
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct HashTrace {
    pub left: Fr,
    pub right: Fr,
    pub out: Fr,
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
    open_hash_traces: &[SMTNode],
    close_hash_traces: &[SMTNode],
) -> Vec<(bool, Fr, Fr, Fr, bool, bool)> {
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
        panic!(); // this is dead code i think
        value
    } else if direction {
        hash(sibling, value)
    } else {
        hash(value, sibling)
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
        dbg!(state_data, leaf);

        if hash_traces[1].out != fr(leaf.value) {
            assert_eq!(u256_from_hex(state_data.value), U256::zero());
        } else {
            assert_eq!(hash_traces[1].out, fr(leaf.value));
        }
    }
    hash_traces[2] = HashTrace::new(Fr::one(), fr(leaf.sibling));
    hash_traces[3] = HashTrace::new(hash_traces[2].out, fr(leaf.value));

    hash_traces
}

fn get_account_hash_traces(
    key: Fr,
    account_data: Option<AccountData>,
    storage_root: Fr, // this is actually optional? what if there is no account?
    leaf: SMTNode,
) -> [HashTrace; 6] {
    let mut hash_traces = [HashTrace::default(); 6];
    if let Some(account_data) = account_data {
        let (codehash_hi, codehash_lo) = hi_lo(&account_data.code_hash);
        let nonce = Fr::from(account_data.nonce);
        let balance = balance_convert(&account_data.balance);

        hash_traces[0] = HashTrace::new(codehash_hi, codehash_lo);
        hash_traces[1] = HashTrace::new(hash_traces[0].out, storage_root);
        hash_traces[2] = HashTrace::new(nonce, balance);
        hash_traces[3] = HashTrace::new(hash_traces[2].out, hash_traces[1].out);

        // Sanity check we calculated the account hash correctly.
        let real_account: Account<Fr> = (&account_data, storage_root).try_into().unwrap();
        assert_eq!(real_account.account_hash(), hash_traces[3].out);

        // Sanity check that the leaf matches the value hash, if present.
        dbg!(hash_traces, leaf);
        assert_eq!(hash_traces[3].out, fr(leaf.value));
    }
    hash_traces[4] = HashTrace::new(Fr::one(), fr(leaf.sibling));
    hash_traces[5] = HashTrace::new(hash_traces[4].out, fr(leaf.value));
    hash_traces
}

#[cfg(test)]
mod test {
    use super::*;

    const EMPTY_ACCOUNT_TRACE: &str = include_str!("../tests/empty_account.json");
    const EMPTY_STORAGE_TRACE: &str = include_str!("../tests/empty_storage.json");
    const TRACES: &str = include_str!("../tests/traces.json");
    const READ_TRACES: &str = include_str!("../tests/read_traces.json");
    const DEPLOY_TRACES: &str = include_str!("../tests/deploy_traces.json");
    const TOKEN_TRACES: &str = include_str!("../tests/token_traces.json");

    #[test]
    fn check_empty_storage() {
        let empty_storage = include_str!("../tests/empty_storage.json");
        let trace: SMTTrace = serde_json::from_str(empty_storage).unwrap();
        let proof = Proof::from(trace);
    }

    #[test]
    fn empty_account() {
        let empty_storage = include_str!("../tests/empty_account.json");
        let trace: SMTTrace = serde_json::from_str(empty_storage).unwrap();
        let proof = Proof::from(trace);
    }

    #[test]
    fn read_traces() {
        for s in [READ_TRACES] {
            let traces: Vec<SMTTrace> = serde_json::from_str::<Vec<_>>(s).unwrap();
            for trace in traces {
                let proof = Proof::from(trace);
            }
        }
    }

    #[test]
    fn deploy_traces() {
        for s in [DEPLOY_TRACES] {
            let traces: Vec<SMTTrace> = serde_json::from_str::<Vec<_>>(s).unwrap();
            for trace in traces {
                let proof = Proof::from(trace);
            }
        }
    }

    #[test]
    fn token_traces() {
        for s in [TOKEN_TRACES] {
            let traces: Vec<SMTTrace> = serde_json::from_str::<Vec<_>>(s).unwrap();
            for trace in traces {
                let proof = Proof::from(trace);
            }
        }
    }
}
