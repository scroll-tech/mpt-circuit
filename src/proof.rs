use ethers_core::types::{Address, U256};
use halo2_proofs::{arithmetic::FieldExt, halo2curves::bn256::Fr};
use itertools::{EitherOrBoth, Itertools};
use num_bigint::BigUint;
use num_traits::identities::Zero;

use crate::{
    operation::{Account, SMTPathParse},
    serde::{AccountData, HexBytes, SMTNode, SMTPath, SMTTrace, StateData},
    Hashable,
    types::Claim,
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
    fn new(key: Fr, paths: [SMTPath; 2], updates: [Option<AccountData>; 2], state_roots: [Fr; 2]) -> Self {
        unimplemented!()
    }
}

struct StorageHashTraces {
    parent_nodes: Vec<(bool, Fr, Fr, Fr, bool, bool)>,
    old_storage: Option<[HashTrace; 3]>,
    new_storage: Option<[HashTrace; 3]>,
}

impl StorageHashTraces {
    fn new(key: Fr, paths: [&SMTPath; 2], updates: [Option<StateData>; 2]) -> Self {
        unimplemented!()
    }

    fn roots(&self) -> [Fr; 2] {
        unimplemented!()
    }
}


struct HashTrace {
    left: Fr,
    right: Fr,
    out: Fr,
}

impl From<SMTTrace> for Proof {
    fn from(trace: SMTTrace) -> Self {
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

        // let account_key = account_key(claim.address);
        // let paths = trace.account_path.clone().map(|path| path.path);
        // let leaf_hashes = trace.account_path.clone().map(leaf_hash);
        // let address_hash_traces = get_internal_hash_traces(
        //     account_key,
        //     leaf_hashes,
        //     &open_hash_traces,
        //     &close_hash_traces,
        // );
        //
        // let leafs = trace.account_path.clone().map(get_leaf).map(|x| x.unwrap());
        // let [old_account, new_account] = trace.account_update;
        // let old_account_hash_traces = match old_account {
        //     None => empty_account_hash_traces(leafs[0]),
        //     Some(account) => account_hash_traces(claim.address, account, old_storage_root),
        // };
        // let new_account_hash_traces = match new_account {
        //     None => empty_account_hash_traces(leafs[1]),
        //     Some(account) => account_hash_traces(claim.address, account, new_storage_root),
        // };
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

fn fr(x: HexBytes<32>) -> Fr {
    Fr::from_bytes(&x.0).unwrap()
}
