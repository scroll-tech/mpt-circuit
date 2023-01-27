use ethers_core::types::{Address, U256};
use halo2_proofs::{arithmetic::FieldExt, halo2curves::bn256::Fr};
use num_bigint::BigUint;
use num_traits::identities::Zero;

use crate::{
    operation::SMTPathParse,
    serde::{HexBytes, SMTPath, SMTTrace},
    Hashable,
};

#[derive(Clone, Copy, Debug)]
struct Claim {
    old_root: Fr,
    new_root: Fr,
    address: Address,
    kind: ClaimKind,
}

#[derive(Clone, Copy, Debug)]
enum ClaimKind {
    Read(Read),
    Write(Write),
    IsEmpty(Option<U256>),
}

#[derive(Clone, Copy, Debug)]
enum Read {
    Nonce(u64),
    Balance(U256),
    CodeHash(U256),
    // CodeSize(u64),
    // PoseidonCodeHash(Fr),
    Storage { key: U256, value: U256 },
}

#[derive(Clone, Copy, Debug)]
enum Write {
    Nonce {
        old: Option<u64>,
        new: Option<u64>,
    },
    Balance {
        old: Option<U256>,
        new: Option<U256>,
    },
    CodeHash {
        old: Option<U256>,
        new: Option<U256>,
    },
    // CodeSize...,
    // PoseidonCodeHash...,
    Storage {
        key: U256,
        old_value: Option<U256>,
        new_value: Option<U256>,
    },
}

#[derive(Clone, Debug)]
struct Proof {
    claim: Claim,
    hash_traces: Vec<(NodeKind, (Fr, Fr, Fr), (Fr, Fr, Fr))>,
}

#[derive(Clone, Copy, Debug)]
enum NodeKind {
    AddressPrefix(bool),
    AddressTail(Address),
    CodeHashHighLow,
    NonceBalance,
    StorageKeyPrefix(bool),
    StorageKeyTail(U256),
}

impl From<&SMTTrace> for ClaimKind {
    fn from(trace: &SMTTrace) -> Self {
        let [account_old, account_new] = &trace.account_update;
        let state_update = &trace.state_update;

        if let Some(update) = state_update {
            match update {
                [None, None] => (),
                [Some(old), Some(new)] => {
                    assert_eq!(account_old, account_new, "{:?}", state_update);
                    return if old == new {
                        ClaimKind::Read(Read::Storage {
                            key: u256_from_hex(old.key),
                            value: u256_from_hex(old.value),
                        })
                    } else {
                        ClaimKind::Write(Write::Storage {
                            key: u256_from_hex(old.key),
                            old_value: Some(u256_from_hex(old.value)),
                            new_value: Some(u256_from_hex(new.value)),
                        })
                    };
                }
                [None, Some(new)] => {
                    assert_eq!(account_old, account_new, "{:?}", state_update);
                    return ClaimKind::Write(Write::Storage {
                        key: u256_from_hex(new.key),
                        old_value: None,
                        new_value: Some(u256_from_hex(new.value)),
                    });
                }
                [Some(old), None] => {
                    unimplemented!("SELFDESTRUCT")
                }
            }
        }

        match &trace.account_update {
            [None, None] => ClaimKind::IsEmpty(None),
            [None, Some(new)] => {
                let write = match (
                    !new.nonce.is_zero(),
                    !new.balance.is_zero(),
                    !new.code_hash.is_zero(),
                ) {
                    (true, false, false) => Write::Nonce {
                        old: None,
                        new: Some(new.nonce.into()),
                    },
                    (false, true, false) => Write::Balance {
                        old: None,
                        new: Some(u256(&new.balance)),
                    },
                    (false, false, true) => Write::CodeHash {
                        old: None,
                        new: Some(u256(&new.code_hash)),
                    },
                    (false, false, false) => {
                        dbg!(trace);
                        // this is a non existance proof.
                        unimplemented!("storage key update")
                    }
                    _ => unreachable!("at most one account field change expected"),
                };
                ClaimKind::Write(write)
            }
            [Some(old), None] => unimplemented!("SELFDESTRUCT"),
            [Some(old), Some(new)] => {
                let write = match (
                    old.nonce != new.nonce,
                    old.balance != new.balance,
                    old.code_hash != new.code_hash,
                ) {
                    (true, false, false) => Write::Nonce {
                        old: Some(old.nonce.into()),
                        new: Some(new.nonce.into()),
                    },
                    (false, true, false) => Write::Balance {
                        old: Some(u256(&old.balance)),
                        new: Some(u256(&new.balance)),
                    },
                    (false, false, true) => Write::CodeHash {
                        old: Some(u256(&old.code_hash)),
                        new: Some(u256(&new.code_hash)),
                    },
                    (false, false, false) => {
                        // Note that there's no way to tell what kind of account read was done from the trace.
                        return ClaimKind::Read(Read::Nonce(old.nonce.into()));
                    }
                    _ => {
                        dbg!(old, new);
                        // return ClaimKind::Read(Read::Nonce(old.nonce.into()));
                        // ok apparently it's possible for more than one field to change.....
                        unreachable!("at most one account field change expected")
                    }
                };
                ClaimKind::Write(write)
            }
        }
    }
}

impl From<SMTTrace> for Proof {
    fn from(trace: SMTTrace) -> Self {
        let [old_root, new_root] = trace.account_path.clone().map(path_root);
        let address = trace.address.0.into(); // TODO: check that this is in the right order.
        let claim = Claim {
            new_root,
            old_root,
            address,
            kind: ClaimKind::from(&trace),
        };

        Self {
            claim,
            hash_traces: vec![],
        }
    }
}

fn path_root(path: SMTPath) -> Fr {
    let parse: SMTPathParse<Fr> = SMTPathParse::try_from(&path).unwrap();
    dbg!(&parse.0);
    for (a, b, c) in parse.0.hash_traces {
        assert_eq!(hash(a, b), c)
    }

    let account_hash = if let Some(node) = path.clone().leaf {
        hash(hash(Fr::one(), fr(node.sibling)), fr(node.value))
    } else {
        Fr::zero()
    };

    let directions = bits(path.path_part.clone().try_into().unwrap(), path.path.len());
    let mut digest = account_hash;
    for (&bit, node) in directions.iter().zip(path.path.iter().rev()) {
        assert_eq!(digest, fr(node.value));
        digest = if bit {
            hash(fr(node.sibling), digest)
        } else {
            hash(digest, fr(node.sibling))
        };
    }
    assert_eq!(digest, fr(path.root));
    fr(path.root)
}

fn bits(x: usize, len: usize) -> Vec<bool> {
    let mut bits = vec![];
    let mut x = x;
    while x != 0 {
        bits.push(x % 2 == 1);
        x /= 2;
    }
    bits.resize(len, false);
    bits.reverse();
    bits
}

fn fr(x: HexBytes<32>) -> Fr {
    Fr::from_bytes(&x.0).unwrap()
}

fn u256(x: &BigUint) -> U256 {
    U256::from_big_endian(&x.to_bytes_be())
}

fn u256_from_hex(x: HexBytes<32>) -> U256 {
    U256::from_big_endian(&x.0)
}

fn hash(x: Fr, y: Fr) -> Fr {
    Hashable::hash([x, y])
}

fn balance_convert(balance: BigUint) -> Fr {
    balance
        .to_u64_digits()
        .iter()
        .rev() // to_u64_digits has least significant digit is first
        .fold(Fr::zero(), |a, b| {
            a * Fr::from(1 << 32).square() + Fr::from(*b)
        })
}

fn hi_lo(x: BigUint) -> (Fr, Fr) {
    let mut u64_digits = x.to_u64_digits();
    u64_digits.resize(4, 0);
    (
        Fr::from_u128((u128::from(u64_digits[3]) << 64) + u128::from(u64_digits[2])),
        Fr::from_u128((u128::from(u64_digits[1]) << 64) + u128::from(u64_digits[0])),
    )
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::{operation::Account, serde::AccountData};

    const TRACES: &str = include_str!("../tests/traces.json");
    const READ_TRACES: &str = include_str!("../tests/read_traces.json");
    const DEPLOY_TRACES: &str = include_str!("../tests/deploy_traces.json");
    const TOKEN_TRACES: &str = include_str!("../tests/token_traces.json");

    #[test]
    fn check_all() {
        // DEPLOY_TRACES(!?!?) has a trace where account nonce and balance change in one trace....
        for s in [TRACES, READ_TRACES, TOKEN_TRACES] {
            let traces: Vec<SMTTrace> = serde_json::from_str::<Vec<_>>(s).unwrap();
            for trace in traces {
                let proof = Proof::from(trace);
                // proof.check();
            }
        }
    }

    fn check_trace(trace: SMTTrace) {
        let [storage_root_before, storage_root_after] = storage_roots(&trace);

        if let Some(account_before) = trace.account_update[0].clone() {
            dbg!("yess????");
            let leaf_before_value = fr(trace.account_path[0].clone().leaf.unwrap().value);
            let leaf_before_sibling = fr(trace.account_path[0].clone().leaf.unwrap().sibling);
            dbg!(
                trace.account_key.clone(),
                trace.account_update.clone(),
                trace.common_state_root.clone(),
                trace.address.clone()
            );
            dbg!(leaf_before_value, leaf_before_sibling);

            let account_hash = account_hash(account_before.clone(), storage_root_before);

            dbg!(account_hash, leaf_before_value, leaf_before_sibling);
            assert_eq!(account_hash, leaf_before_value);
            dbg!("yessssss!");
        }

        // let leaf = acc_trie
        //     .old
        //     .leaf()
        //     .expect("leaf should exist when there is account data");
        // let old_state_root = state_trie
        //     .as_ref()
        //     .map(|s| s.start_root())
        //     .unwrap_or(comm_state_root);
        // let account: Account<Fp> = (account_data, old_state_root).try_into()?;
        // // sanity check
        // assert_eq!(account.account_hash(), leaf);

        // let storage_root = trace.common_state_root.or().unwrap()
        // let [account_hash_after, account_hash_before] = trace.account_update.iter().zip(trace.state)map(||)account_hash()

        let [state_root_before, state_root_after] = trace.account_path.map(path_root);
    }

    fn storage_roots(trace: &SMTTrace) -> [Fr; 2] {
        if let Some(root) = trace.common_state_root {
            [root, root].map(fr)
        } else {
            trace.state_path.clone().map(|p| path_root(p.unwrap()))
        }
    }

    fn path_root(path: SMTPath) -> Fr {
        let parse: SMTPathParse<Fr> = SMTPathParse::try_from(&path).unwrap();
        dbg!(&parse.0);
        for (a, b, c) in parse.0.hash_traces {
            assert_eq!(hash(a, b), c)
        }

        let account_hash = if let Some(node) = path.clone().leaf {
            hash(hash(Fr::one(), fr(node.sibling)), fr(node.value))
        } else {
            // we are here but this is not correct?
            // sometimes there is no storage root. is this only for empty accounts, or just for accounts where the storage is empty?
            // my theory is that this only happens for emtpy storage trees
            // this should always be present for account paths.
            // it is option for storage paths.
            // return Fr::zero();
            Fr::zero()
            // dbg!(path);
            // unimplemented!("does this happen for non-existing accounts?");
        };

        let directions = bits(path.path_part.clone().try_into().unwrap(), path.path.len());
        let mut digest = account_hash;
        for (&bit, node) in directions.iter().zip(path.path.iter().rev()) {
            assert_eq!(digest, fr(node.value));
            digest = if bit {
                hash(fr(node.sibling), digest)
            } else {
                hash(digest, fr(node.sibling))
            };
        }
        assert_eq!(digest, fr(path.root));
        dbg!("yay!!!!");
        fr(path.root)
    }

    fn account_hash(account: AccountData, state_root: Fr) -> Fr {
        let real_account: Account<Fr> = (&account, state_root).try_into().unwrap();
        dbg!(&real_account);

        let (codehash_hi, codehash_lo) = hi_lo(account.code_hash);
        // dbg!(codehash_hi, codehash_lo);

        let h1 = hash(codehash_hi, codehash_lo);
        let h3 = hash(Fr::from(account.nonce), balance_convert(account.balance));
        let h2 = hash(h1, state_root);
        // dbg!(h1, h2, h3, hash(h3, h2));

        // dbg!(hash(Fr::one(), hash(h3, h2)));

        let result = hash(h3, h2);
        assert_eq!(result, real_account.account_hash());
        result
    }

    fn bits(x: usize, len: usize) -> Vec<bool> {
        let mut bits = vec![];
        let mut x = x;
        while x != 0 {
            bits.push(x % 2 == 1);
            x /= 2;
        }
        bits.resize(len, false);
        bits.reverse();
        bits
    }
}
