use ethers_core::types::{Address, U256};
use halo2_proofs::{arithmetic::FieldExt, halo2curves::bn256::Fr};
use itertools::Itertools;
use num_bigint::BigUint;
use num_traits::identities::Zero;

use crate::{
    operation::{Account, SMTPathParse},
    serde::{AccountData, HexBytes, SMTPath, SMTTrace},
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
    address_hash_traces: Vec<(bool, Fr, Fr, Fr)>,
    old_account_hash_traces: [[Fr; 3]; 6],
    new_account_hash_traces: [[Fr; 3]; 6],

    leafs: [[Fr; 2]; 2],
    // storage_hash_traces: Vec<(bool, Fr, Fr, Fr)>,
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
                        // this is a non existance proof? i think??? probably not since it's covered above.
                        unimplemented!("non-existence proof?")
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
                        // apparently it's possible for more than one field to change.....
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
        dbg!(&trace);

        let leafs = trace.account_path.clone().map(path_leaf);

        let [old_root, new_root] = trace.account_path.clone().map(path_root);
        let address = trace.address.0.into();
        let claim = Claim {
            new_root,
            old_root,
            address,
            kind: ClaimKind::from(&trace),
        };

        let [open_hash_traces, close_hash_traces] = trace.account_path.map(|path| path.path);
        assert_eq!(open_hash_traces.len(), close_hash_traces.len());
        let path_length = open_hash_traces.len();

        let account_key = account_key(address);
        let mut address_hash_traces = vec![];
        for (i, (open, close)) in open_hash_traces
            .iter()
            .rev()
            .zip_eq(close_hash_traces.iter().rev())
            .enumerate()
        {
            assert_eq!(open.sibling, close.sibling);
            address_hash_traces.push((
                account_key.bit(path_length - 1 - i),
                fr(open.value),
                fr(close.value),
                fr(open.sibling),
            ));
        }

        let [old_account, new_account] = trace.account_update;
        let [old_state_root, new_state_root] = if let Some(root) = trace.common_state_root {
            [root, root].map(fr)
        } else {
            trace.state_path.clone().map(|p| path_root(p.unwrap()))
        };

        // account_update can be none for non-existing accounts?
        let old_account_hash_traces =
            account_hash_traces(address, old_account.unwrap(), old_state_root);
        let new_account_hash_traces =
            account_hash_traces(address, new_account.unwrap(), new_state_root);

        Self {
            claim,
            address_hash_traces,
            old_account_hash_traces,
            new_account_hash_traces,
            leafs,
        }
    }
}

fn path_leaf(path: SMTPath) -> [Fr; 2] {
    let leaf = path.leaf.unwrap();
    [leaf.value, leaf.sibling].map(fr)
}

fn account_hash_traces(address: Address, account: AccountData, state_root: Fr) -> [[Fr; 3]; 6] {
    let real_account: Account<Fr> = (&account, state_root).try_into().unwrap();
    dbg!(&real_account, real_account.account_hash());

    let (codehash_hi, codehash_lo) = hi_lo(account.code_hash);
    let h1 = hash(codehash_hi, codehash_lo);
    let h2 = hash(h1, state_root);

    let nonce = Fr::from(account.nonce);
    let balance = balance_convert(account.balance);
    let h3 = hash(nonce, balance);

    let h4 = hash(h3, h2);

    let account_key = account_key(address);
    let h5 = hash(Fr::one(), account_key);

    let h6 = hash(h5, h4);

    let mut account_hash_traces = [[Fr::zero(); 3]; 6];
    account_hash_traces[0] = [codehash_hi, codehash_lo, h1];
    account_hash_traces[1] = [h1, state_root, h2];
    account_hash_traces[2] = [nonce, balance, h3];
    account_hash_traces[3] = [h3, h2, h4];
    account_hash_traces[4] = [Fr::one(), account_key, h5];
    account_hash_traces[5] = [h5, h4, h6];

    assert_eq!(real_account.account_hash(), h4);
    dbg!("yay!!!!!");
    account_hash_traces
}

impl Proof {
    fn check(&self) {
        // poseidon hashes are correct
        let current_address_hash_traces = self.address_hash_traces.iter();
        let mut next_address_hash_traces = self.address_hash_traces.iter();
        next_address_hash_traces.next();
        for ((direction, open, close, sibling), (_, next_open, next_close, _)) in
            current_address_hash_traces.zip(next_address_hash_traces)
        {
            if *direction {
                assert_eq!(hash(*sibling, *open), *next_open);
                assert_eq!(hash(*sibling, *close), *next_close);
            } else {
                assert_eq!(hash(*open, *sibling), *next_open);
                assert_eq!(hash(*close, *sibling), *next_close);
            }
        }

        // directions match account key.
        let account_key = account_key(self.claim.address);
        for (i, (direction, _, _, _)) in self.address_hash_traces.iter().enumerate() {
            assert_eq!(
                *direction,
                account_key.bit(self.address_hash_traces.len() - i - 1)
            );
        }

        // mpt path matches account fields, if applicable.
        // let[ old_account, new_account ]=
        // let account_hash = account_hash(account, state_root);

        // mpt path matches storage key, if applicable.

        // old and new roots are correct
        if let Some((direction, open, close, sibling)) = self.address_hash_traces.last() {
            // dbg!(
            //     hash(*sibling, *open),
            //     hash(*open, *sibling),
            //     self.claim.old_root
            // );
            if *direction {
                assert_eq!(hash(*sibling, *open), self.claim.old_root);
                assert_eq!(hash(*sibling, *close), self.claim.new_root);
            } else {
                assert_eq!(hash(*open, *sibling), self.claim.old_root);
                assert_eq!(hash(*close, *sibling), self.claim.new_root);
            }
        } else {
            panic!("no hash traces!!!!");
        }


        dbg!(
            hash(Fr::one(), self.leafs[0][1]),
            hash(hash(Fr::one(), self.leafs[0][1]), self.leafs[0][0]),
            self.old_account_hash_traces,
            self.address_hash_traces.get(0).unwrap()
        );
        assert_eq!(
            self.old_account_hash_traces[5][2],
            self.address_hash_traces.get(0).unwrap().1
        );

        // want leaf node sibling and leaf node value

        // inputs match claim kind
        // match self.claim.kind {
        //     ClaimKind::Read(read) => match read {
        //         Read::Nonce(_) => panic!("nonce never happens?"),
        //         Read::Balance(_) => panic!("balance never happens?"),
        //         Read::CodeHash(_) => panic!("codehash never happens?"),
        //         Read::Storage { .. } => panic!("storage never happens?"),
        //     },
        //     ClaimKind::Write(write) => {}
        //     ClaimKind::IsEmpty(None) => {
        //         panic!("never happens?")
        //     }
        //     ClaimKind::IsEmpty(Some(key)) => {
        //         panic!("never happens?")
        //     }
        // }

        dbg!("ok!!!!");
    }
}

fn path_root(path: SMTPath) -> Fr {
    let parse: SMTPathParse<Fr> = SMTPathParse::try_from(&path).unwrap();
    // dbg!(&parse.0);
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

fn account_hash(account: AccountData, state_root: Fr) -> Fr {
    let real_account: Account<Fr> = (&account, state_root).try_into().unwrap();
    // dbg!(&real_account);

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

fn account_key(address: Address) -> Fr {
    let high_bytes: [u8; 16] = address.0[..16].try_into().unwrap();
    let low_bytes: [u8; 4] = address.0[16..].try_into().unwrap();

    let address_high = Fr::from_u128(u128::from_be_bytes(high_bytes));
    let address_low = Fr::from_u128(u128::from(u32::from_be_bytes(low_bytes)) << 96);
    hash(address_high, address_low)
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

trait Bit {
    fn bit(&self, i: usize) -> bool;
}

// // want to be able to not implement this....
// impl Bit for Address {
//     fn bit(&self, i: usize) -> bool {
//         self.0
//             .get(19 - i / 8)
//             .map_or_else(|| false, |&byte| byte & (1 << (i % 8)) != 0)
//     }
// }

impl Bit for Fr {
    fn bit(&self, i: usize) -> bool {
        let mut bytes = self.to_bytes();
        bytes.reverse();
        bytes
            .get(31 - i / 8)
            .map_or_else(|| false, |&byte| byte & (1 << (i % 8)) != 0)
    }
}
// bit method is already defined for U256, but is not what you want. you probably want to rename this trait.

#[cfg(test)]
mod test {
    use super::*;

    use crate::{operation::Account, serde::AccountData};

    const TRACES: &str = include_str!("../tests/traces.json");
    const READ_TRACES: &str = include_str!("../tests/read_traces.json");
    const DEPLOY_TRACES: &str = include_str!("../tests/deploy_traces.json");
    const TOKEN_TRACES: &str = include_str!("../tests/token_traces.json");

    #[test]
    fn bit_trait() {
        assert_eq!(Fr::one().bit(0), true);
        assert_eq!(Fr::one().bit(1), false);
    }

    #[test]
    fn check_path_part() {
        // DEPLOY_TRACES(!?!?) has a trace where account nonce and balance change in one trace....
        for s in [TRACES, READ_TRACES, TOKEN_TRACES] {
            let traces: Vec<SMTTrace> = serde_json::from_str::<Vec<_>>(s).unwrap();
            for trace in traces {
                let address = Address::from(trace.address.0);
                let [open, close] = trace.account_path;

                // not always true for deploy traces because account comes into existence.
                assert_eq!(open.path.len(), close.path.len());
                assert_eq!(open.path_part, close.path_part);

                let directions_1 = bits(open.path_part.try_into().unwrap(), open.path.len());
                let directions_2: Vec<_> = (0..open.path.len())
                    .map(|i| fr(trace.account_key).bit(open.path.len() - 1 - i))
                    .collect();
                assert_eq!(directions_1, directions_2);
            }
        }
    }

    #[test]
    fn check_account_key() {
        for s in [TRACES, READ_TRACES, TOKEN_TRACES] {
            let traces: Vec<SMTTrace> = serde_json::from_str::<Vec<_>>(s).unwrap();
            for trace in traces {
                let address = Address::from(trace.address.0);
                assert_eq!(fr(trace.account_key), account_key(address));
            }
        }
    }

    #[test]
    fn check_all() {
        // DEPLOY_TRACES(!?!?) has a trace where account nonce and balance change in one trace....
        for s in [TRACES, READ_TRACES, TOKEN_TRACES] {
            let traces: Vec<SMTTrace> = serde_json::from_str::<Vec<_>>(s).unwrap();
            for trace in traces {
                let proof = Proof::from(trace);
                proof.check();
                // break;
            }
            break;
        }
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
}
