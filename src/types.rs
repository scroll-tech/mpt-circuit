use ethers_core::types::{Address, U256};
use halo2_proofs::{arithmetic::FieldExt, halo2curves::bn256::Fr};
use itertools::{EitherOrBoth, Itertools};
use num_bigint::BigUint;
use num_traits::identities::Zero;

use crate::{
    operation::{Account, SMTPathParse},
    serde::{AccountData, HexBytes, SMTNode, SMTPath, SMTTrace},
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
    // you should just make make this an update or soemthing....
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
    // direction, open value, close value, sibling, is_padding_open, is_padding_close
    address_hash_traces: Vec<(bool, Fr, Fr, Fr, bool, bool)>,

    leafs: [[Fr; 2]; 2], // lol. you need these now.

    old_account_hash_traces: [[Fr; 3]; 6],
    new_account_hash_traces: [[Fr; 3]; 6],

    storage_hash_traces: Option<Vec<(bool, Fr, Fr, Fr, bool, bool)>>,
    // TODO: make this a struct plz.
    storage_key_value_hash_traces: Option<[[[Fr; 3]; 3]; 2]>,
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

// TODOOOOOOOO generic over value??????
struct LeafNode {
    key: Fr,
    value_hash: Fr,
}

impl From<&SMTTrace> for Claim {
    fn from(trace: &SMTTrace) -> Self {
        // TODO: this is doing a lot of extra work!!!!
        let [old_root, new_root] = trace.account_path.clone().map(path_root);
        let address = trace.address.0.into();
        Self {
            new_root,
            old_root,
            address,
            kind: ClaimKind::from(trace),
        }
    }
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

        let claim = Claim::from(&trace);

        // do storage stuff first, if needed.
        let (
            [old_storage_root, new_storage_root],
            storage_hash_traces,
            storage_key_value_hash_traces,
        ) = match (
            trace.common_state_root,
            trace.state_key,
            &trace.state_path,
            trace.state_update,
        ) {
            (Some(storage_root), None, [None, None], Some([None, None])) => {
                ([storage_root; 2].map(fr), None, None)
            }
            (None, Some(key), [Some(open), Some(close)], Some(storage_updates)) => {
                let leaf_hashes = [open, close].map(|path| {
                    path.leaf
                        .as_ref()
                        .map(|leaf| hash(hash(Fr::one(), fr(leaf.sibling)), fr(leaf.value)))
                        .unwrap_or_default()
                });
                (
                    [open.clone(), close.clone()].map(path_root),
                    Some(get_internal_hash_traces_storage(
                        fr(key),
                        leaf_hashes,
                        &(open.path),
                        &(close.path),
                    )),
                    None,
                    // Some([
                    //     storage_key_value_hash_traces(
                    //         u256_from_hex(old_leaf.key),
                    //         u256_from_hex(old_leaf.value),
                    //     ),
                    //     storage_key_value_hash_traces(
                    //         u256_from_hex(new_leaf.key),
                    //         u256_from_hex(new_leaf.value),
                    //     ),
                    // ]),
                )
            }
            _ => {
                unreachable!();
            }
        };

        let account_key = account_key(claim.address);
        let leafs = trace.account_path.clone().map(path_leaf);
        let [open_hash_traces, close_hash_traces] = trace.account_path.map(|path| path.path);
        let address_hash_traces =
            get_internal_hash_traces(account_key, leafs, &open_hash_traces, &close_hash_traces);

        let [old_account, new_account] = trace.account_update;
        let old_account_hash_traces = match old_account {
            None => empty_account_hash_traces(leafs[0]),
            Some(account) => account_hash_traces(claim.address, account, old_storage_root),
        };
        let new_account_hash_traces = match new_account {
            None => empty_account_hash_traces(leafs[1]),
            Some(account) => account_hash_traces(claim.address, account, new_storage_root),
        };

        Self {
            claim,
            address_hash_traces,
            old_account_hash_traces,
            new_account_hash_traces,
            leafs,
            storage_hash_traces,
            storage_key_value_hash_traces,
        }
    }
}

fn path_leaf(path: SMTPath) -> [Fr; 2] {
    if let Some(leaf) = path.leaf {
        [leaf.value, leaf.sibling].map(fr)
    } else {
        assert_eq!(path, SMTPath::default());
        [Fr::zero(), Fr::zero()]
    }
}

fn account_hash_traces(address: Address, account: AccountData, storage_root: Fr) -> [[Fr; 3]; 6] {
    let real_account: Account<Fr> = (&account, storage_root).try_into().unwrap();

    let (codehash_hi, codehash_lo) = hi_lo(account.code_hash);
    let h1 = hash(codehash_hi, codehash_lo);
    let h2 = hash(h1, storage_root);

    let nonce = Fr::from(account.nonce);
    let balance = balance_convert(account.balance);
    let h3 = hash(nonce, balance);

    let h4 = hash(h3, h2);

    let account_key = account_key(address);
    let h5 = hash(Fr::one(), account_key);

    let h6 = hash(h5, h4);

    let mut account_hash_traces = [[Fr::zero(); 3]; 6];
    account_hash_traces[0] = [codehash_hi, codehash_lo, h1];
    account_hash_traces[1] = [h1, storage_root, h2];
    account_hash_traces[2] = [nonce, balance, h3];
    account_hash_traces[3] = [h3, h2, h4]; //
    account_hash_traces[4] = [Fr::one(), account_key, h5]; // this should be the sibling?
    account_hash_traces[5] = [h5, h4, h6];

    // h4 is value of node?
    // h5 is sibling of node?
    assert_eq!(real_account.account_hash(), h4);
    account_hash_traces
}

fn get_internal_hash_traces(
    key: Fr,
    leafs: [[Fr; 2]; 2],
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
                hash(hash(Fr::one(), leafs[1][1]), leafs[1][0]),
                fr(open.sibling),
                false,
                true,
            ),
            EitherOrBoth::Right(close) => (
                key.bit(i),
                hash(hash(Fr::one(), leafs[0][1]), leafs[0][0]),
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

fn get_internal_hash_traces_storage(
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

fn empty_account_hash_traces(leafs: [Fr; 2]) -> [[Fr; 3]; 6] {
    let mut hash_traces = [[Fr::zero(); 3]; 6];

    let h5 = hash(Fr::one(), leafs[1]);
    let h6 = hash(h5, leafs[0]);

    hash_traces[4] = [Fr::one(), leafs[1], h5];
    hash_traces[5] = [h5, leafs[0], h6];

    hash_traces
}

fn storage_key_value_hash_traces(key: U256, value: U256) -> [[Fr; 3]; 3] {
    let (key_high, key_low) = split_word(key);
    let (value_high, value_low) = split_word(value);
    let h0 = hash(key_high, key_low);
    let h1 = hash(value_high, value_low);
    dbg!(
        hash(key_high, key_low),
        hash(value_high, value_low),
        hash(Fr::one(), hash(key_high, key_low)),
        hash(Fr::one(), hash(value_high, value_low)),
        hash(h0, h1),
        hash(h1, h0),
    );

    let mut hash_traces = [[Fr::zero(); 3]; 3];
    hash_traces[0] = [key_high, key_low, h0];
    hash_traces[1] = [value_high, value_low, h1];
    hash_traces[2] = [h0, h1, hash(h0, h1)];
    hash_traces
}

impl Proof {
    fn check(&self) {
        // poseidon hashes are correct
        check_hash_traces_new(&self.address_hash_traces);

        // directions match account key.
        let account_key = account_key(self.claim.address);
        for (i, (direction, _, _, _, _, _)) in self.address_hash_traces.iter().enumerate() {
            assert_eq!(
                *direction,
                account_key.bit(self.address_hash_traces.len() - i - 1)
            );
        }

        // old and new roots are correct
        if let Some((direction, open, close, sibling, is_padding_open, is_padding_close)) =
            self.address_hash_traces.last()
        {
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

        // this suggests we want something that keeps 1/2 unchanged if something....
        // going to have to add an is padding row or something?
        assert_eq!(
            self.old_account_hash_traces[5][2],
            self.address_hash_traces.get(0).unwrap().1
        );

        assert_eq!(
            self.new_account_hash_traces[5][2],
            self.address_hash_traces.get(0).unwrap().2
        );

        dbg!(self.old_account_hash_traces, self.leafs);

        assert_eq!(
            hash(hash(Fr::one(), self.leafs[0][1]), self.leafs[0][0]),
            self.old_account_hash_traces[5][2],
        );

        assert_eq!(
            hash(hash(Fr::one(), self.leafs[1][1]), self.leafs[1][0]),
            self.new_account_hash_traces[5][2],
        );

        // storage poseidon hashes are correct
        self.storage_hash_traces
            .as_ref()
            .map(|x| check_hash_traces_new(x.as_slice()));

        // directions match storage key hash.
        match self.claim.kind {
            ClaimKind::Read(Read::Storage { key, .. })
            | ClaimKind::Write(Write::Storage { key, .. })
            | ClaimKind::IsEmpty(Some(key)) => {
                let storage_key_hash = storage_key_hash(key);
                for (i, (direction, _, _, _, _, _)) in self
                    .storage_hash_traces
                    .as_ref()
                    .unwrap()
                    .iter()
                    .enumerate()
                {
                    assert_eq!(
                        *direction,
                        storage_key_hash
                            .bit(self.storage_hash_traces.as_ref().unwrap().len() - i - 1)
                    );
                }
            }
            _ => {}
        }

        // storage root is correct, if needed.
        if let Some(storage_update) = &self.storage_hash_traces {
            if let Some((direction, open, close, sibling, _, _)) =
                self.storage_hash_traces.as_ref().unwrap().last()
            {
                let old_storage_root = self.old_account_hash_traces[1][1];
                let new_storage_root = self.new_account_hash_traces[1][1];
                if *direction {
                    assert_eq!(hash(*sibling, *open), old_storage_root);
                    assert_eq!(hash(*sibling, *close), new_storage_root);
                } else {
                    assert_eq!(hash(*open, *sibling), old_storage_root);
                    assert_eq!(hash(*close, *sibling), new_storage_root);
                }
            } else {
                // TODO: check claimed read is 0
            }
        } else {
            // check claim does not involve storage.
        }

        // let [old_storage_root, new_storage_root] = if let Some(root) = trace.common_state_root {
        //     [root, root].map(fr)
        // } else {
        //     trace.state_path.clone().map(|p| path_root(p.unwrap()))
        // };
    }
}

fn check_hash_traces(traces: &[(bool, Fr, Fr, Fr)]) {
    let current_hash_traces = traces.iter();
    let mut next_hash_traces = traces.iter();
    next_hash_traces.next();
    for ((direction, open, close, sibling), (_, next_open, next_close, _)) in
        current_hash_traces.zip(next_hash_traces)
    {
        if *direction {
            assert_eq!(hash(*sibling, *open), *next_open);
            assert_eq!(hash(*sibling, *close), *next_close);
        } else {
            assert_eq!(hash(*open, *sibling), *next_open);
            assert_eq!(hash(*close, *sibling), *next_close);
        }
    }
}

fn check_hash_traces_new(traces: &[(bool, Fr, Fr, Fr, bool, bool)]) {
    let current_hash_traces = traces.iter();
    let mut next_hash_traces = traces.iter();
    next_hash_traces.next();
    for (
        (direction, open, close, sibling, is_padding_open, is_padding_close),
        (_, next_open, next_close, _, is_padding_open_next, is_padding_close_next),
    ) in current_hash_traces.zip(next_hash_traces)
    {
        if *direction {
            if *is_padding_open {

                // TODOOOOOO
            } else {
                assert_eq!(*is_padding_open_next, false);
                assert_eq!(hash(*sibling, *open), *next_open);
            }

            if *is_padding_close {
                // TODOOOOOO
            } else {
                assert_eq!(*is_padding_close_next, false);
                assert_eq!(hash(*sibling, *close), *next_close);
            }
        } else {
            if *is_padding_open {
                // TODOOOOOO
            } else {
                assert_eq!(*is_padding_open_next, false);
                assert_eq!(hash(*open, *sibling), *next_open);
            }

            if *is_padding_close {
                // TODOOOOOO
            } else {
                assert_eq!(*is_padding_close_next, false);
                assert_eq!(hash(*close, *sibling), *next_close);
            }
        }
    }
}

fn path_root(path: SMTPath) -> Fr {
    let parse: SMTPathParse<Fr> = SMTPathParse::try_from(&path).unwrap();
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

fn account_key(address: Address) -> Fr {
    // TODO: the names of these are reversed
    let high_bytes: [u8; 16] = address.0[..16].try_into().unwrap();
    let low_bytes: [u8; 4] = address.0[16..].try_into().unwrap();

    let address_high = Fr::from_u128(u128::from_be_bytes(high_bytes));
    let address_low = Fr::from_u128(u128::from(u32::from_be_bytes(low_bytes)) << 96);
    hash(address_high, address_low)
}

fn storage_key_hash(key: U256) -> Fr {
    let (high, low) = split_word(key);
    hash(high, low)
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

    const EMPTY_ACCOUNT_TRACE: &str = include_str!("../tests/empty_account.json");
    const EMPTY_STORAGE_TRACE: &str = include_str!("../tests/empty_storage.json");
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

    // #[test]
    // fn check_all() {
    //     // DEPLOY_TRACES(!?!?) has a trace where account nonce and balance change in one trace....
    //     for s in [TRACES, READ_TRACES, TOKEN_TRACES] {
    //         let traces: Vec<SMTTrace> = serde_json::from_str::<Vec<_>>(s).unwrap();
    //         for trace in traces {
    //             let proof = Proof::from(trace);
    //             proof.check();
    //             // break;
    //         }
    //         break;
    //     }
    // }

    #[test]
    fn check_all() {
        for s in [READ_TRACES, TOKEN_TRACES] {
            let traces: Vec<SMTTrace> = serde_json::from_str::<Vec<_>>(s).unwrap();
            for trace in traces {
                let proof = Proof::from(trace);
                proof.check();
            }
        }
    }

    #[test]
    fn check_empty_account() {
        let trace: SMTTrace = serde_json::from_str(EMPTY_ACCOUNT_TRACE).unwrap();
        let proof = Proof::from(trace);
        proof.check();
    }

    #[test]
    fn check_deploy_traces() {
        let traces: Vec<SMTTrace> = serde_json::from_str::<Vec<_>>(DEPLOY_TRACES).unwrap();
        for trace in traces {
            let proof = Proof::from(trace);
            proof.check();
        }
    }

    #[test]
    fn check_empty_storage_write() {
        let trace: SMTTrace = serde_json::from_str(EMPTY_STORAGE_TRACE).unwrap();
        let proof = Proof::from(trace);
        proof.check();
    }

    fn storage_roots(trace: &SMTTrace) -> [Fr; 2] {
        if let Some(root) = trace.common_state_root {
            [root, root].map(fr)
        } else {
            trace.state_path.clone().map(|p| path_root(p.unwrap()))
        }
    }

    #[test]
    fn sanity_check_paths() {
        for s in [READ_TRACES, TRACES, DEPLOY_TRACES, TOKEN_TRACES] {
            let traces: Vec<SMTTrace> = serde_json::from_str::<Vec<_>>(s).unwrap();
            for trace in traces {
                let address = trace.address.0.into();
                for (path, account) in trace.account_path.iter().zip_eq(trace.account_update) {
                    assert!(
                        contains(
                            &bits(
                                path.clone().path_part.try_into().unwrap(),
                                path.clone().path.len()
                            ),
                            account_key(address)
                        ),
                        "{:?}",
                        (address, path.path_part.clone(), account_key(address))
                    );
                }
            }
        }
    }

    fn contains(path: &[bool], key: Fr) -> bool {
        for (i, direction) in path.iter().rev().enumerate() {
            if key.bit(i) != *direction {
                return false;
            }
        }
        true
    }

    #[test]
    fn test_contains() {
        assert_eq!(contains(&[true, true], Fr::from(0b11)), true);
        assert_eq!(contains(&[], Fr::from(0b11)), true);

        assert_eq!(contains(&[false, false, false], Fr::zero()), true);

        assert_eq!(contains(&[false, false, true], Fr::one()), true);
        assert_eq!(contains(&[false, false, false], Fr::one()), false);
    }
}
