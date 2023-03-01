// pub struct SMTTrace {
//     /// Address for the trace
//     pub address: Address,
//     /// key of account (hash of address)
//     pub account_key: Hash,
//     /// SMTPath for account
//     pub account_path: [SMTPath; 2],
//     /// update on accountData
//     pub account_update: [Option<AccountData>; 2],
//     /// SMTPath for storage,
//     pub state_path: [Option<SMTPath>; 2],
//     /// common State Root, if no change on storage part
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub common_state_root: Option<Hash>,
//     /// key of address (hash of storage address)
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub state_key: Option<Hash>,
//     /// update on storage
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub state_update: Option<[Option<StateData>; 2]>,
// }

// 0xd = 00001101
// 0xe = 00001110

#[cfg(test)]
mod test {
    use crate::hash::Hashable;
    use crate::operation::{Account, SMTPathParse};
    use crate::serde;
    use crate::serde::HexBytes;
    use halo2_proofs::arithmetic::FieldExt;
    use halo2_proofs::halo2curves::bn256::Fr;
    use num_bigint::BigUint;

    const TRACES: &str = include_str!("../tests/traces.json");
    const READ_TRACES: &str = include_str!("../tests/read_traces.json");
    const DEPLOY_TRACES: &str = include_str!("../tests/deploy_traces.json");
    const TOKEN_TRACES: &str = include_str!("../tests/token_traces.json");

    #[test]
    fn check() {
        for s in [TRACES, READ_TRACES, DEPLOY_TRACES, TOKEN_TRACES] {
            for trace in serde_json::from_str::<Vec<_>>(s).unwrap() {
                check_trace(trace);
            }
        }
    }

    fn check_trace(trace: serde::SMTTrace) {
        let [storage_root_before, _storage_root_after] = storage_roots(&trace);

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

        let [_state_root_before, _state_root_after] = trace.account_path.map(path_root);
    }

    fn storage_roots(trace: &serde::SMTTrace) -> [Fr; 2] {
        if let Some(root) = trace.common_state_root {
            [root, root].map(fr)
        } else {
            trace.state_path.clone().map(|p| path_root(p.unwrap()))
        }
    }

    fn path_root(path: serde::SMTPath) -> Fr {
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

    fn account_hash(account: serde::AccountData, state_root: Fr) -> Fr {
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

    fn fr(x: HexBytes<32>) -> Fr {
        Fr::from_bytes(&x.0).unwrap()
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
}
