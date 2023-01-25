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
    use crate::operation::{MPTPath, SMTPathParse};
    use crate::serde;
    use crate::serde::HexBytes;
    use halo2_proofs::arithmetic::FieldExt;
    use halo2_proofs::halo2curves::bn256::Fr;

    const TRACES: &str = include_str!("../tests/traces.json");
    const READ_TRACES: &str = include_str!("../tests/read_traces.json");
    const DEPLOY_TRACES: &str = include_str!("../tests/deploy_traces.json");
    const TOKEN_TRACES: &str = include_str!("../tests/token_traces.json");

    #[test]
    fn check() {
        for s in [TRACES, READ_TRACES, DEPLOY_TRACES, TOKEN_TRACES] {
            let traces: Vec<serde::SMTTrace> = serde_json::from_str(s).unwrap();
            for trace in traces {
                check_trace(trace);
            }
        }
    }

    fn check_trace(trace: serde::SMTTrace) {
        let [storage_root_before, storage_root_after] = if let Some(root) = trace.common_state_root
        {
            [root, root].map(fr)
        } else {
            trace.state_path.map(|p| path_root(p.unwrap()))
        };
        // let storage_root = trace.common_state_root.or().unwrap()
        // let [account_hash_after, account_hash_before] = trace.account_update.iter().zip(trace.state)map(||)account_hash()

        let [state_root_before, state_root_after] = trace.account_path.map(path_root);
    }

    fn path_root(path: serde::SMTPath) -> Fr {
        let account_hash = if let Some(node) = path.clone().leaf {
            hash(hash(Fr::one(), fr(node.sibling)), fr(node.value))
        } else {
            return Fr::zero()
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
        fr(path.root)
    }

    // fn account_hash(account: serde::AccountData, state_root: Fr) -> Fr {
    //     let h1 = hash(account.codehash.0, account.codehash.1);
    //     let h3 = hash(account.nonce, account.balance);
    //     let h2 = hash(h1, state_root);
    //     hash(h3, h2)
    // }

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
}
