use halo2_mpt_circuits::operation::AccountOp;
use halo2_mpt_circuits::serde::*;
use halo2_proofs::pairing::bn256::Fr as Fp;

#[test]
fn trace_parse_object() {
    let trace0: SMTTrace = serde_json::from_str(SMT_TRACE_EXAMPLE).unwrap();
    assert_eq!(
        trace0.account_path[0].path[0].value,
        Hash::try_from("0x4ea9d4a290473ecc2d3f25123515c1cd24f9317187837cbf798b9ec3f7c9ec0f")
            .unwrap()
    );

    let op: AccountOp<Fp> = (&trace0).try_into().unwrap();
    assert_eq!(
        op.acc_trie.old.leaf().unwrap(),
        op.account_before.unwrap().account_hash(),
    );
}

const TEST_TRACE1: &'static str = include_str!("./token_traces.json");
const TEST_TRACE2: &'static str = include_str!("./deploy_traces.json");

#[test]
fn trace_parse() {
    let traces: Vec<SMTTrace> = serde_json::from_str(TEST_TRACE1).unwrap();

    for tr in traces {
        let _: AccountOp<Fp> = (&tr).try_into().unwrap();
    }

    let traces: Vec<SMTTrace> = serde_json::from_str(TEST_TRACE2).unwrap();

    for tr in traces {
        let _: AccountOp<Fp> = (&tr).try_into().unwrap();
    }
}

const SMT_TRACE_EXAMPLE: &str = r#"
{
    "index": 122,
    "address": "0x05fdbdfae180345c6cff5316c286727cf1a43327",
    "accountKey": "0xfb6c28252d0ee14db1cdabda01391300ac75dcfdcda6ba1880e509aed4bc1225",
    "accountPath": [
        {
            "pathPart": "0x3",
            "root": "0xd5cba51852248915b4265454f4ceef34a34b10ad3a819a4b568104fd96d2280e",
            "path": [
                {
                    "value": "0x4ea9d4a290473ecc2d3f25123515c1cd24f9317187837cbf798b9ec3f7c9ec0f",
                    "sibling": "0x923ad76a4f3e4c63049db2818456f9037e49b5b467292e893b8fc3afe1cdd019"
                },
                {
                    "value": "0xb0dc4e59b50d8c8752055382e97d68b87442e6f890f91c6679044cb8c40cbf0a",
                    "sibling": "0xe2ed604a484416597397aba756822f61b2766fe43c487b34b0fe19ab864f8607"
                }
            ],
            "leaf": {
                "value": "0xa752c959446a834841df2e54e627e222d9fdc13f2e04000e26f63c5bd1abdc12",
                "sibling": "0xfb6c28252d0ee14db1cdabda01391300ac75dcfdcda6ba1880e509aed4bc1225"
            }
        },
        {
            "pathPart": "0x3",
            "root": "0x268e75a2c6986e031e3e7d88e4fc66a472e69df823ac59ff1da8a2738654791e",
            "path": [
                {
                    "value": "0x8d203e4d2b9fa13b281373af4c23830ecb7bb79f8f6924d8ebb629cc58e9811e",
                    "sibling": "0x923ad76a4f3e4c63049db2818456f9037e49b5b467292e893b8fc3afe1cdd019"
                },
                {
                    "value": "0xd42b1f9c974d478ce2666e6f703a929c2c0decfe4cb35b6cd034e73bc7fb8816",
                    "sibling": "0xe2ed604a484416597397aba756822f61b2766fe43c487b34b0fe19ab864f8607"
                }
            ],
            "leaf": {
                "value": "0x2a76cacad6031e98d2da2c33932f8e2672dcc6a6beac79c5865cec59c4174c10",
                "sibling": "0xfb6c28252d0ee14db1cdabda01391300ac75dcfdcda6ba1880e509aed4bc1225"
            }
        }
    ],
    "accountUpdate": [
        {
            "nonce": 1,
            "balance": "0x0",
            "codeHash": "0x09d2fd3a7cb9d5547a21c851248d703921e6348bfbdf4c0130695a3263f916ef"
        },
        {
            "nonce": 1,
            "balance": "0x0",
            "codeHash": "0x09d2fd3a7cb9d5547a21c851248d703921e6348bfbdf4c0130695a3263f916ef"
        }
    ],
    "stateKey": "0x6448b64684ee39a823d5fe5fd52431dc81e4817bf2c3ea3cab9e239efbf59820",
    "statePath": [
        {
            "pathPart": "0x0",
            "root": "0x0000000000000000000000000000000000000000000000000000000000000000"
        },
        {
            "pathPart": "0x0",
            "root": "0xd4153e6ea0fdc6f7c25844c5b7af55295be93ddc41d5570cc6856b0fb9287527",
            "leaf": {
                "value": "0xcae505636ece0f6fb9d660a8fafa3e0b29b52267c9fc03e72fd44642120f3f0e",
                "sibling": "0x6448b64684ee39a823d5fe5fd52431dc81e4817bf2c3ea3cab9e239efbf59820"
            }
        }
    ],
    "stateUpdate": [
        null,
        {
            "key": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "value": "0x00000000000000000000000000000000000000000000000000000181964e7585"
        }
    ]
}
"#;
