use halo2_mpt_circuits::operation::AccountOp;
use halo2_mpt_circuits::serde::*;
pub use halo2_proofs::halo2curves::bn256::Fr as Fp;

#[test]
fn trace_parse_object() {
    let trace0: SMTTrace = serde_json::from_str(SMT_TRACE_EXAMPLE).unwrap();
    assert_eq!(
        trace0.account_path[0].path[0].value,
        Hash::try_from("0x0532e1b50d41522e91a1de10e2e56ca75422e2a2f60c2b610d379404b184262b")
            .unwrap()
    );

    let op: AccountOp<Fp> = (&trace0).try_into().unwrap();
    assert_eq!(
        op.acc_trie.old.leaf().unwrap(),
        op.account_before.unwrap().account_hash(),
    );
}

const TEST_TRACE1: &str = include_str!("./dual_code_hash/traces_1.json");
const TEST_TRACE2: &str = include_str!("./dual_code_hash/traces_1.json");

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

#[test]
fn trace_serialize() {
    let traces: SMTTrace = serde_json::from_str(SMT_TRACE_EXAMPLE).unwrap();

    let re_ser_fst = serde_json::to_string(&traces).unwrap();

    let traces: SMTTrace = serde_json::from_str(&re_ser_fst).unwrap();

    let re_ser_snd = serde_json::to_string(&traces).unwrap();

    assert_eq!(re_ser_fst, re_ser_snd);

    println!("{}", re_ser_snd);
}

const SMT_TRACE_EXAMPLE: &str = include_str!("./dual_code_hash/trace_1.json");
