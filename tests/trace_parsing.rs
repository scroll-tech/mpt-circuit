use halo2_mpt_circuits::serde::*;

const TEST_TRACE: &'static str = include_str!("../traces.jsonl");

#[test]
fn trace_parse() {
    let lines: Vec<&str> = TEST_TRACE.trim().split('\n').collect();

    let trace0: SMTTrace = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(
        trace0.account_path[0].path[0].value,
        Hash::try_from("0xb4f8bce5f7e6f384fbdf7561458705c55b25163e9aea66c862f5b8c40e13811d")
            .unwrap()
    );

    for ln in lines.into_iter().skip(1) {
        //println!("{}", ln);
        serde_json::from_str::<SMTTrace>(ln).unwrap();
    }
}
