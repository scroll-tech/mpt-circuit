#[derive(Clone, Copy, Debug)]
struct Config<F> {
    address: Column<Advice>,
    address_high: Column<Advice>,
    address_low: Column<Advice>,

    nonce: Column<Advice>,
    balance: Column<Advice>,
    code_hash_high: Column<Advice>,
    code_hash_low: Column<Advice>,
    storage_root: Column<Advice>,

    h_0: Column<Advice>, // poseidon(code_hash_high, code_hash_low)
    h_1: Column<Advice>, // poseidon(nonce, balance)
    h_2: Column<Advice>, //
    h_3: Column<Advice>, //
    account_hash: Column<Advice>,
    key: Column<Advice>,
    leaf_hash: Column<Advice>,

    poseidon_table: PoseidonTable<F>,
}
