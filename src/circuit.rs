#[derive(Clone, Copy, Debug)]
struct Config {
    storage_leafs: StorageLeafConfig,

    account_parents: AccountParentsConfig,
    account_leafs: AccountLeafConfig,

}

// AddressKey -> Account -> StorageKey -> StorageLeaf

// StorageLeaf -> StorageKey -> Account -> AddressKey -> Root


// 5 -> 4 -> 3 -> 2 -> 1
