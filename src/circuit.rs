#[derive(Clone, Copy, Debug)]
struct Config {
    selector: Selector,
    exported_columns: [Column<Advice>; 10],
    binary_columns: [Column<Advice>; 6],
    field_columns: [Column<Advice>; 10],
}

// AddressKey -> Account -> StorageKey -> StorageLeaf

// StorageLeaf -> StorageKey -> Account -> AddressKey -> Root


// 5 -> 4 -> 3 -> 2 -> 1
