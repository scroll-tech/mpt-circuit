// must be followed by
// if old hash is zero hash, then followed by NewPathExtensionConfig
// else if new hash is zero hash, followed by OldPathExtensionConfig
struct AccountUpdateConfig {
	old: AccountConfig,
	field: AdviceColumn,
	new_value: AdviceColumn,
}

struct NewPathExtensionConfig {
	new_hash: AdviceColumn,
	new_value: AdviceColumn,
	old_hash: AdviceColumn,
	old_value: AdviceColumn,

	sibling_hash: AdviceColumn,
}

struct OldPathExtensionConfig {
	new_hash: AdviceColumn,
	old_hash: AdviceColumn,

	sibling_hash: AdviceColumn,
}

struct CommonPathConfig {
	new_hash: AdviceColumn,
	old_hash: AdviceColumn,

	sibling_hash: AdviceColumn,
}
