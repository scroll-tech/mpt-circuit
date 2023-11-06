test:
	@cargo test

fmt:
	@cargo fmt

clippy:
	@cargo clippy --all-features -- -D warnings
