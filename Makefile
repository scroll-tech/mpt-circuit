test:
	@cargo test

fmt:
	@cargo fmt

clippy:
	@cargo clippy --all-features

bench:
	@cargo bench --features bench
