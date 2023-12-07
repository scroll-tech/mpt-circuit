test:
	@cargo test

test_par:
	PARALLEL_SYN=true cargo test -- --nocapture

fmt:
	@cargo fmt

clippy:
	@cargo clippy --all-features

bench:
	@cargo bench --features bench
