test:
	@cargo test

test_par:
	PARALLEL_SYN=true cargo test -- --nocapture

fmt:
	@cargo fmt

clippy:
	@cargo clippy --all-features

bench:
	PARALLEL_SYN=true cargo bench --features bench
