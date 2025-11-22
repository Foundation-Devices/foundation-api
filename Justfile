# Run clippy on all targets and features, treating warnings as errors
clippy:
    cargo clippy --all-targets --all-features -- -D warnings

# Run golden/snapshot tests
golden:
    cargo test -p foundation-api --test golden_tests

# Update golden/snapshot tests (accept all new snapshots)
golden-update:
    INSTA_UPDATE=always cargo test -p foundation-api --test golden_tests

# Review pending golden/snapshot changes interactively (requires cargo-insta)
golden-review:
    cargo insta review