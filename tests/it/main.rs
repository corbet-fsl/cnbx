//! The crate's integration tests in one binary.
//!
//! Every former `tests/<name>.rs` is a module here, so a warm edit loop links one test
//! executable instead of one per file. The test names keep their module prefix
//! (`<name>::<test>`), and `tests/it/support` holds the shared fixtures they all use.
mod authority;
mod contacts;
mod handle;
mod inbox;
mod release;
mod support;
mod waves;
