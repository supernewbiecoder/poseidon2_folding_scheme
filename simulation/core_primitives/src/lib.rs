pub mod config;
pub mod poseidon2;
pub mod merkle_tree;

// Re-export để dễ dùng ở crate khác
pub use config::EngramConfig;
pub use pasta_curves::pallas::Scalar as Fr;