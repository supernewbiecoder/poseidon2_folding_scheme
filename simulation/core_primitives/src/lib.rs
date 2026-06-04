pub mod config;
pub mod poseidon2;
pub mod poseidon2_gadget;
pub mod merkle_tree;

// Re-export để dễ dùng ở crate khác
pub use config::EngramConfig;
pub use nova_snark::provider::pasta::pallas::Scalar as Fr;