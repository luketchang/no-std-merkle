#![no_std]
#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
#![warn(missing_debug_implementations)]
#![warn(missing_copy_implementations)]

extern crate thiserror_no_std as thiserror;

extern crate alloc;

/// Hashing utils
pub mod utils;

/// Common error types for the merkle trees.
pub mod error;

/// A lightweight incremental merkle, suitable for running on-chain. Stores O
/// (1) data
pub mod light;
/// Merkle Proof struct
pub mod proof;

use primitive_types::{H256, U256};

/// Tree depth
pub const TREE_DEPTH: usize = 32;
/// An incremental Nomad protocol standard-depth tree
pub type NomadLightMerkle = light::LightMerkle<TREE_DEPTH>;
/// A Nomad protocol standard-depth proof
pub type NomadProof = proof::Proof<TREE_DEPTH>;


pub use error::*;
pub use light::*;
pub use proof::*;

pub use utils::*;

lazy_static::lazy_static! {
    /// A cache of the zero hashes for each layer of the tree.
    pub static ref ZERO_HASHES: [H256; TREE_DEPTH + 1] = {
        let mut hashes = [H256::zero(); TREE_DEPTH + 1];
        for i in 0..TREE_DEPTH {
            hashes[i + 1] = hash_concat(hashes[i], hashes[i]);
        }
        hashes
    };
}

/// A merkle proof
pub trait MerkleProof {
    /// Calculate the merkle root of this proof's branch
    fn root(&self) -> H256;
}

/// A simple trait for merkle-based accumulators
pub trait Merkle: core::fmt::Debug + Default {
    /// A proof of some leaf in this tree
    type Proof: MerkleProof;

    /// The maximum number of elements the tree can ingest
    fn max_elements() -> U256;

    /// The number of elements currently in the tree
    fn count(&self) -> usize;

    /// Calculate the root hash of this Merkle tree.
    fn root(&self) -> H256;

    /// Get the tree's depth.
    fn depth(&self) -> usize;

    /// Push a leaf to the tree
    fn ingest(&mut self, element: H256) -> Result<H256, IngestionError>;

    /// Verify a proof against this tree's root.
    fn verify(&self, proof: &Self::Proof) -> Result<(), VerifyingError> {
        let actual = proof.root();
        let expected = self.root();
        if expected == actual {
            Ok(())
        } else {
            Err(VerifyingError::VerificationFailed { expected, actual })
        }
    }
}
