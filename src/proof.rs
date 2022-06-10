use crate::{merkle_root_from_branch, MerkleProof};
use primitive_types::H256;

/// A merkle proof object. The leaf, its path to the root, and its index in the
/// tree.
#[derive(Debug)]
pub struct Proof<const N: usize> {
    /// The leaf
    pub leaf: H256,
    /// The index
    pub index: usize,
    /// The merkle branch
    pub path: [H256; N],
}

impl<const N: usize> MerkleProof for Proof<N> {
    /// Calculate the merkle root produced by evaluating the proof
    fn root(&self) -> H256 {
        merkle_root_from_branch(self.leaf, self.path.as_ref(), N, self.index)
    }
}
