use serde::Serialize;
use serlp::rlp::to_bytes;

use crate::{node::MptNode, mpt::{Database, node_get, KecHash}, hex_prefix::bytes_to_nibbles};
use crate::error::Result;

pub fn verify_proof<ProofDb, K>(
    root_hash: &KecHash, proof: &ProofDb, key: &K
) -> Result<bool>
where
    K: Serialize,
    ProofDb: Database
{
    let rlp_key = to_bytes(key)?;
    let ikey = bytes_to_nibbles(&rlp_key);
    Ok(if let Some(rlp) = proof.get(&root_hash)? {
        let root = MptNode::from_rlp(&rlp)?;
        node_get(&root, proof, &ikey)?.is_some()
    } else {
        false
    })
}