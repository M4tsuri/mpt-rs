use serde::Serialize;
use serlp::rlp::to_bytes;

use crate::{node::MptNode, mpt::{Database, node_get, KecHash}, hex_prefix::bytes_to_nibbles};

pub fn verify_prove<ProofDb, K>(root_hash: &KecHash, proof: &ProofDb, key: &K) -> bool
where
    K: Serialize,
    ProofDb: Database
{
    let rlp_key = to_bytes(key).unwrap();
    let ikey = bytes_to_nibbles(&rlp_key);
    if let Some(rlp) = proof.get(&root_hash) {
        let root = MptNode::from_rlp(&rlp);
        node_get(&root, proof, &ikey).is_some()
    } else {
        false
    }
}