//! A Merkle Patricia Tree maps a 256-bit length data structure into arbitary binary data.
//! This is an implementation of what is described in ETH Yellow Paper.

use std::{marker::PhantomData, mem};

use serde::{Serialize, de::DeserializeOwned};
use serlp::rlp::{to_bytes, from_bytes};
use sha3::{Keccak256, Digest};

use crate::{
    hex_prefix::{bytes_to_nibbles, common_prefix},
    node::{MptNode, LeafNode, Subtree, BranchNode, ExtensionNode}, error::Error,
    error::{Result, TrieError}
};

pub const KEY_LEN: usize = 32;

pub type KecHash = [u8; KEY_LEN];

pub(crate) fn keccak256(rlp: &[u8]) -> KecHash {
    let mut hasher = Keccak256::default();
    hasher.update(rlp);
    hasher.finalize().into()
}

pub trait Database 
where
    Self: Sized
{
    fn new() -> Self;
    /// insert a value
    fn insert(&mut self, key: &KecHash, value: Vec<u8>) -> Result<()>;
    fn exists(&mut self, key: &KecHash) -> Result<bool>;
    fn get(&self, key: &KecHash) -> Result<Option<Vec<u8>>>;
}

#[derive(Clone)]
pub struct Trie<Db, K, V> 
where
    Db: Database,
    K: Serialize,
    V: Serialize + DeserializeOwned
{
    /// When root is None, the tree is empty.
    /// As is defined in the yellow paper, this tree has no empty state. 
    /// I.e. if we need an empty tree, we need to make c(J, 0) empty.
    /// However, 
    ///  1. Branch node cannot be empty because we only use them when nessessary
    ///  2. Extension node cannot be empty because there is no such j != 0
    ///  3. Leaf node cannot be empty because ||J|| == 0 != 1
    root: Option<MptNode>,
    pub db: Db,
    dirty: bool,
    root_hash: Option<KecHash>,
    _k: PhantomData<K>,
    _v: PhantomData<V>
}

impl<Db, K, V> Trie<Db, K, V>
where
    Db: Database,
    K: Serialize,
    V: Serialize + DeserializeOwned
{
    pub fn new(db: Db) -> Self {
        Self {
            root: None,
            db,
            dirty: false,
            root_hash: None,
            _k: PhantomData::default(),
            _v: PhantomData::default()
        }
    }

    pub fn revert(mut self, root_hash: KecHash) -> Result<Self> {
        if let Some(rlp) = self.db.get(&root_hash)? {
            self.root = Some(MptNode::from_rlp(&rlp)?);
            self.dirty = false;
            Ok(self)
        } else {
            Err(Error::StateNotFound)
        }
    }

    pub fn insert(mut self, key: &K, value: &V) -> Result<Self> {
        let ivalue = to_bytes(value)?;
        let rlp_key = to_bytes(key)?;
        let ikey = bytes_to_nibbles(&rlp_key);

        let root = mem::replace(&mut self.root, None);
        self.root = Some(match root {
            Some(root) => node_insert(root, &mut self.db, &ikey, ivalue)?,
            None => LeafNode {
                    remained: ikey,
                    value: ivalue
                }.into()
        });
        // inserted value, not the trie is dirty 
        self.dirty = true;

        Ok(self)
    }

    pub fn get(&self, key: &K) -> Result<Option<V>> {
        let rlp_key = to_bytes(key)?;
        let ikey = bytes_to_nibbles(&rlp_key);

        Ok(if let Some(root) = &self.root {
            if let Some(value) = node_get(root, &self.db, &ikey)? {
                Some(from_bytes(&value)?)
            } else {
                None
            }
        } else {
            None
        })
    }

    pub fn root_hash(&self) -> Option<KecHash> {
        self.root_hash
    }

    pub fn commit(&mut self) -> Result<Option<KecHash>> {
        if !self.dirty {
            return Ok(self.root_hash)
        }

        let root = mem::replace(&mut self.root, None);
        self.root = if let Some(root) = root {
            match node_collapse(root, &mut self.db)? {
                Subtree::Node(node) => {
                    let (dbkey, rlp) = node.encode()?;
                    self.db.insert(&dbkey, rlp)?;
                    self.root_hash = Some(dbkey);
                    Some(*node)
                },
                Subtree::NodeKey(dbkey) => {
                    let node = MptNode::from_rlp(
                        &self.db.get(&dbkey)?
                            .ok_or(Error::TrieError(TrieError::SubtreeNotFound))?
                    )?;
                    self.root_hash = Some(dbkey);
                    Some(node)
                },
                _ => unreachable!()
            }
        } else {
            self.root_hash = None;
            None
        };

        self.dirty = false;
        Ok(self.root_hash)
    }

    pub fn get_proof<ProofDb: Database>(&mut self, key: &K) -> Result<(ProofDb, bool)> {
        if self.dirty {
            self.commit()?;
        }

        let mut proof = ProofDb::new();

        let rlp_key = to_bytes(key)?;
        let ikey = bytes_to_nibbles(&rlp_key);

        let exists = if let Some(root) = &self.root {
            node_proof(root, &self.db, &mut proof, &ikey)?
        } else {
            false
        };

        Ok((proof, exists))
    }
}

/// collapse a node
/// returns (collapsed node, collapsed node length)
fn node_collapse<Db>(root: MptNode, db: &mut Db) -> Result<Subtree>
where
    Db: Database
{
    let rlp = to_bytes(&root)?;

    // this node do not need to be collapsed
    if rlp.len() < 32 {
        return Ok(Subtree::Node(Box::new(root)))
    }

    let node_collapsed = match root {
        MptNode::Leaf(_) => root,
        MptNode::Branch(BranchNode { branchs, value }) => {
            let mut collapsed_node = BranchNode::new();
            for (idx, branch) in branchs.into_iter().enumerate() {
                collapsed_node.branch(idx, subtree_collapse(branch, db)?);
            }
            collapsed_node.value = value;
            collapsed_node.into()
        },
        MptNode::Extension(ExtensionNode { shared, subtree }) => {
            ExtensionNode {
                shared: shared,
                subtree: subtree_collapse(subtree, db)?
            }.into()
        }
    };

    let (dbkey, rlp) = node_collapsed.encode()?;
    // after collapsing, a node either keeps unchanged, or part of it is committed to database,
    // in the later case, the node must contains a database key, whose length is 32
    // so the rlp length of collapsed node must exceeds the 32 byte limit
    assert!(rlp.len() >= 32);
    db.insert(&dbkey, rlp)?;
    Ok(Subtree::NodeKey(dbkey))
}

fn subtree_collapse<Db>(subtree: Subtree, db: &mut Db) -> Result<Subtree>
where 
    Db: Database
{
    match subtree {
        Subtree::Node(root) => node_collapse(*root, db),
        _ => Ok(subtree)
    }
}

fn node_proof<Db, ProofDb>(
    root: &MptNode, db: &Db, proof: &mut ProofDb, ikey: &[u8]
) -> Result<bool>
where
    Db: Database,
    ProofDb: Database
{
    let (hash, rlp) = root.encode()?;
    proof.insert(&hash, rlp)?;
    match root {
        MptNode::Leaf(leaf) => Ok(leaf.remained == ikey),
        MptNode::Extension(ExtensionNode { shared, subtree }) => {
            match common_prefix(&shared, ikey) {
                (_, [], key_remained) => {
                    subtree_proof(subtree, db, proof, key_remained)
                },
                _ => Ok(false)
            }
        },
        MptNode::Branch(branch) => {
            if ikey.is_empty() {
                Ok(false)
            } else {
                let (prefix, key_remained) = ikey.split_at(1);
                let idx = prefix[0] as usize;
                let subtree = &branch.branchs[idx];
                subtree_proof(subtree, db, proof, key_remained)
            }
        },
    }
}

fn subtree_proof<Db, ProofDb>(subtree: &Subtree, db: &Db, proof: &mut ProofDb, ikey: &[u8]) -> Result<bool>
where
    Db: Database,
    ProofDb: Database
{
    match subtree {
        Subtree::Empty => Ok(false),
        Subtree::Node(node) => node_proof(node, db, proof, ikey),
        Subtree::NodeKey(dbkey) => {
            let rlp = db.get(&dbkey)?
                .ok_or(Error::TrieError(TrieError::SubtreeNotFound))?;
            let root = MptNode::from_rlp(&rlp)?;
            node_proof(&root, db, proof, ikey)
        }
    }
}

/// get value with a key from the trie
pub(crate) fn node_get<Db>(
    root: &MptNode, db: &Db, ikey: &[u8]
) -> Result<Option<Vec<u8>>>
where
    Db: Database
{
    match root {
        MptNode::Leaf(LeafNode { remained, value: leaf_value }) => {
            if remained != ikey {
                Ok(None)
            } else {
                Ok(Some(leaf_value.clone()))
            }
        },
        MptNode::Extension(ExtensionNode { shared, subtree }) => {
            match common_prefix(&shared, ikey) {
                (_, [], key_remained) => subtree_get(subtree, db, key_remained),
                _ => Ok(None)
            }
        },
        MptNode::Branch(BranchNode { branchs, value }) => {
            if ikey.is_empty() {
                Ok(Some(value.clone()))
            } else {
                let (prefix, key_remained) = ikey.split_at(1);
                let idx = prefix[0] as usize;
                let subtree = &branchs[idx];
                subtree_get(subtree, db, key_remained)
            }
        },
    }
}

fn subtree_get<Db>(
    subtree: &Subtree, db: &Db, key: &[u8]
) -> Result<Option<Vec<u8>>>
where
    Db: Database
{
    match subtree {
        Subtree::Empty => Ok(None),
        Subtree::Node(node) => node_get(node, db, key),
        Subtree::NodeKey(dbkey) => {
            let rlp = db.get(&dbkey)?
                .ok_or(Error::TrieError(TrieError::SubtreeNotFound))?;
            let root = MptNode::from_rlp(&rlp)?;
            node_get(&root, db, key)
        }
    }
}

/// insert a key-value pair into trie.
/// Value is a owned Vec<u8> here intentionally to reduce heap allocation.
fn node_insert<Db>(
    root: MptNode, db: &mut Db, ikey: &[u8], ivalue: Vec<u8>
) -> Result<MptNode>
where
    Db: Database
{
    Ok(match root {
        // branch node, we choose the corresponding branch and visit it
        MptNode::Branch(BranchNode { mut branchs, value }) => {
            // we finally hit this branch
            if ikey.is_empty() {
                BranchNode {
                    branchs,
                    value: ivalue
                }
            } else {
                // now the first one nibble is comsumpted
                let (prefix, key) = ikey.split_at(1);
                let idx = prefix[0] as usize;
                let subtree = Subtree::Empty;
                // swap out the original subtree
                let subtree = mem::replace(&mut branchs[idx], subtree);
                branchs[idx] = subtree_insert(subtree, db, key, ivalue)?;
                BranchNode { branchs, value }
            }.into()
        },
        MptNode::Leaf(LeafNode { remained, value: leaf_value }) => {
            // match max common prefix 
            match common_prefix(ikey, &remained) {
                // full matched, replace the value
                (_, [], []) => {
                    LeafNode {
                        remained,
                        value: ivalue
                    }.into()
                },
                // not fully matched 
                (shared, key_remained, leaf_remained) => {
                    let branch = BranchNode::new().into();
                    let branch = node_insert(branch, db, key_remained, ivalue)?;
                    let branch = node_insert(branch, db, leaf_remained, leaf_value)?;

                    // has no common prefix
                    if shared.is_empty() {
                        branch
                    } else {
                        ExtensionNode {
                            shared: shared.to_vec(),
                            subtree: MptNode::from(branch).into()
                        }.into()
                    }
                },
            }
        },
        MptNode::Extension(ExtensionNode { shared, subtree }) => {
            assert!(shared.len() > 0);
            // match max common prefix 
            match common_prefix(ikey, &shared) {
                // shared fully matched, track to next node
                (_, key_remained, []) => {
                    ExtensionNode {
                        shared,
                        subtree: subtree_insert(subtree, db, key_remained, ivalue)?
                    }.into()
                },
                // here shared is not empty, so we build a extension first
                // leaf_remained is not empty
                (shared, key_remained, shared_remained) => {
                    let mut branch = BranchNode::new();
                    // length of shared must not less than 1
                    let (prefix, shared_remained) = shared_remained.split_at(1);
                    let idx = prefix[0] as usize;
                    if shared_remained.is_empty() {
                        branch.branch(idx, subtree);
                    } else {
                        branch.branch(idx, MptNode::from(ExtensionNode {
                            shared: shared_remained.to_vec(),
                            subtree
                        }).into());
                    }
                    
                    let node = node_insert(
                        branch.into(), db, key_remained, ivalue
                    )?;
                    if shared.is_empty() {
                        node
                    } else {
                        ExtensionNode {
                            shared: shared.to_vec(),
                            subtree: MptNode::from(node).into()
                        }.into()
                    }
                }
            }
        }
    })
}

fn subtree_insert<Db>(
    subtree: Subtree, db: &mut Db, key: &[u8], value: Vec<u8>
) -> Result<Subtree>
where 
    Db: Database
{
    Ok(Subtree::Node(Box::new(match subtree {
        // subtress is empty, we 
        Subtree::Empty => {
            LeafNode {
                remained: key.to_vec(),
                value: value.to_vec()
            }.into()
        },
        Subtree::Node(root) => {
            node_insert(*root, db, key, value)?
        },
        Subtree::NodeKey(dbkey) => {
            let rlp = db.get(&dbkey)?
                .ok_or(Error::TrieError(TrieError::SubtreeNotFound))?;
            let root = MptNode::from_rlp(&rlp)?;
            node_insert(root, db, key, value)?
        }
    })))
}
