//! A Merkle Patricia Tree maps a 256-bit length data structure into arbitary binary data.
//! This is an implementation of what is described in ETH Yellow Paper.

use std::{marker::PhantomData, mem};

use serde::{Serialize, Deserialize};
use serlp::rlp::to_bytes;

use crate::{
    error::Result, 
    hex_prefix::{bytes_to_nibbles, common_prefix},
    node::{MptNode, LeafNode, Subtree, BranchNode, ExtensionNode, KecHash},
    
};


pub trait Database {
    fn new() -> Self;
    /// insert a value
    fn insert(&mut self, key: &KecHash, value: Vec<u8>);
    fn exists(&mut self, key: &KecHash) -> bool;
    fn get(&self, key: &KecHash) -> &Vec<u8>;
}

pub struct Trie<'a, Db, K, V> 
where
    Db: Database,
    K: Serialize,
    V: Serialize + Deserialize<'a>
{
    /// When root is None, the tree is empty.
    /// As is defined in the yellow paper, this tree has no empty state. 
    /// I.e. if we need an empty tree, we need to make c(J, 0) empty.
    /// However, 
    ///  1. Branch node cannot be empty because we only use them when nessessary
    ///  2. Extension node cannot be empty because there is no such j != 0
    ///  3. Leaf node cannot be empty because ||J|| == 0 != 1
    root: Option<MptNode>,
    db: &'a mut Db,
    _k: PhantomData<K>,
    _v: PhantomData<V>
}

impl<'a, Db, K, V> Trie<'a, Db, K, V>
where
    Db: Database,
    K: Serialize,
    V: Serialize + Deserialize<'a>
{
    pub fn new(db: &'a mut Db) -> Self {
        Self {
            root: None,
            db,
            _k: PhantomData::default(),
            _v: PhantomData::default()
        }
    }

    pub fn insert(self, key: &K, value: &V) -> Result<Self> {
        let ivalue = to_bytes(value)?;
        let rlp_key = to_bytes(key)?;
        let ikey = bytes_to_nibbles(&rlp_key);

        let node = match self.root {
            Some(root) => node_insert(root, self.db, &ikey, ivalue),
            None => LeafNode {
                    remained: ikey,
                    value: ivalue
                }.into()
        };
        Ok(Self {
            root: Some(node),
            db: self.db,
            _k: PhantomData::default(),
            _v: PhantomData::default()
        })
    }
}


/// insert a key-value pair into trie.
/// Value is a owned Vec<u8> here intentionally to reduce heap allocation.
fn node_insert<Db>(root: MptNode, db: &mut Db, ikey: &[u8], ivalue: Vec<u8>) -> MptNode
where
    Db: Database
{
    match root {
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
                branchs[idx] = subtree_insert(subtree, db, key, ivalue);
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
                    let branch = node_insert(branch, db, key_remained, ivalue);
                    let branch = node_insert(branch, db, leaf_remained, leaf_value);

                    // has no common prefix
                    if shared.is_empty() {
                        branch
                    } else {
                        ExtensionNode {
                            shared: shared.to_vec(),
                            subtree: pack_subtree(db, branch)
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
                        subtree: subtree_insert(subtree, db, key_remained, ivalue)
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
                        branch.branch(idx, pack_subtree(db, ExtensionNode {
                            shared: shared_remained.to_vec(),
                            subtree
                        }.into()));
                    }
                    
                    let node = node_insert(branch.into(), db, key_remained, ivalue);
                    if shared.is_empty() {
                        node
                    } else {
                        ExtensionNode {
                            shared: shared.to_vec(),
                            subtree: pack_subtree(db, node)
                        }.into()
                    }
                }
            }
        }
    }
}

fn subtree_insert<Db>(subtree: Subtree, db: &mut Db, key: &[u8], value: Vec<u8>) -> Subtree
where 
    Db: Database
{
    let node = match subtree {
        // subtress is empty, we 
        Subtree::Empty => {
            LeafNode {
                remained: key.to_vec(),
                value: value.to_vec()
            }.into()
        },
        Subtree::Node(root) => {
            node_insert(*root, db, key, value)
        },
        Subtree::NodeKey(dbkey) => {
            let rlp = db.get(&dbkey);
            let root = MptNode::from_rlp(&rlp);
            node_insert(root, db, key, value)
        }
    };
    pack_subtree(db, node)
}

/// pack a key-value pair into a subtree
fn pack_subtree<Db>(db: &mut Db, node: MptNode) -> Subtree 
where
    Db: Database
{
    let (dbkey, rlp) = node.encode();

    if rlp.len() < 32 {
        Subtree::Node(Box::new(node))
    } else {
        db.insert(&dbkey, rlp);
        Subtree::NodeKey(dbkey)
    }
}
