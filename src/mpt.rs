//! A Merkle Patricia Tree maps a 256-bit length data structure into arbitary binary data.
//! This is an implementation of what is described in ETH Yellow Paper.

use std::{marker::PhantomData};

use serde::{Serialize, Deserialize};

use crate::{
    error::Result, 
    hex_prefix::to_nibbles,
    
};


pub trait KVMap<K, V> {
    fn new() -> Self;
    /// insert a value
    fn insert(&mut self, key: &K);
    fn exists(&mut self, key: &K) -> bool;
    fn get(&self, key: &K) -> V;
}

pub struct MerklePatriciaTree<'a, K, V, M> 
where
    V: Serialize + Deserialize<'a>,
    M: KVMap<DbKey, RLPEncoded>
{
    _v: PhantomData<&'a V>,
    /// When root is None, the tree is empty.
    /// As is defined in the yellow paper, this tree has no empty state. 
    /// I.e. if we need an empty tree, we need to make c(J, 0) empty.
    /// However, 
    ///  1. Branch node cannot be empty because we only use them when nessessary
    ///  2. Extension node cannot be empty because there is no such j != 0
    ///  3. Leaf node cannot be empty because ||J|| == 0 != 1
    root: Option<MPTNode>,
    map: M
}

impl<'a, V, M> MerklePatriciaTree<'a, V, M>
where
    V: Serialize + Deserialize<'a>,
    M: KVMap<MPTKey, Vec<u8>>
{
    pub fn new() -> Self {
        Self {
            _v: PhantomData::default(),
            root: MPTNode::Empty,
            map: M::new()
        }
    }

    pub fn insert(&mut self, value: &V) -> Result<MPTKey> {
        let key = MPTKey::new(value)?;
        let index_key = to_nibbles(&key.0);
        Self::insert_with_key(&mut self.root, &index_key, value);
        Ok(key)

    }

    fn insert_with_key(root: &mut MPTNode, key: &[u8], value: &V) {
        match root {
            MPTNode::Path(_) => todo!(),
            MPTNode::Branch(_) => todo!(),
            MPTNode::Empty => todo!()
        }
    }
}
