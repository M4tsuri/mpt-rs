//! This module defined the node structure.
//! We also implemented RLP encoding and decoding operations for these nodes.
//! To minimize the space required for storing the serialized nodes,
//! we use the following tricks described in the Yellow Papar and the original
//! Golang tire implementation:
//! 
//! 1. Encode all nibbles with hex-prefix encoding
//! 2. Indicate whether a node is leaf or extension with a single flag when encoding
//! 3. Encode all nodes with RLP encoding
//! 
//! It's rather difficult to achieve these with serlp library, for example, we have to 
//! determine node type from RLP encoded byte array. So we created some proxy types as 
//! a middle layer during encoding and decoding.

use serde::{Serialize, Deserialize, Serializer, ser::SerializeSeq};
use serde_bytes::{ByteBuf, Bytes};
use serlp::{
    rlp::{from_bytes, RlpNodeValue, to_bytes}, 
    de::RlpProxy,
    types::byte_array
};
use array_init::array_init;
use sha3::{Keccak256, Digest};

use crate::hex_prefix::{
    Nibbles,
    FLAG_MASK
};


const KEY_LEN: usize = 32;

pub type KecHash = [u8; KEY_LEN];

pub(crate) fn keccak256(rlp: &[u8]) -> KecHash {
    let mut hasher = Keccak256::default();
    hasher.update(rlp);
    hasher.finalize().into()
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub(crate) struct LeafNode {
    #[serde(with = "hex_prefix_leaf")]
    pub(crate) remained: Nibbles,
    #[serde(with = "serde_bytes")]
    pub(crate) value: Vec<u8>
}

mod hex_prefix_leaf {
    use serde::{Deserializer, Serializer};

    use crate::hex_prefix::{hex_prefix_encode, hex_prefix_decode};

    /// This just specializes [`serde_bytes::serialize`] to `<T = [u8]>`.
    pub(super) fn serialize<S>(nibbles: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = hex_prefix_encode(&nibbles, true);
        serde_bytes::serialize(&encoded, serializer)
    }

    /// This takes the result of [`serde_bytes::deserialize`] from `[u8]` to `[u8; N]`.
    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let slice: &[u8] = serde_bytes::deserialize(deserializer)?;
        let (decoded, flag) = hex_prefix_decode(slice);
        if flag != true { panic!("Wrong node type met when decoding.") }
        Ok(decoded)
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(from = "RlpProxy")]
pub(crate) enum Subtree {
    /// this field will be encoded into 0x80 with RLP encoding
    Empty,
    Node(Box<MptNode>),
    #[serde(with = "byte_array")]
    NodeKey(KecHash)
}

impl From<RlpProxy> for Subtree {
    fn from(node: RlpProxy) -> Self {
        let buf = node.raw();
        
        match buf.len() {
            // empty 
            1 if buf[0] == 0x80 => Subtree::Empty,
            1..=31 => Subtree::Node(Box::new(from_bytes(&buf).unwrap())),
            32.. => Subtree::NodeKey(from_bytes(&buf).unwrap()),
            _ => panic!("Error subtree encoding.")
        }
    }
}

#[derive(Deserialize, Serialize, Clone, PartialEq, Eq, Debug)]
pub(crate) struct ExtensionNode {
    #[serde(with = "hex_prefix_extension")]
    pub(crate) shared: Nibbles,
    pub(crate) subtree: Subtree
}

mod hex_prefix_extension {
    use serde::{Deserializer, Serializer};

    use crate::hex_prefix::{hex_prefix_encode, hex_prefix_decode};

    /// This just specializes [`serde_bytes::serialize`] to `<T = [u8]>`.
    pub(super) fn serialize<S>(nibbles: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = hex_prefix_encode(&nibbles, false);
        serde_bytes::serialize(&encoded, serializer)
    }

    /// This takes the result of [`serde_bytes::deserialize`] from `[u8]` to `[u8; N]`.
    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let slice: &[u8] = serde_bytes::deserialize(deserializer)?;
        let (decoded, flag) = hex_prefix_decode(slice);
        if flag != false { panic!("Wrong node type met when decoding.") }
        Ok(decoded)
    }
}

#[derive(Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(from = "RlpProxy")]
pub(crate) struct BranchNode {
    pub branchs: [Subtree; 16],
    /// vec is empty when this node is not leaf
    #[serde(with = "serde_bytes")]
    pub value: Vec<u8>
}

impl From<RlpProxy> for BranchNode {
    fn from(proxy: RlpProxy) -> Self {
        let mut tree = proxy.rlp_tree();
        let root = tree.root_mut();
        if let RlpNodeValue::Compound(compound) = &mut root.value {
            let branchs: [Subtree; 16] = array_init(|_| {
                from_bytes::<Subtree>(compound.pop_front().unwrap().span).unwrap()
            });
            let value: ByteBuf = from_bytes(compound.pop_front().unwrap().span).unwrap();
            Self {
                branchs,
                value: value.into_vec()
            }
        } else {
            panic!("Malformed Branch Node.")
        }
    }
}

impl Serialize for BranchNode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer 
    {
        let mut seq = serializer.serialize_seq(Some(17))?;
        for branch in &self.branchs {
            seq.serialize_element(branch)?;
        }
        seq.serialize_element(Bytes::new(&self.value))?;
        seq.end()
    }
}

impl BranchNode {
    pub fn new() -> Self {
        Self {
            branchs: array_init(|_| Subtree::Empty),
            value: Vec::new()
        }
    }

    pub fn branch(&mut self, idx: usize, value: Subtree) {
        self.branchs[idx] = value
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(from = "RlpProxy")]
pub(crate) enum MptNode {
    Leaf(LeafNode),
    Extension(ExtensionNode),
    Branch(BranchNode),
}

impl MptNode {
    pub fn encode(&self) -> (KecHash, Vec<u8>) {
        let encoded =to_bytes(self).unwrap();
        (keccak256(&encoded), encoded)
    }

    pub fn from_rlp(rlp: &[u8]) -> Self {
        from_bytes(rlp).unwrap()
    }
}

impl From<RlpProxy> for MptNode {
    fn from(proxy: RlpProxy) -> Self {
        let mut tree = proxy.rlp_tree();
        let root = tree.root();
        let buf = proxy.raw();

        if let RlpNodeValue::Compound(nodes) = &root.value {
            match nodes.len() {
                2 => {
                    let nibbles = tree.next().unwrap();
                    let flag = nibbles[0] & FLAG_MASK;
                    if flag == 0 {
                        MptNode::Extension(from_bytes(buf).unwrap())
                    } else {
                        MptNode::Leaf(from_bytes(buf).unwrap())
                    }
                },
                17 => MptNode::Branch(from_bytes(buf).unwrap()),
                _ => panic!("Unexpected node type.")
            }
        } else {
            panic!("Unexpected node type.")
        }
    }
}

impl From<LeafNode> for MptNode {
    fn from(node: LeafNode) -> Self { Self::Leaf(node) }
}

impl From<ExtensionNode> for MptNode {
    fn from(node: ExtensionNode) -> Self { Self::Extension(node) }
}

impl From<BranchNode> for MptNode {
    fn from(node: BranchNode) -> Self { Self::Branch(node) }
}

#[cfg(test)]
mod test_nodes {
    use serlp::rlp::RlpTree;

    use super::{LeafNode, BranchNode, ExtensionNode, MptNode, Subtree};

    #[test]
    fn test_extension_node() {
        let leaf = LeafNode {
            remained: vec![5, 0, 6],
            value: b"coin".to_vec()
        };

        let mut branch = BranchNode::new();

        branch.branch(0, Subtree::Node(Box::new(MptNode::Leaf(leaf.clone()))));
        branch.value = b"verb".to_vec();

        let extension = ExtensionNode {
            shared: vec![0, 1, 0, 2, 0, 3, 0, 4],
            subtree: Subtree::Node(Box::new(branch.into()))
        };

        let node = MptNode::Extension(extension.clone());

        // RLP encode
        let (hash, encoded) = node.encode();
        let expected = hex::decode("e4850001020304ddc882350684636f696e8080808080808080808080808080808476657262").unwrap();
        assert_eq!(encoded, expected);
        assert_eq!(hex::encode(hash), "64d67c5318a714d08de6958c0e63a05522642f3f1087c6fd68a97837f203d359");

        // RLP tree construction
        let expected_tree = RlpTree::new(&expected).unwrap();
        let real_tree = RlpTree::new(&encoded).unwrap();
        assert_eq!(expected_tree, real_tree);

        // RLP decode
        let decoded = MptNode::from_rlp(&encoded);
        assert_eq!(decoded, node);
    }
}
