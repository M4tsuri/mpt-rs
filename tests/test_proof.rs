use std::collections::HashMap;

use mpt_rs::{mpt::{Trie, Database, KecHash}, proof::verify_prove};
use serde::{Deserialize, Serialize};
use num_bigint::BigUint;
use serde_bytes;
use serlp::types::{biguint, byte_array};
use hex;

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct LegacyTx {
    nonce: u64,
    #[serde(with = "biguint")]
    gas_price: BigUint,
    gas_limit: u64,
    #[serde(with = "byte_array")]
    to: [u8; 20],
    #[serde(with = "biguint")]
    value: BigUint,
    #[serde(with = "serde_bytes")]
    data: Vec<u8>,
    #[serde(with = "biguint")]
    v: BigUint,
    #[serde(with = "biguint")]
    r: BigUint,
    #[serde(with = "biguint")]
    s: BigUint
}

#[test]
fn test_tx() {
    let bn = |s| BigUint::from_bytes_be(&hex::decode(s).unwrap());
    let to_addr = |s| {
        let mut addr = [0; 20];
        addr.copy_from_slice(&hex::decode(s).unwrap());
        addr
    };
    let decode = |s| hex::decode(s).unwrap();

    let tx0 = LegacyTx {
        nonce: 0xa5,
        gas_price: bn("2e90edd000"),
        gas_limit: 0x12bc2,
        to: to_addr("a3bed4e1c75d00fa6f4e5e6922db7261b5e9acd2"),
        value: bn("00"),
        data: decode("a9059cbb0000000000000000000000008bda8b9823b8490e8cf220dc7b91d97da1c54e250000000000000000000000000000000000000000000000056bc75e2d63100000"),
        v: bn("26"),
        r: bn("6c89b57113cf7da8aed7911310e03d49be5e40de0bd73af4c9c54726c478691b"),
        s: bn("56223f039fab98d47c71f84190cf285ce8fc7d9181d6769387e5efd0a970e2e9")
    };

    let tx1 = LegacyTx {
        nonce: 0xa6,
        gas_price: bn("2e90edd000"),
        gas_limit: 0x12bc2,
        to: to_addr("a3bed4e1c75d00fa6f4e5e6922db7261b5e9acd2"),
        value: bn("00"),
        data: decode("a9059cbb0000000000000000000000008bda8b9823b8490e8cf220dc7b91d97da1c54e250000000000000000000000000000000000000000000000056bc75e2d63100000"),
        v: bn("26"),
        r: bn("d77c66153a661ecc986611dffda129e14528435ed3fd244c3afb0d434e9fd1c1"),
        s: bn("5ab202908bf6cbc9f57c595e6ef3229bce80a15cdf67487873e57cc7f5ad7c8a")
    };

    let tx2 = LegacyTx {
        nonce: 0x29f1,
        gas_price: bn("199c82cc00"),
        gas_limit: 0x5208,
        to: to_addr("88e9a2d38e66057e18545ce03b3ae9ce4fc36053"),
        value: bn("02ce7de1537c00"),
        data: vec![],
        v: bn("25"),
        r: bn("96e7a1d9683b205f697b4073a3e2f0d0ad42e708f03e899c61ed6a894a7f916a"),
        s: bn("5da238fbb96d41a4b5ec0338c86cfcb627d0aa8e556f21528e62f31c32f7e672")
    };

    let tx3 = LegacyTx {
        nonce: 0x6b25,
        gas_price: bn("199c82cc00"),
        gas_limit: 0x15f90,
        to: to_addr("e955ede0a3dbf651e2891356ecd0509c1edb8d9c"),
        value: bn("01051fdc4efdc000"),
        data: vec![],
        v: bn("25"),
        r: bn("2190f26e70a82d7f66354a13cda79b6af1aa808db768a787aeb348d425d7d0b3"),
        s: bn("6a82bd0518bc9b69dc551e20d772a1b06222edfc5d39b6973e4f4dc46ed8b196")
    };

    let txs = [tx0, tx1, tx2, tx3];
    let mut trie: Trie<MapDb, _, _> = Trie::new();

    for (i, tx) in txs.iter().enumerate() {
        trie = trie.insert(&i, tx);
    }

    println!("Root Hash: {}", hex::encode(trie.root_hash().unwrap()))
}

#[test]
fn test_extension() {
    let a = "a".to_string().repeat(1);
    let b = "b".to_string().repeat(20);
    let c = "c".to_string().repeat(35);
    let d = "d".to_string().repeat(400);

    let mut trie: Trie<MapDb, _, _> = Trie::new();

    trie = trie.insert(&"aaaa", &a);
    trie = trie.insert(&"aaaab", &b);
    let root_hash = trie.root_hash().unwrap();
    trie = trie.insert(&"aaaa", &c);
    trie = trie.insert(&"aa", &d);

    assert_eq!(b, trie.get(&"aaaab").unwrap());
    assert_eq!(None, trie.get(&"a"));
    assert_eq!(c, trie.get(&"aaaa").unwrap());
    assert_eq!(d, trie.get(&"aa").unwrap());

    // revert the state
    trie = trie.revert(root_hash);
    assert_eq!(a, trie.get(&"aaaa").unwrap());
}

#[test]
fn test_proof() {
    let a = "a".to_string().repeat(1);
    let b = "b".to_string().repeat(20);
    let c = "c".to_string().repeat(35);
    let d = "d".to_string().repeat(400);

    let mut trie: Trie<MapDb, _, _> = Trie::new();

    trie = trie.insert(&"aaaa", &a);
    trie = trie.insert(&"aaaab", &b);
    let old_root_hash = trie.root_hash().unwrap();
    trie = trie.insert(&"aaaa", &c);
    trie = trie.insert(&"aa", &d);
    let new_root_hash = trie.root_hash().unwrap();

    // proof of existence 
    let (proof, exists) = trie.prove::<MapDb>(&"aaaa");
    assert_eq!(exists, true);
    // verify with old hash, this should fail
    assert!(!verify_prove(&old_root_hash, &proof, &"aaaa"));
    // verify with the newest hash, should success
    assert!(verify_prove(&new_root_hash, &proof, &"aaaa"));

    // proof of non-existence
    let (proof, exists) = trie.prove::<MapDb>(&"a");
    assert_eq!(exists, false);
    // both should fail
    assert!(!verify_prove(&old_root_hash, &proof, &"a"));
    assert!(!verify_prove(&new_root_hash, &proof, &"a"));
}

#[derive(Debug, Clone)]
struct MapDb(HashMap<KecHash, Vec<u8>>);

impl Database for MapDb {
    fn new() -> Self {
        Self(HashMap::new())
    }

    fn insert(&mut self, key: &KecHash, value: Vec<u8>) {
        self.0.insert(*key, value);
    }

    fn exists(&mut self, key: &KecHash) -> bool {
        self.0.contains_key(key)
    }

    fn get(&self, key: &KecHash) -> Option<&Vec<u8>> {
        self.0.get(key)
    }
}
