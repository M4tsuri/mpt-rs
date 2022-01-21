use serde::{Serialize, Deserialize};
use serlp::rlp::to_bytes;
use sha3::{Keccak256, Digest};

use crate::error::Result;

const KEY_LEN: usize = 32;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DbKey([u8; KEY_LEN]);

impl DbKey {
    pub(crate) fn new(rlp: &[u8]) -> Self {
        let mut hasher = Keccak256::default();
        hasher.update(rlp);
        Self(hasher.finalize().into())
    }

    pub fn from_hexstring(s: &str) -> Self {
        let mut key = [0; KEY_LEN];
        key.copy_from_slice(&hex::decode(s).unwrap());
        Self(key)
    }

    pub fn hexstring(&self) -> String {
        hex::encode(&self.0)
    }
}

/// See https://github.com/serde-rs/bytes/issues/26
/// We have to manually implement serialize and deserialize 
/// until specification is supported in rust
pub(crate) mod serde_dbkey {
    use core::convert::TryInto;

    use serde::de::Error;
    use serde::{Deserializer, Serializer};

    use super::{DbKey, KEY_LEN};

    /// This just specializes [`serde_bytes::serialize`] to `<T = [u8]>`.
    pub(crate) fn serialize<S>(key: &DbKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_bytes::serialize(key.0.as_ref(), serializer)
    }

    /// This takes the result of [`serde_bytes::deserialize`] from `[u8]` to `[u8; N]`.
    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<DbKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let slice: &[u8] = serde_bytes::deserialize(deserializer)?;
        let array: [u8; KEY_LEN] = slice.try_into().map_err(|_| {
            let expected = format!("[u8; {}]", KEY_LEN);
            D::Error::invalid_length(slice.len(), &expected.as_str())
        })?;
        Ok(DbKey(array))
    }
}
