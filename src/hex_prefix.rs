//! This is an implementation of hex-prefix encoding

use std::ptr::NonNull;

/// This type represents a nibble list, in which each element represents a single nibble
pub(crate) type Nibbles = Vec<u8>;
/// This type represents a hex-prefix encoded nibble list, 
/// in which two nibbles are compressed into one bytes
pub(crate) type HPNibbles = Vec<u8>;

const ODD_MASK: u8 = 0b00010000;
pub(crate) const FLAG_MASK: u8 = 0b00100000;

/// This function encodes an array of nibbles together with a boolean flag into a byte array
/// Each element of src should all be nibbles. 
/// Passing slice with element with non-zero high 4-bit will lead to undefined behavior
pub fn hex_prefix_encode<'a>(src: &'a [u8], flag: bool) -> HPNibbles {
    let encode_nibbles = |x: &'a [u8]| x.chunks(2).map(|two| (two[0] << 4) | two[1]);
    let mut res = Vec::new();
    // the length is odd
    if src.len() & 1 == 1 {
        res.push(((((flag as u8) << 1) | 1) << 4) | src[0]);
        res.extend(encode_nibbles(&src[1..]));
    // the length is even
    } else {
        res.push(((flag as u8) << 1) << 4);
        res.extend(encode_nibbles(src));
    }
    res
}

pub fn hex_prefix_decode(src: &[u8]) -> (Nibbles, bool) {
    if src.is_empty() {
        panic!("Empty slice met when hex-prefix decoding.");
    }

    let mut nibbles: Nibbles = Vec::new();
    let (prefix, encoded) = src.split_at(1);

    if src[0] & ODD_MASK != 0 {
        // odd length, nibbles start at src[0][..4]
        nibbles.push(prefix[0] & 0x0f);
    }
    nibbles.extend(encoded.iter().map(|i| [(i & 0xf0) >> 4, i & 0x0f]).flatten());

    (nibbles, prefix[0] & FLAG_MASK != 0)
}

pub fn common_prefix<'a, 'b>(a: &'a [u8], b: &'b [u8]) -> (&'a [u8], &'a [u8], &'b [u8]) {
    let min = a.len().min(b.len());

    let split = |i| {
        (
            &a[..i],
            if i < a.len() { &a[i..a.len()] } else { &[] },
            if i < b.len() { &b[i..b.len()] } else { &[] }
        )
    };

    for i in 0..min {
        if a[i] != b[i] {
            return split(i)
        }
    }
    return split(min)
}

pub fn bytes_to_nibbles(src: &[u8]) -> Nibbles {
    src.iter().map(|x| {
        [x & 0xf0 >> 4, x & 0x0f]
    }).flatten().collect()
}

