//! This is an implementation of hex-prefix encoding

/// This function encodes an array of nibbles together with a boolean flag into a byte array
/// 
pub fn hex_prefix_encode<'a>(src: &'a [u8], flag: bool) -> Vec<u8> {
    let encode_nibbles = |x: &'a [u8]| x.chunks(2).map(|two| (two[0] << 4) + two[1]);
    let mut res = Vec::new();
    // the length is odd
    if src.len() & 1 == 1 {
        res.push(((((flag as u8) << 1) + 1) << 4) + src[0]);
        res.extend(encode_nibbles(&src[1..]));
    // the length is even
    } else {
        res.push(((flag as u8) << 1) << 4);
        res.extend(encode_nibbles(src));
    }
    res
}

