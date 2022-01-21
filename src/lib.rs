// pub mod mpt;
mod hex_prefix;
pub mod error;
mod node;
mod key;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
