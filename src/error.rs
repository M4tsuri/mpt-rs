use std::fmt::Display;

use serlp;

#[derive(Debug)]
pub enum TrieError {
    SubtreeNotFound
}

#[derive(Debug)]
pub enum Error {
    EncodingError(String),
    DatabaseError(String),
    StateNotFound,
    TrieError(TrieError),
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", format!("{:?}", self))
    }
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<serlp::error::Error> for Error {
    fn from(ser: serlp::error::Error) -> Self {
        Error::EncodingError(ser.to_string())
    }
}



