use serlp;

#[derive(Debug)]
pub enum Error {
    EncodingError(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<serlp::error::Error> for Error {
    fn from(ser: serlp::error::Error) -> Self {
        Error::EncodingError(ser.to_string())
    }
}
