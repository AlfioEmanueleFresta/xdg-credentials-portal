use crate::proto::CtapError;

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum TransportError {
    ConnectionFailed,
    ConnectionLost,
    InvalidEndpoint,
    InvalidFraming,
    NegotiationFailed,
}

impl std::error::Error for TransportError {}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Error {
    Transport(TransportError),
    Ctap(CtapError),
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<CtapError> for Error {
    fn from(error: CtapError) -> Self {
        Error::Ctap(error)
    }
}

impl From<TransportError> for Error {
    fn from(error: TransportError) -> Self {
        Error::Transport(error)
    }
}
