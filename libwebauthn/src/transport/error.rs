pub use crate::proto::CtapError;

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum PlatformError {
    PinTooShort,
    PinTooLong,
    PinNotSupported,
}

impl std::error::Error for PlatformError {}

impl std::fmt::Display for PlatformError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum TransportError {
    ConnectionFailed,
    ConnectionLost,
    InvalidEndpoint,
    InvalidFraming,
    NegotiationFailed,
    TransportUnavailable,
    Timeout,
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
    Platform(PlatformError),
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

impl From<PlatformError> for Error {
    fn from(error: PlatformError) -> Self {
        Error::Platform(error)
    }
}
