use crate::ops::u2f::Error as U2FError;
use crate::ops::webauthn::Error as WebauthnError;

#[derive(Debug)]
pub enum Error {
    AuthenticatorError, // Does not behave as an authenticator should.
    ConnectionLost,
    NegotiationFailed,
    UnsupportedRequestVersion,
    InvalidData,
    Timeout,
    AuthenticatorCancel,
    UserPresenceTestFailed,
    WebauthnError(WebauthnError),
    U2FError(U2FError),
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<WebauthnError> for Error {
    fn from(error: WebauthnError) -> Self {
        Error::WebauthnError(error)
    }
}

impl From<U2FError> for Error {
    fn from(error: U2FError) -> Self {
        Error::U2FError(error)
    }
}
