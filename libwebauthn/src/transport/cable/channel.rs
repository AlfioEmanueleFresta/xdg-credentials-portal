use std::fmt::{Display, Formatter};

use tracing::instrument;

#[derive(Debug)]
pub struct CableChannel {
    // pub ws_stream: ??
}

impl Drop for CableChannel {
    #[instrument(skip_all)]
    fn drop(&mut self) {
        todo!()
    }
}

impl Display for CableChannel {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "CableChannel")
    }
}
