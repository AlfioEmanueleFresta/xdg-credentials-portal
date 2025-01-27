use std::hash::Hash;

#[derive(Debug, Clone)]
pub struct FidoDevice {
    pub path: String,
    pub alias: String,
    pub is_paired: bool,
    pub is_connected: bool,
}

impl PartialEq for FidoDevice {
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path
    }
}

impl Eq for FidoDevice {}

impl Hash for FidoDevice {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.path.hash(state);
    }
}

impl FidoDevice {
    pub fn new(path: &str, alias: &str, is_paired: bool, is_connected: bool) -> Self {
        Self {
            path: path.into(),
            alias: alias.into(),
            is_paired,
            is_connected,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FidoEndpoints {
    pub control_point: String,
    pub control_point_length: String,
    pub status: String,
    pub service_revision_bitfield: String,
}

impl FidoEndpoints {
    pub fn new(
        control_point: &str,
        control_point_length: &str,
        status: &str,
        service_revision_bitfield: &str,
    ) -> Self {
        Self {
            control_point: control_point.into(),
            control_point_length: control_point_length.into(),
            status: status.into(),
            service_revision_bitfield: service_revision_bitfield.into(),
        }
    }
}
