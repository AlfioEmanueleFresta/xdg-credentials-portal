use super::processor::{
    Ctap2GetAssertionExtensionProcessor, Ctap2MakeCredentialExtensionProcessor,
};

trait Ctap2ExtensionRegistry<'a> {
    const MAKE_CREDENTIAL_PROCESSORS: &'a [Box<dyn Ctap2MakeCredentialExtensionProcessor>];
    const GET_ASSERTION_PROCESSORS: &'a [Box<dyn Ctap2GetAssertionExtensionProcessor>];
}
