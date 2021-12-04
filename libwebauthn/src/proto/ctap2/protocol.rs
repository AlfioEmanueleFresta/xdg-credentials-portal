use std::{marker::PhantomData, time::Duration};

use async_trait::async_trait;
use serde_cbor::from_slice;
use tracing::{debug, info, instrument, trace, warn};

use crate::proto::ctap2::cbor::CborRequest;
use crate::proto::ctap2::Ctap2CommandCode;
use crate::transport::device::FidoDevice;
use crate::transport::error::{CtapError, Error};

use super::{
    Ctap2GetAssertionRequest, Ctap2GetAssertionResponse, Ctap2GetInfoResponse,
    Ctap2MakeCredentialRequest, Ctap2MakeCredentialResponse,
};

const TIMEOUT_GET_INFO: Duration = Duration::from_millis(250);

#[async_trait]
pub trait Ctap2<T> {
    async fn get_info(device: &mut T) -> Result<Ctap2GetInfoResponse, Error>;
    async fn make_credential(
        device: &mut T,
        request: &Ctap2MakeCredentialRequest,
        timeout: Duration,
    ) -> Result<Ctap2MakeCredentialResponse, Error>;
    async fn get_assertion(
        device: &mut T,
        request: &Ctap2GetAssertionRequest,
        timeout: Duration,
    ) -> Result<Ctap2GetAssertionResponse, Error>;
    async fn selection(device: &mut T, timeout: Duration) -> Result<(), Error>;
}

pub struct Ctap2Protocol<T: FidoDevice + ?Sized> {
    device_type: PhantomData<T>,
}

#[async_trait]
impl<T> Ctap2<T> for Ctap2Protocol<T>
where
    T: FidoDevice + Send,
{
    #[instrument(skip_all)]
    async fn get_info(device: &mut T) -> Result<Ctap2GetInfoResponse, Error> {
        let cbor_request = CborRequest::new(Ctap2CommandCode::AuthenticatorGetInfo);
        let cbor_response = device
            .send_cbor_request(&cbor_request, TIMEOUT_GET_INFO)
            .await?;
        let ctap_response: Ctap2GetInfoResponse = from_slice(&cbor_response.data.unwrap()).unwrap();
        info!("CTAP2 GetInfo response: {:?}", ctap_response);
        Ok(ctap_response)
    }

    #[instrument(skip_all)]
    async fn make_credential(
        device: &mut T,
        request: &Ctap2MakeCredentialRequest,
        timeout: Duration,
    ) -> Result<Ctap2MakeCredentialResponse, Error> {
        trace!(?request);
        let cbor_request: CborRequest = request.into();
        let cbor_response = device.send_cbor_request(&cbor_request, timeout).await?;

        let ctap_response: Ctap2MakeCredentialResponse =
            from_slice(&cbor_response.data.unwrap()).unwrap();
        info!(?ctap_response, "CTAP2 MakeCredential response");
        Ok(ctap_response)
    }

    #[instrument(skip_all)]
    async fn get_assertion(
        device: &mut T,
        request: &Ctap2GetAssertionRequest,
        timeout: Duration,
    ) -> Result<Ctap2GetAssertionResponse, Error> {
        debug!("CTAP2 GetAssertion request: {:?}", request);
        let cbor_request: CborRequest = request.into();
        let cbor_response = device.send_cbor_request(&cbor_request, timeout).await?;

        let ctap_response: Ctap2GetAssertionResponse =
            from_slice(&cbor_response.data.unwrap()).unwrap();
        info!(?ctap_response, "CTAP2 GetAssertion response");
        Ok(ctap_response)
    }

    #[instrument(skip_all)]
    async fn selection(device: &mut T, timeout: Duration) -> Result<(), Error> {
        debug!("CTAP2 Authenticator Selection request");
        let cbor_request = CborRequest::new(Ctap2CommandCode::AuthenticatorSelection);

        loop {
            let cbor_response = device.send_cbor_request(&cbor_request, timeout).await?;
            match cbor_response.status_code {
                CtapError::Ok => {
                    return Ok(());
                }
                error => {
                    warn!(?error, "Selection request failed with status code");
                    return Err(Error::Ctap(error));
                }
            }
        }
    }
}

impl<T> Ctap2Protocol<T> where T: FidoDevice {}
