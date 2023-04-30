use std::time::Duration;

use async_trait::async_trait;
use serde_cbor::from_slice;
use tracing::{debug, instrument, trace, warn};

use crate::proto::ctap2::cbor::CborRequest;
use crate::proto::ctap2::Ctap2CommandCode;
use crate::transport::error::{CtapError, Error};
use crate::transport::Channel;

use super::model::Ctap2ClientPinResponse;
use super::{
    Ctap2ClientPinRequest, Ctap2GetAssertionRequest, Ctap2GetAssertionResponse,
    Ctap2GetInfoResponse, Ctap2MakeCredentialRequest, Ctap2MakeCredentialResponse,
};

const TIMEOUT_GET_INFO: Duration = Duration::from_millis(250);

#[async_trait]
pub trait Ctap2 {
    async fn ctap2_get_info(&mut self) -> Result<Ctap2GetInfoResponse, Error>;
    async fn ctap2_make_credential(
        &mut self,
        request: &Ctap2MakeCredentialRequest,
        timeout: Duration,
    ) -> Result<Ctap2MakeCredentialResponse, Error>;
    async fn ctap2_client_pin(
        &mut self,
        request: &Ctap2ClientPinRequest,
        timeout: Duration,
    ) -> Result<Ctap2ClientPinResponse, Error>;
    async fn ctap2_get_assertion(
        &mut self,
        request: &Ctap2GetAssertionRequest,
        timeout: Duration,
    ) -> Result<Ctap2GetAssertionResponse, Error>;
    async fn ctap2_get_next_assertion(
        &mut self,
        timeout: Duration,
    ) -> Result<Ctap2GetAssertionResponse, Error>;
    async fn ctap2_selection(&mut self, timeout: Duration) -> Result<(), Error>;
}

#[async_trait]
impl<C> Ctap2 for C
where
    C: Channel,
{
    #[instrument(skip_all)]
    async fn ctap2_get_info(&mut self) -> Result<Ctap2GetInfoResponse, Error> {
        let cbor_request = CborRequest::new(Ctap2CommandCode::AuthenticatorGetInfo);
        self.cbor_send(&cbor_request, TIMEOUT_GET_INFO).await?;
        let cbor_response = self.cbor_recv(TIMEOUT_GET_INFO).await?;
        match cbor_response.status_code {
            CtapError::Ok => (),
            error => return Err(Error::Ctap(error)),
        };
        let ctap_response: Ctap2GetInfoResponse = from_slice(&cbor_response.data.unwrap()).unwrap();
        debug!("CTAP2 GetInfo successful");
        trace!(?ctap_response);
        Ok(ctap_response)
    }

    #[instrument(skip_all)]
    async fn ctap2_make_credential(
        &mut self,
        request: &Ctap2MakeCredentialRequest,
        _timeout: Duration,
    ) -> Result<Ctap2MakeCredentialResponse, Error> {
        trace!(?request);
        self.cbor_send(&request.into(), TIMEOUT_GET_INFO).await?;
        let cbor_response = self.cbor_recv(TIMEOUT_GET_INFO).await?;
        match cbor_response.status_code {
            CtapError::Ok => (),
            error => return Err(Error::Ctap(error)),
        };
        let ctap_response: Ctap2MakeCredentialResponse =
            from_slice(&cbor_response.data.unwrap()).unwrap();
        debug!("CTAP2 MakeCredential successful");
        trace!(?ctap_response);
        Ok(ctap_response)
    }

    #[instrument(skip_all)]
    async fn ctap2_get_assertion(
        &mut self,
        request: &Ctap2GetAssertionRequest,
        _timeout: Duration,
    ) -> Result<Ctap2GetAssertionResponse, Error> {
        trace!(?request);
        self.cbor_send(&request.into(), TIMEOUT_GET_INFO).await?;
        let cbor_response = self.cbor_recv(TIMEOUT_GET_INFO).await?;
        let ctap_response: Ctap2GetAssertionResponse =
            from_slice(&cbor_response.data.unwrap()).unwrap();
        debug!("CTAP2 GetAssertion successful");
        trace!(?ctap_response);
        Ok(ctap_response)
    }

    #[instrument(skip_all)]
    async fn ctap2_get_next_assertion(
        &mut self,
        _timeout: Duration,
    ) -> Result<Ctap2GetAssertionResponse, Error> {
        debug!("CTAP2 GetNextAssertion request");
        let cbor_request = CborRequest::new(Ctap2CommandCode::AuthenticatorGetNextAssertion);
        self.cbor_send(&cbor_request, TIMEOUT_GET_INFO).await?;
        let cbor_response = self.cbor_recv(TIMEOUT_GET_INFO).await?;
        let ctap_response: Ctap2GetAssertionResponse =
            from_slice(&cbor_response.data.unwrap()).unwrap();
        debug!("CTAP2 GetNextAssertion successful");
        trace!(?ctap_response);
        Ok(ctap_response)
    }

    #[instrument(skip_all)]
    async fn ctap2_selection(&mut self, _timeout: Duration) -> Result<(), Error> {
        debug!("CTAP2 Authenticator Selection request");
        let cbor_request = CborRequest::new(Ctap2CommandCode::AuthenticatorSelection);

        loop {
            self.cbor_send(&cbor_request, TIMEOUT_GET_INFO).await?;
            let cbor_response = self.cbor_recv(TIMEOUT_GET_INFO).await?;
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

    #[instrument(skip_all)]
    async fn ctap2_client_pin(
        &mut self,
        request: &Ctap2ClientPinRequest,
        _timeou: Duration,
    ) -> Result<Ctap2ClientPinResponse, Error> {
        trace!(?request);
        self.cbor_send(&request.into(), TIMEOUT_GET_INFO).await?;
        let cbor_response = self.cbor_recv(TIMEOUT_GET_INFO).await?;
        match cbor_response.status_code {
            CtapError::Ok => (),
            error => return Err(Error::Ctap(error)),
        };
        let ctap_response: Ctap2ClientPinResponse =
            from_slice(&cbor_response.data.unwrap()).unwrap();
        debug!("CTAP2 ClientPin successful");
        trace!(?ctap_response);
        Ok(ctap_response)
    }
}
