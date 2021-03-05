extern crate async_trait;
extern crate log;
extern crate serde;
extern crate serde_cbor;

use async_trait::async_trait;
use log::{debug, info};
use serde_cbor::from_slice;
use std::{marker::PhantomData, time::Duration};

use crate::proto::ctap2::cbor::CborRequest;
use crate::proto::ctap2::{Ctap2CommandCode, Ctap2GetInfoResponse};
use crate::transport::{device::FidoDevice, error::Error};

use super::{
    Ctap2GetAssertionRequest, Ctap2GetAssertionResponse, Ctap2MakeCredentialRequest,
    Ctap2MakeCredentialResponse,
};

#[async_trait]
pub trait Ctap2<T> {
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
}

pub struct Ctap2Protocol<T: FidoDevice + ?Sized> {
    device_type: PhantomData<T>,
}

#[async_trait]
impl<T> Ctap2<T> for Ctap2Protocol<T>
where
    T: FidoDevice + Send,
{
    async fn make_credential(
        device: &mut T,
        request: &Ctap2MakeCredentialRequest,
        timeout: Duration,
    ) -> Result<Ctap2MakeCredentialResponse, Error> {
        debug!("CTAP2 makeCredential request: {:?}", request);

        let cbor_request: CborRequest = CborRequest {
            command: Ctap2CommandCode::AuthenticatorGetInfo,
            encoded_data: vec![],
        };
        let cbor_response = device.send_cbor_request(&cbor_request, timeout).await?;
        let ctap_response: Ctap2GetInfoResponse = from_slice(&cbor_response.data.unwrap()).unwrap();
        info!("GetInfo: {:?}", ctap_response);

        let cbor_request: CborRequest = request.into();
        let cbor_response = device.send_cbor_request(&request.into(), timeout).await?;

        unimplemented!()
    }

    async fn get_assertion(
        device: &mut T,
        request: &Ctap2GetAssertionRequest,
        timeout: Duration,
    ) -> Result<Ctap2GetAssertionResponse, Error> {
        unimplemented!()
    }
}

impl<T> Ctap2Protocol<T> where T: FidoDevice {}
