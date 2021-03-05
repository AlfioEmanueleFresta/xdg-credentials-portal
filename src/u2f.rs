extern crate async_trait;
extern crate hidapi;
extern crate serde;
extern crate serde_cbor;

use async_trait::async_trait;
use std::fmt::Display;
use std::marker::PhantomData;

use crate::proto::ctap1::{Ctap1, Ctap1Protocol};
use crate::transport::device::FidoDevice;

use crate::ops::u2f::{RegisterRequest, SignRequest};
use crate::ops::u2f::{RegisterResponse, SignResponse};

use crate::fido::FidoProtocol;
use crate::transport::error::{Error, TransportError};

#[async_trait]
pub trait U2F<T> {
    async fn register(device: &mut T, op: &RegisterRequest) -> Result<RegisterResponse, Error>;
    async fn sign(device: &mut T, op: &SignRequest) -> Result<SignResponse, Error>;
}

pub struct U2FManager<T> {
    device_type: PhantomData<T>,
}

#[async_trait]
impl<T> U2F<T> for U2FManager<T>
where
    T: FidoDevice + Send + Display,
{
    async fn register(device: &mut T, op: &RegisterRequest) -> Result<RegisterResponse, Error> {
        let protocol = U2FManager::negotiate_u2f_protocol(device).await?;
        match protocol {
            FidoProtocol::U2F => Ctap1Protocol::register(device, op).await,
            _ => Err(Error::Transport(TransportError::NegotiationFailed)),
        }
    }

    async fn sign(device: &mut T, op: &SignRequest) -> Result<SignResponse, Error> {
        let protocol = U2FManager::negotiate_u2f_protocol(device).await?;

        match protocol {
            FidoProtocol::U2F => Ctap1Protocol::sign(device, op).await,
            _ => Err(Error::Transport(TransportError::NegotiationFailed)),
        }
    }
}

impl<T> U2FManager<T>
where
    T: FidoDevice + Send,
{
    async fn negotiate_u2f_protocol(device: &mut T) -> Result<FidoProtocol, Error> {
        let supported = device.supported_protocols().await?;
        if !supported.u2f && !supported.fido2 {
            return Err(Error::Transport(TransportError::NegotiationFailed));
        }
        // Ensure CTAP1 version is reported correctly.
        Ctap1Protocol::version(device).await?;
        Ok(FidoProtocol::U2F)
    }
}
