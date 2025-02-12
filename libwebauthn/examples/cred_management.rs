use libwebauthn::management::CredentialManagement;
use libwebauthn::pin::{PinProvider, StdinPromptPinProvider};
use libwebauthn::proto::ctap2::{
    Ctap2, Ctap2CredentialData, Ctap2PublicKeyCredentialRpEntity, Ctap2RPData,
};
use libwebauthn::proto::CtapError;
use libwebauthn::transport::hid::list_devices;
use libwebauthn::transport::Device;
use libwebauthn::webauthn::Error as WebAuthnError;
use std::fmt::Display;
use std::io::{self, Write};
use std::time::Duration;
use text_io::read;
use tracing_subscriber::{self, EnvFilter};

const TIMEOUT: Duration = Duration::from_secs(10);

fn setup_logging() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .without_time()
        .init();
}

macro_rules! handle_retries {
    ($res:expr) => {
        loop {
            match $res.await {
                Ok(r) => break r,
                Err(WebAuthnError::Ctap(ctap_error)) => {
                    if ctap_error.is_retryable_user_error() {
                        println!("Oops, try again! Error: {}", ctap_error);
                        continue;
                    }
                    return Err(WebAuthnError::Ctap(ctap_error));
                }
                Err(err) => return Err(err),
            }
        }
    };
}

fn format_rp(rp: &Ctap2PublicKeyCredentialRpEntity) -> String {
    rp.name.clone().unwrap_or(rp.id.clone())
}

fn format_credential(cred: &Ctap2CredentialData) -> String {
    cred.user
        .display_name
        .clone()
        .unwrap_or(cred.user.name.clone().unwrap_or("<No username>".into()))
        .to_string()
}

async fn enumerate_rps<T: CredentialManagement>(
    channel: &mut T,
    pin_provider: &mut Box<dyn PinProvider>,
) -> Result<Vec<Ctap2RPData>, WebAuthnError> {
    let (rp, total_rps) = handle_retries!(channel.enumerate_rps_begin(pin_provider, TIMEOUT));
    let mut rps = vec![rp];
    // Starting at 1, as we already have one from the begin-call.
    for _ in 1..total_rps {
        let rp = handle_retries!(channel.enumerate_rps_next_rp(pin_provider, TIMEOUT));
        rps.push(rp);
    }
    Ok(rps)
}

async fn enumerate_credentials_for_rp<T: CredentialManagement>(
    channel: &mut T,
    pin_provider: &mut Box<dyn PinProvider>,
    rp_id_hash: &[u8],
) -> Result<Vec<Ctap2CredentialData>, WebAuthnError> {
    let (credential, num_of_creds) =
        handle_retries!(channel.enumerate_credentials_begin(pin_provider, rp_id_hash, TIMEOUT));
    let mut credentials = vec![credential];
    // Starting at 1, as we already have one from the begin-call.
    for _ in 1..num_of_creds {
        let credential = handle_retries!(channel.enumerate_credentials_next(pin_provider, TIMEOUT));
        credentials.push(credential);
    }
    Ok(credentials)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Operation {
    GetMetadata,
    EnumerateRPs,
    EnumerateCredentials,
    RemoveCredential,
    UpdateUserInfo,
}

impl Display for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Operation::GetMetadata => f.write_str("Get metadata"),
            Operation::EnumerateRPs => f.write_str("Enumerate relying parties"),
            Operation::EnumerateCredentials => f.write_str("Enumerate credentials"),
            Operation::RemoveCredential => f.write_str("Remove credential"),
            Operation::UpdateUserInfo => f.write_str("Update user info"),
        }
    }
}

fn ask_for_user_input(num_of_items: usize) -> usize {
    let idx = loop {
        print!("Your choice: ");
        io::stdout().flush().expect("Failed to flush stdout!");
        let input: String = read!("{}\n");
        if let Ok(idx) = input.trim().parse::<usize>() {
            if idx < num_of_items {
                println!();
                break idx;
            }
        }
    };
    idx
}

#[tokio::main]
pub async fn main() -> Result<(), WebAuthnError> {
    setup_logging();

    let devices = list_devices().await.unwrap();
    println!("Devices found: {:?}", devices);
    let mut pin_provider: Box<dyn PinProvider> = Box::new(StdinPromptPinProvider::new());

    for mut device in devices {
        println!("Selected HID authenticator: {}", &device);
        device.wink(TIMEOUT).await?;

        let mut channel = device.channel().await?;
        let info = channel.ctap2_get_info().await?;

        if !info.supports_credential_management() {
            println!("Your token does not support credential management.");
            return Err(WebAuthnError::Ctap(CtapError::InvalidCommand));
        }

        let options = [
            Operation::GetMetadata,
            Operation::EnumerateRPs,
            Operation::EnumerateCredentials,
            Operation::RemoveCredential,
            Operation::UpdateUserInfo,
        ];

        println!("What do you want to do?");
        println!();
        for (idx, op) in options.iter().enumerate() {
            println!("({idx}) {op}");
        }

        let idx = ask_for_user_input(options.len());
        let metadata = handle_retries!(channel.get_credential_metadata(&mut pin_provider, TIMEOUT));
        if options[idx] == Operation::GetMetadata {
            println!("Metadata: {metadata:#?}");
            return Ok(());
        }

        let rps = enumerate_rps(&mut channel, &mut pin_provider).await?;
        if options[idx] == Operation::EnumerateRPs {
            println!("RPs:");
            for rp in &rps {
                println!("{}", format_rp(&rp.rp));
            }
            return Ok(());
        }

        let mut credlist = Vec::new();
        for rp in &rps {
            let creds =
                enumerate_credentials_for_rp(&mut channel, &mut pin_provider, &rp.rp_id_hash)
                    .await?;
            for cred in creds {
                credlist.push((rp.rp.clone(), cred));
            }
        }
        if options[idx] == Operation::EnumerateCredentials {
            println!("Credentials:");
            for (rp, cred) in &credlist {
                println!("{}: {}", format_rp(rp), format_credential(cred));
            }
            return Ok(());
        }

        // For all remaining operations, we need to enumerate the found creds
        for (idx, (rp, cred)) in credlist.iter().enumerate() {
            println!("({idx}) {}: {}", format_rp(rp), format_credential(cred));
        }

        let cred_idx = ask_for_user_input(options.len());

        if options[idx] == Operation::RemoveCredential {
            let (_, cred) = &credlist[cred_idx];
            handle_retries!(channel.delete_credential(
                &cred.credential_id,
                &mut pin_provider,
                TIMEOUT
            ));
            println!("Done");
            return Ok(());
        }

        if options[idx] == Operation::UpdateUserInfo {
            let name = loop {
                print!("New user name: ");
                io::stdout().flush().expect("Failed to flush stdout!");
                let input: String = read!("{}\n");
                let input = input.trim();
                if !input.is_empty() {
                    println!();
                    break input.to_string();
                }
            };
            let (_rp, cred) = &credlist[cred_idx];
            let mut user = cred.user.clone();
            user.name = Some(name);
            handle_retries!(channel.update_user_info(
                &cred.credential_id,
                &user,
                &mut pin_provider,
                TIMEOUT
            ));
            println!("Done");
            return Ok(());
        }
    }

    Ok(())
}
