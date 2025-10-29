use std::collections::HashSet;
use std::convert::Infallible;
use std::io::{self, Write};
use std::fs;
use std::net::IpAddr;
use std::sync::LazyLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use base64::engine::{general_purpose::STANDARD, Engine};
use clap::{Parser};
use futures_util::future::BoxFuture;
use futures_util::FutureExt;
use http::{HeaderMap, HeaderName, HeaderValue};
use libsignal_core::curve::{KeyPair, PublicKey};
use libsignal_core::{DeviceId, ProtocolAddress};
use libsignal_net::chat::server_requests::ServerEvent;
use libsignal_net::chat::ws::{ListenerEvent};
use libsignal_net::chat::{ChatConnection, ChatHeaders, ConnectError, LanguageList, Request};
use libsignal_net::connect_state::{
    ConnectState, ConnectionResources, DefaultConnectorFactory, SUGGESTED_CONNECT_CONFIG,
    SUGGESTED_TLS_PRECONNECT_LIFETIME,
};
use libsignal_net::env::{UserAgent, PROD};
use libsignal_net::infra::dns::DnsResolver;
use libsignal_net::infra::route::{
    ConnectionProxyRoute, DirectOrProxyProvider, DirectOrProxyRoute,
    PreconnectingFactory, SimpleRoute, TcpRoute, TlsRouteFragment,
};
use libsignal_net::infra::tcp_ssl::TcpSslConnector;
use libsignal_net::infra::{EnableDomainFronting, EnforceMinimumTls};
use libsignal_net_chat::api::ChallengeOption;
use libsignal_net_chat::api::{registration::*, Unauth};
use libsignal_net_chat::registration::{ConnectUnauthChat, RegistrationService};
use libsignal_protocol::{sealed_sender_decrypt, sealed_sender_encrypt, IdentityKeyStore, PrivateKey, SenderCertificate, ServerCertificate, Timestamp};
use libsignal_protocol::{IdentityKeyPair, InMemSignalProtocolStore};
use rand_core::{OsRng, TryRngCore};
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;
use zkgroup::profiles::ProfileKey;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Phone number to register (e.g., +1234567890)
    #[arg(short, long)]
    phone_number: String,
}

fn sample_password<R: rand_core::CryptoRng>(rng: &mut R, len: usize) -> Vec<u8> {
    // Digits: 48-57
    // Upper: 65-90
    // Lower: 97-122
    // Hyphen: 45
    // Underscore: 95
    //
    // 0-9 => 48-57
    // 10-35 => 65-90
    // 36-61 => 97-122
    // 62 => 45
    // 63 => 95
    fn encode(x: u8) -> u8 {
        if x < 10 {
            48 + x
        } else if x < 36 {
            (x - 10) + 65
        } else if x < 62 {
            (x - 36) + 97
        } else if x == 62 {
            45
        } else if x == 63 {
            95
        } else {
            panic!("Invalid byte")
        }
    }

    let mut buf = vec![0u8; len];
    rng.fill_bytes(&mut buf);
    buf.iter_mut().for_each(|b| *b = encode(*b & 63));
    buf
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    // A program which gets a phone number from the command line and
    // registers for signal using that phone number. Currently it does not complete
    // the registration flow, it just submits the verification captcha and sms if needed.
    let args = Args::parse();

    log::info!(
        "Starting registration for phone number: {}",
        args.phone_number
    );

    let mut rng = OsRng.unwrap_err();

    // Generate and serialize keys
    let (sks, keys) = generate_keys(&mut rng);
    log::info!("Generated keys successfully");

    // TODO : Serialize keys!

    let network_change_event = SENDER_THAT_NEVER_SENDS.subscribe();
    let connector = ProductionChatConnector {
        user_agent: UserAgent::with_libsignal_version("TODO"),
        dns_resolver: DnsResolver::new(&network_change_event),
        network_change_event,
        connect_state: ConnectState::new_with_transport_connector(
            SUGGESTED_CONNECT_CONFIG,
            PreconnectingFactory::new(DefaultConnectorFactory, SUGGESTED_TLS_PRECONNECT_LIFETIME),
        ),
    };

    let mut registration_service = RegistrationService::create_session(
        CreateSession {
            number: args.phone_number.clone(),
            ..Default::default()
        },
        Box::new(connector),
    )
    .await?;

    if registration_service
        .session_state()
        .requested_information
        .contains(&ChallengeOption::Captcha)
    {
        println!("Go to https://signalcaptchas.org/registration/generate");
        println!("Solve the captcha and then copy the link address of the 'Open Signal' link, which will look like.");
        println!("signalcaptcha://signal-hcaptcha.XXXXXXX\n");

        let captcha =
            read_user_input("Copy everything after the signalcaptcha:// and paste it here: ")?;
        registration_service.submit_captcha(&captcha).await?;
    } else {
        println!("No captcha required");
    }

    if registration_service.session_state().allowed_to_request_code {
        log::info!("Requesting SMS verification code");
        let languages = LanguageList::parse(&["en"])?;
        registration_service
            .request_verification_code(
                VerificationTransport::Sms,
                "simple-registration-client",
                languages,
            )
            .await?;
        log::info!("SMS verification code requested");

        // Wait for user to enter verification code
        let verification_code =
            read_user_input("Please enter the verification code you received: ")?;
        registration_service
            .submit_verification_code(&verification_code)
            .await?;
        log::info!("Verification code submitted successfully");
    }

    let password = sample_password(&mut rng, 40);
    let recovery_password = sample_password(&mut rng, 40);

    let profile_key = {
        let mut randomness = [0u8; 32]; // RANDOMNESS_LEN = 32
        rng.try_fill_bytes(&mut randomness).unwrap();
        ProfileKey::generate(randomness)
    };

    use rand::Rng;
    let registration_id = rng.random::<u16>() & 0x3FFF;
    let pni_registration_id = rng.random::<u16>() & 0x3FFF;

    let registed_account = registration_service.register_account(
        NewMessageNotification::WillFetchMessages,
        ProvidedAccountAttributes {
            recovery_password: &recovery_password,
            registration_id,
            pni_registration_id,
            // Device name. None for the primary device.
            name: None,
            registration_lock: None,
            unidentified_access_key: &profile_key.derive_access_key(),
            unrestricted_unidentified_access: false,
            capabilities: HashSet::new(),
            discoverable_by_phone_number: false,
        },
        Some(SkipDeviceTransfer),
        ForServiceIds::generate(|k| keys.get(k).as_borrowed()),
        &str::from_utf8(&password).unwrap(),
    ).await?;

    // Extract the aci directly
    let user_aci = registed_account.aci;

    // The aci is the uuid, we just need to make it a string
    println!("Registration successful! UUID (ACI): {:?}", user_aci.service_id_string());

    let network_change_event = SENDER_THAT_NEVER_SENDS.subscribe();

    let connector = ProductionChatConnector {
        user_agent: UserAgent::with_libsignal_version("TODO"),
        dns_resolver: DnsResolver::new(&network_change_event),
        network_change_event,
        connect_state: ConnectState::new_with_transport_connector(
            SUGGESTED_CONNECT_CONFIG,
            PreconnectingFactory::new(DefaultConnectorFactory, SUGGESTED_TLS_PRECONNECT_LIFETIME),
        ),
    };

    let (tx, rx) = oneshot::channel();
    let chat = connector.connect_chat(tx).await?;

    let request_path = "/v1/message";
    let test_ptext = vec![1, 2, 3, 23, 99]; // TODO: get real text here
    let mut store = InMemSignalProtocolStore::new(IdentityKeyPair::generate(&mut rng), rng.random::<u32>())?;

    // these are the results of:
    // data_encoding_macro::base64!("BUkY0I+9+oPgDCn4+Ac6Iu813yvqkDr/ga8DzLxFxuk6")
    // &const_str::hex!("0a250803122105bc9d1d290be964810dfa7e94856480a3f7060d004c9762c24c575a1522353a5a1240c11ec3c401eb0107ab38f8600e8720a63169e0e2eb8a3fae24f63099f85ea319c3c1c46d3454706ae2a679d1fee690a488adda98a2290b66c906bb60295ed781")
    // which come from KNOWN_SERVER_CERTIFICATES in sealed_sender.rs
    let trust_root: [u8; 33] = [5, 73, 24, 208, 143, 189, 250, 131, 224, 12, 41, 248, 248, 7, 58, 34, 239, 53, 223, 43, 234, 144, 58, 255, 129, 175, 3, 204, 188, 69, 198, 233, 58];
    let cert: &[u8; 105] = &[10, 37, 8, 3, 18, 33, 5, 188, 157, 29, 41, 11, 233, 100, 129, 13, 250, 126, 148, 133, 100, 128, 163, 247, 6, 13, 0, 76, 151, 98, 194, 76, 87, 90, 21, 34, 53, 58, 90, 18, 64, 193, 30, 195, 196, 1, 235, 1, 7, 171, 56, 248, 96, 14, 135, 32, 166, 49, 105, 224, 226, 235, 138, 63, 174, 36, 246, 48, 153, 248, 94, 163, 25, 195, 193, 196, 109, 52, 84, 112, 106, 226, 166, 121, 209, 254, 230, 144, 164, 136, 173, 218, 152, 162, 41, 11, 102, 201, 6, 187, 96, 41, 94, 215, 129];

    // Neither of these seem to work unfortunately
    let server_cert = ServerCertificate::deserialize(cert).expect("valid");
    // let server_cert = ServerCertificate::new(
    //     3, 
    //     PublicKey::deserialize(&trust_root).expect("valid"), 
    //     &PrivateKey::deserialize(&trust_root).expect("valid"),
    //     &mut rng
    // );

    let sender_cert = SenderCertificate::new(
        user_aci.service_id_string(),
        Some(registed_account.number),
        *store.get_identity_key_pair().await?.public_key(),
        DeviceId::new(1).unwrap(), // the first device registered is given device id 1
        Timestamp::from_epoch_millis(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64),
        server_cert,
        &PrivateKey::deserialize(&trust_root).expect("valid"),
        &mut rng,
    )?;

    let body = sealed_sender_encrypt(
        &ProtocolAddress::new("eric.7615".to_string().clone(), DeviceId::new(2).unwrap()),
        &sender_cert,
        &test_ptext,
        &mut store.session_store,
        &mut store.identity_store,
        SystemTime::now(),
        &mut rng,
    ).await;

    let signal_timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis().to_string();

    let res = chat.send(
        Request {
            method: http::Method::POST,
            path: request_path.parse().unwrap(),
            headers: HeaderMap::from_iter([
                (
                    HeaderName::from_static("x-signal-key"),
                    HeaderValue::from_static("false"),
                ),
                (
                    HeaderName::from_static("x-signal-timestamp"),
                    HeaderValue::from_str(&signal_timestamp.as_str())?,
                ),
            ]),
            body: match body.into() {
                Ok(byte_vec) => Some(byte_vec.into()),
                Err(_) => None
            },
        },
        Duration::from_secs(3),
    ).await?;

    println!("{:?}", res);

    match rx.await {
        Ok(v) => println!("got = {:?}", v),
        Err(_) => println!("the sender dropped"),
    }

    return Ok(());
}

#[derive(Serialize, Deserialize, Debug)]
struct SerializedKeys {
    aci_identity_key: String,
    pni_identity_key: String,
    aci_signed_prekey: SerializedSignedPreKey,
    pni_signed_prekey: SerializedSignedPreKey,
    aci_pq_prekey: SerializedSignedPreKey,
    pni_pq_prekey: SerializedSignedPreKey,
    registration_id: u16,
    pni_registration_id: u16,
}

#[derive(Serialize, Deserialize, Debug)]
struct SerializedSignedPreKey {
    key_id: u32,
    public_key: String,
    signature: String,
}

struct ProductionChatConnector {
    user_agent: UserAgent,
    // network_change_event_tx: ::tokio::sync::watch::Sender<()>,
    network_change_event: ::tokio::sync::watch::Receiver<()>,
    dns_resolver: DnsResolver,
    connect_state: std::sync::Mutex<
        ConnectState<
            PreconnectingFactory<
                SimpleRoute<
                    TlsRouteFragment,
                    DirectOrProxyRoute<TcpRoute<IpAddr>, ConnectionProxyRoute<IpAddr>>,
                >,
                DefaultConnectorFactory,
            >,
        >,
    >,
}

impl std::panic::UnwindSafe for ProductionChatConnector {}

static SENDER_THAT_NEVER_SENDS: LazyLock<tokio::sync::watch::Sender<()>> =
    LazyLock::new(Default::default);

impl ConnectUnauthChat for ProductionChatConnector {
    fn connect_chat(
        &self,
        on_disconnect: oneshot::Sender<Infallible>,
    ) -> BoxFuture<'_, Result<Unauth<ChatConnection>, ConnectError>> {
        let user_agent = &self.user_agent;
        let enable_domain_fronting = EnableDomainFronting::No;

        let transport_connector =
            std::sync::Mutex::new(TcpSslConnector::new_direct(self.dns_resolver.clone()));

        let route_provider = {
            let env = PROD;

            let chat_connect = &env.chat_domain_config.connect;

            DirectOrProxyProvider::direct(
                chat_connect
                    .route_provider_with_options(enable_domain_fronting, EnforceMinimumTls::No),
            )
        };

        let headers: Option<ChatHeaders> = None;

        let connection_resources = ConnectionResources {
            connect_state: &self.connect_state,
            dns_resolver: &self.dns_resolver,
            network_change_event: &self.network_change_event,
            confirmation_header_name: None,
        };

        let pending = ChatConnection::start_connect_with(
            connection_resources,
            route_provider,
            user_agent,
            libsignal_net::chat::ws::Config {
                local_idle_timeout: Duration::from_secs(60),
                remote_idle_timeout: Duration::from_secs(60),
                initial_request_id: 0,
                post_request_interface_check_timeout: Duration::from_secs(60),
            },
            libsignal_net::chat::EnablePermessageDeflate::No,
            headers,
            "logging",
        );
        pending
            .map(|pending| {
                pending.map(|pending| {
                    let mut on_disconnect = Some(on_disconnect);
                    let listener = move |event| match event {
                        ListenerEvent::Finished(_) => drop(on_disconnect.take()),
                        ListenerEvent::ReceivedAlerts(_) | ListenerEvent::ReceivedMessage(_, _) => {
                            // let event: Result<ServerEvent, _> = event.try_into().unwrap();
                            // let (addr, msg) = decrypt_message(
                            //     ciphertext,
                            //     trust_root,
                            //     local_uuid,
                            //     local_device_id,
                            //     store,
                            //     rng,
                            // );
                            // TODO: do something with the encrypted message
                        }
                    };
                    // let listener: libsignal_net::chat::ws::EventListener = Box::new(|_event| {});
                    let tokio_runtime =
                        tokio::runtime::Handle::try_current().expect("can get tokio runtime");
                    let chat_connection =
                        ChatConnection::finish_connect(tokio_runtime, pending, Box::new(listener));
                    Unauth(chat_connection)
                })
            })
            .boxed()
    }
}

struct OwnedAccountKeys {
    identity_key: PublicKey,
    signed_pre_key: SignedPreKeyBody<Box<[u8]>>,
    pq_last_resort_pre_key: SignedPreKeyBody<Box<[u8]>>,
}

impl OwnedAccountKeys {
    fn as_borrowed(&self) -> AccountKeys<'_> {
        let Self {
            identity_key,
            signed_pre_key,
            pq_last_resort_pre_key,
        } = self;
        AccountKeys {
            identity_key,
            signed_pre_key: signed_pre_key.as_deref(),
            pq_last_resort_pre_key: pq_last_resort_pre_key.as_deref(),
        }
    }
}

/// Generate random keypairs
fn generate_keys<R: rand_core::CryptoRng>(
    csprng: &mut R,
) -> (
    ForServiceIds<(IdentityKeyPair, libsignal_protocol::kem::KeyPair)>,
    ForServiceIds<OwnedAccountKeys>,
) {
    let secret_keys = ForServiceIds::generate(|__| {
        (
            IdentityKeyPair::generate(csprng),
            libsignal_protocol::kem::KeyPair::generate(
                libsignal_protocol::kem::KeyType::Kyber1024,
                csprng,
            ),
        )
    });
    let keys = ForServiceIds::generate(|kind| {
        let (identity, kem_keypair) = secret_keys.get(kind);

        let signed_pre_key = {
            let pk = identity.public_key().serialize();
            let id: u32 = csprng.next_u32();
            SignedPreKeyBody {
                key_id: id,
                signature: identity
                    .private_key()
                    .calculate_signature(&pk, csprng)
                    .unwrap(),
                public_key: pk,
            }
        };

        let pq_last_resort_pre_key = {
            let id: u32 = csprng.next_u32();

            let public_key = kem_keypair.public_key.serialize();
            SignedPreKeyBody {
                key_id: id,
                signature: identity
                    .private_key()
                    .calculate_signature(&public_key, csprng)
                    .unwrap(),
                public_key,
            }
        };

        OwnedAccountKeys {
            identity_key: identity.public_key().clone(),
            signed_pre_key,
            pq_last_resort_pre_key,
        }
    });
    (secret_keys, keys)
}

// Create a struct that owns the byte data
#[derive(Debug)]
struct AccountKeysWithData {
    aci_identity_key: libsignal_protocol::IdentityKey,
    pni_identity_key: libsignal_protocol::IdentityKey,
    aci_signed_prekey_public: Vec<u8>,
    aci_signed_prekey_signature: Vec<u8>,
    pni_signed_prekey_public: Vec<u8>,
    pni_signed_prekey_signature: Vec<u8>,
    aci_pq_prekey_public: Vec<u8>,
    aci_pq_prekey_signature: Vec<u8>,
    pni_pq_prekey_public: Vec<u8>,
    pni_pq_prekey_signature: Vec<u8>,
    registration_id: u16,
    pni_registration_id: u16,
}

impl AccountKeysWithData {
    fn new(keys: &SerializedKeys) -> Result<Self> {
        let aci_identity_key =
            libsignal_protocol::IdentityKey::decode(&STANDARD.decode(&keys.aci_identity_key)?)?;
        let pni_identity_key =
            libsignal_protocol::IdentityKey::decode(&STANDARD.decode(&keys.pni_identity_key)?)?;

        Ok(Self {
            aci_identity_key,
            pni_identity_key,
            aci_signed_prekey_public: STANDARD.decode(&keys.aci_signed_prekey.public_key)?,
            aci_signed_prekey_signature: STANDARD.decode(&keys.aci_signed_prekey.signature)?,
            pni_signed_prekey_public: STANDARD.decode(&keys.pni_signed_prekey.public_key)?,
            pni_signed_prekey_signature: STANDARD.decode(&keys.pni_signed_prekey.signature)?,
            aci_pq_prekey_public: STANDARD.decode(&keys.aci_pq_prekey.public_key)?,
            aci_pq_prekey_signature: STANDARD.decode(&keys.aci_pq_prekey.signature)?,
            pni_pq_prekey_public: STANDARD.decode(&keys.pni_pq_prekey.public_key)?,
            pni_pq_prekey_signature: STANDARD.decode(&keys.pni_pq_prekey.signature)?,
            registration_id: keys.registration_id,
            pni_registration_id: keys.pni_registration_id,
        })
    }

    fn to_account_keys(&self, keys: &SerializedKeys) -> ForServiceIds<AccountKeys> {
        ForServiceIds {
            aci: AccountKeys {
                identity_key: self.aci_identity_key.public_key(),
                signed_pre_key: SignedPreKeyBody {
                    key_id: keys.aci_signed_prekey.key_id,
                    public_key: &self.aci_signed_prekey_public,
                    signature: &self.aci_signed_prekey_signature,
                },
                pq_last_resort_pre_key: SignedPreKeyBody {
                    key_id: keys.aci_pq_prekey.key_id,
                    public_key: &self.aci_pq_prekey_public,
                    signature: &self.aci_pq_prekey_signature,
                },
            },
            pni: AccountKeys {
                identity_key: self.pni_identity_key.public_key(),
                signed_pre_key: SignedPreKeyBody {
                    key_id: keys.pni_signed_prekey.key_id,
                    public_key: &self.pni_signed_prekey_public,
                    signature: &self.pni_signed_prekey_signature,
                },
                pq_last_resort_pre_key: SignedPreKeyBody {
                    key_id: keys.pni_pq_prekey.key_id,
                    public_key: &self.pni_pq_prekey_public,
                    signature: &self.pni_pq_prekey_signature,
                },
            },
        }
    }
}

fn read_user_input(prompt: &str) -> Result<String> {
    print!("{}", prompt);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let mut res = input.trim().to_string();
    if &res[..5] == "FILE:" {
        res = fs::read_to_string(&res[5..]).expect("Should have been able to read the file");
    }
    return Ok(res);
}
