use std::collections::HashSet;
use std::convert::Infallible;
use std::fs;
use std::io::{self, Write};
use std::net::IpAddr;
use std::sync::LazyLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use base64::engine::{general_purpose::STANDARD, Engine};
use clap::Parser;
use futures_util::future::BoxFuture;
use futures_util::FutureExt;
use http::{HeaderMap, HeaderName, HeaderValue};
use libsignal_core::curve::{KeyPair, PublicKey};
use libsignal_core::{DeviceId, ProtocolAddress, ServiceIdKind};
use libsignal_net::chat::server_requests::ServerEvent;
use libsignal_net::chat::ws::ListenerEvent;
use libsignal_net::chat::{
    AuthenticatedChatHeaders, ChatConnection, ChatHeaders, ConnectError, LanguageList,
    ReceiveStories, Request,
};
use libsignal_net::connect_state::{
    ConnectState, ConnectionResources, DefaultConnectorFactory, SUGGESTED_CONNECT_CONFIG,
    SUGGESTED_TLS_PRECONNECT_LIFETIME,
};
use libsignal_net::auth::Auth;
use libsignal_net::env::{UserAgent, PROD};
use libsignal_net::infra::dns::DnsResolver;
use libsignal_net::infra::route::{
    ConnectionProxyRoute, DirectOrProxyProvider, DirectOrProxyRoute, PreconnectingFactory,
    SimpleRoute, TcpRoute, TlsRouteFragment,
};
use libsignal_net::infra::tcp_ssl::TcpSslConnector;
use libsignal_net::infra::{EnableDomainFronting, EnforceMinimumTls};
use libsignal_net_chat::api::usernames::UnauthenticatedChatApi;
use libsignal_net_chat::api::ChallengeOption;
use libsignal_net_chat::api::{registration::*, Unauth};
use libsignal_net_chat::registration::{ConnectUnauthChat, RegistrationService};
use libsignal_protocol::{
    sealed_sender_decrypt, sealed_sender_encrypt, IdentityKeyStore, PrivateKey, SenderCertificate,
    ServerCertificate, Timestamp,
};
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
    let args = Args::parse();

    let mut rng = OsRng.unwrap_err();

    // Check if keys.json already exists
    let (saved_registration, user_aci, password, phone_number) = if std::path::Path::new(
        "keys.json",
    )
    .exists()
    {
        log::info!("Found existing keys.json, loading saved registration");
        let saved_json = fs::read_to_string("keys.json")?;
        let saved: SavedRegistration = serde_json::from_str(&saved_json)?;

        log::info!(
            "Loaded existing registration for phone: {}",
            saved.phone_number
        );
        log::info!("ACI: {}", saved.aci);

        use libsignal_core::Aci;
        let aci = Aci::parse_from_service_id_string(&saved.aci)
            .ok_or_else(|| anyhow::anyhow!("Invalid ACI in saved registration"))?;
        let password_bytes = saved.password.as_bytes().to_vec();
        let phone = saved.phone_number.clone();

        (saved, aci, password_bytes, phone)
    } else {
        log::info!(
            "No existing registration found, starting registration for: {}",
            args.phone_number
        );

        // Generate keys
        let (sks, keys) = generate_keys(&mut rng);
        log::info!("Generated keys successfully");

        // Generate registration IDs
        use rand::Rng;
        let registration_id = rng.random::<u16>() & 0x3FFF;
        let pni_registration_id = rng.random::<u16>() & 0x3FFF;

        // Serialize keys
        let serialized_keys = serialize_keys(&sks, &keys, registration_id, pni_registration_id);

        let network_change_event = SENDER_THAT_NEVER_SENDS.subscribe();
        let connector = ProductionChatConnector {
            user_agent: UserAgent::with_libsignal_version("TODO"),
            dns_resolver: DnsResolver::new(&network_change_event),
            network_change_event,
            connect_state: ConnectState::new_with_transport_connector(
                SUGGESTED_CONNECT_CONFIG,
                PreconnectingFactory::new(
                    DefaultConnectorFactory,
                    SUGGESTED_TLS_PRECONNECT_LIFETIME,
                ),
            ),
            auth_username: None,
            auth_password: None,
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

            /*
                        let captcha =
                            read_user_input("Copy everything after the signalcaptcha:// and paste it here: ")
                                .await?;
            */
            let captcha = "signal-hcaptcha.5fad97ac-7d06-4e44-b18a-b950b20148ff.registration.P1_eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.haJwZACjZXhwzmkEADancGFzc2tlecUEPr0cv_e9rZH2jszfskPywlJZY2RWjz-35JwOWM2prl-Yv78dubyqZceZElmUxucPHIiUoSThZhGQBEsyXedELtYNhq4N6DMxiZmCei6JvIzy3JqpDJ5UtG2lmdOKk3fad0UwVYr7XIxo3cCkLazG-SfkpnchtoRCVtiUYc5l-iTRTzIgFe49WEA5BTYfkeUd5GoklsQUkRrNh3wsK77yLivgdhaUH8bt3W20XNTn-GAsMbI6vRa6h5bKO5uOaSehwrKAr5l7n26ixkTW8It_y3YbsoJvbX2S7VN3CRqVkeRYlfy9LE2KRx1vrpJu5TNXfYEqmdlKhVs1o844Uck3Hxl1nBMt40hlodc1yI_C3K-BRuioIMY4KfqChKzpRo_rggAi-aUcePvJ70M-k59REkBhr9a4AZ8HdVR_ITqlk0E9vPkIPWv_gHWqU31QcqTK98FP8o9iNVXEW0V7HpSDSf-M6n_YkNLFz_fjA6oBHg0EhsnrPjg4XYO-az8ePwRiVLg-yhOupMzaH6dbQkZqPQJD08W7DJu1DjryDKPa-K5O2DBtclET_qwEoMSO-DuKPFvIV226xJTn5CNd7nNYgpDgoo1FveoWrzXkoJ2we_T_-QRdwi9BV6uSz3qRgCxrmNHnWhfe7JDhOefRaQc6thdZ_VI4dnsgP6LVfbBPRbYNakAjeHYZil7hYPSpNg0V49EGTbIdhx2zzGk5wuRmAyaY86DR4b85owAQSSqMKgB__hMXiFpMfFUBT0FnmTLZEG6h3ONxi_dx_062gRtvZ3KkQ7vzgd3nj7-FGRxZD4RwmrVLNpBcQdDwQTjjnjECiCtLM_fVEoAlY0a_s6IItDIJ-pgyJVz_-qtxj2N0L2n4j1GSEpd4dg74mQoqae3pQVxb2hB_puC2JzG39IJf3VKWKiLUM27V4py4-oobBt5f-6KVAROSfDKhlR3cbdgt2Y0DfGsd5rU2UnXhks8tYKMK5Hgm_72154uq5qc6olIODLx1gUpc55rteSdWehtTuHvIPzrQaywLjakGFYUVjbSTbBVRPyPRLg8ZOgot6zM21hWgYiDBLs9caJS8gADDHYv0vi9ht1SujuMp9vh_hxvMBGNFW6abD7fT0xe67Z5nkEx33bPAf7sFUqgWggmf7oDou3h6gp74VgUgxo7hiLzxsHMrYuI6Lv9W3RzR-mQ9CTX3sCiPkzsqOLqRoyWkHo-mY-_5byd-GBm_tsgnoXrM5P9BBe_lhY509c8j0Op9RvB-sVFKa_2lz1xaNDq3lV5QSyp0TuI6J6Lt6uCU5lbxR3xQI5KMaiXFvcMbVe3KIQNr3QrnXgpaP6R_S1q_4eE2PNGhBKbYfpXX0Wp6jpoLtd01HT7fgyKddC00bZx3WJCuD4s50BzmaHpPNVFy66S2xS6CAFsE-ULBfkBBSAN3mez8cGVHi8shSmR6IaJrcqg0NDgyMjhiN6hzaGFyZF9pZM4NO2Qp.XRTOkfBfK7Aaku5gp4pD07TCuYsIDzZennilQYw4J-s";
            println!("GOT CAPTCHA");
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
                read_user_input("Please enter the verification code you received: ").await?;
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

        let registed_account = registration_service
            .register_account(
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
            )
            .await?;

        // Create saved registration with all needed info
        let saved_registration = SavedRegistration {
            keys: serialized_keys,
            password: String::from_utf8(password.clone())?,
            recovery_password: String::from_utf8(recovery_password.clone())?,
            aci: registed_account.aci.service_id_string(),
            pni: registed_account.pni.service_id_string(),
            phone_number: registed_account.number.clone(),
        };

        // Write to file
        let registration_json = serde_json::to_string_pretty(&saved_registration)?;
        fs::write("keys.json", registration_json)?;
        log::info!("Registration saved to keys.json");

        println!(
            "Registration successful! UUID (ACI): {}",
            registed_account.aci.service_id_string()
        );

        (
            saved_registration,
            registed_account.aci,
            password,
            registed_account.number,
        )
    };

    let network_change_event = SENDER_THAT_NEVER_SENDS.subscribe();

    let password_str = String::from_utf8(password.clone())?;
    let connector = ProductionChatConnector {
        user_agent: UserAgent::with_libsignal_version("TODO"),
        dns_resolver: DnsResolver::new(&network_change_event),
        network_change_event,
        connect_state: ConnectState::new_with_transport_connector(
            SUGGESTED_CONNECT_CONFIG,
            PreconnectingFactory::new(DefaultConnectorFactory, SUGGESTED_TLS_PRECONNECT_LIFETIME),
        ),
        auth_username: Some(user_aci.service_id_string()),
        auth_password: Some(password_str.clone()),
    };

    let (tx, rx) = oneshot::channel();
    let chat = connector.connect_chat(tx).await?;

    // Look up a username to get their ACI
    log::info!("Looking up username: eric.7615");
    let recipient_username = "eric.7615";
    let recipient_aci = lookup_username(&chat, recipient_username).await?;

    if let Some(aci) = recipient_aci {
        log::info!("Found user: {}", aci.service_id_string());

        // Fetch sender certificate from the Signal server
        log::info!("Fetching sender certificate from Signal server...");
        let sender_cert = get_sender_certificate(
            &chat.0,
            true,
            &user_aci.service_id_string(),
            &password_str,
        )
        .await?;
        log::info!("Sender certificate obtained");

        let recipient_uuid = aci.service_id_string();
        let request_path = format!("/v1/messages/{}", recipient_uuid);
        let test_ptext = "hello world";
        use rand::Rng;
        let mut store = InMemSignalProtocolStore::new(
            IdentityKeyPair::generate(&mut rng),
            rng.random::<u32>(),
        )?;

        // Note: You need to establish a session with the recipient before sending encrypted messages
        // For now this will fail because we don't have a session established
        let body = sealed_sender_encrypt(
            &ProtocolAddress::new(recipient_uuid.clone(), DeviceId::new(1).unwrap()),
            &sender_cert,
            test_ptext.as_bytes(),
            &mut store.session_store,
            &mut store.identity_store,
            SystemTime::now(),
            &mut rng,
        )
        .await;

        let signal_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis()
            .to_string();

        let res = chat
            .send(
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
                        Err(_) => None,
                    },
                },
                Duration::from_secs(3),
            )
            .await?;

        println!("{:?}", res);
    } else {
        log::warn!("Username '{}' not found", recipient_username);
    }

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

#[derive(Serialize, Deserialize, Debug)]
struct SenderCertificateResponse {
    certificate: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct SavedRegistration {
    keys: SerializedKeys,
    password: String,
    recovery_password: String,
    aci: String,
    pni: String,
    phone_number: String,
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
    auth_username: Option<String>,
    auth_password: Option<String>,
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

        let headers: Option<ChatHeaders> = if let (Some(username), Some(password)) =
            (&self.auth_username, &self.auth_password)
        {
            let languages = LanguageList::parse(&["en"]).unwrap();
            Some(ChatHeaders::Auth(AuthenticatedChatHeaders {
                auth: Auth {
                    username: username.clone(),
                    password: password.clone(),
                },
                receive_stories: false.into(),
                languages,
            }))
        } else {
            None
        };

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

/// Serialize the keys generated by generate_keys into a SerializedKeys structure
fn serialize_keys(
    secret_keys: &ForServiceIds<(IdentityKeyPair, libsignal_protocol::kem::KeyPair)>,
    public_keys: &ForServiceIds<OwnedAccountKeys>,
    registration_id: u16,
    pni_registration_id: u16,
) -> SerializedKeys {
    let aci_keys = public_keys.get(ServiceIdKind::Aci);
    let pni_keys = public_keys.get(ServiceIdKind::Pni);

    let (aci_identity, _) = secret_keys.get(ServiceIdKind::Aci);
    let (pni_identity, _) = secret_keys.get(ServiceIdKind::Pni);

    SerializedKeys {
        aci_identity_key: STANDARD.encode(aci_identity.identity_key().serialize()),
        pni_identity_key: STANDARD.encode(pni_identity.identity_key().serialize()),
        aci_signed_prekey: SerializedSignedPreKey {
            key_id: aci_keys.signed_pre_key.key_id,
            public_key: STANDARD.encode(&aci_keys.signed_pre_key.public_key),
            signature: STANDARD.encode(&aci_keys.signed_pre_key.signature),
        },
        pni_signed_prekey: SerializedSignedPreKey {
            key_id: pni_keys.signed_pre_key.key_id,
            public_key: STANDARD.encode(&pni_keys.signed_pre_key.public_key),
            signature: STANDARD.encode(&pni_keys.signed_pre_key.signature),
        },
        aci_pq_prekey: SerializedSignedPreKey {
            key_id: aci_keys.pq_last_resort_pre_key.key_id,
            public_key: STANDARD.encode(&aci_keys.pq_last_resort_pre_key.public_key),
            signature: STANDARD.encode(&aci_keys.pq_last_resort_pre_key.signature),
        },
        pni_pq_prekey: SerializedSignedPreKey {
            key_id: pni_keys.pq_last_resort_pre_key.key_id,
            public_key: STANDARD.encode(&pni_keys.pq_last_resort_pre_key.public_key),
            signature: STANDARD.encode(&pni_keys.pq_last_resort_pre_key.signature),
        },
        registration_id,
        pni_registration_id,
    }
}

/// Deserialize keys from a SerializedKeys structure
fn deserialize_keys(serialized: &SerializedKeys) -> Result<ForServiceIds<OwnedAccountKeys>> {
    let keys_data = AccountKeysWithData::new(serialized)?;

    let aci_keys = OwnedAccountKeys {
        identity_key: keys_data.aci_identity_key.public_key().clone(),
        signed_pre_key: SignedPreKeyBody {
            key_id: serialized.aci_signed_prekey.key_id,
            public_key: keys_data.aci_signed_prekey_public.into_boxed_slice(),
            signature: keys_data.aci_signed_prekey_signature.into_boxed_slice(),
        },
        pq_last_resort_pre_key: SignedPreKeyBody {
            key_id: serialized.aci_pq_prekey.key_id,
            public_key: keys_data.aci_pq_prekey_public.into_boxed_slice(),
            signature: keys_data.aci_pq_prekey_signature.into_boxed_slice(),
        },
    };

    let pni_keys = OwnedAccountKeys {
        identity_key: keys_data.pni_identity_key.public_key().clone(),
        signed_pre_key: SignedPreKeyBody {
            key_id: serialized.pni_signed_prekey.key_id,
            public_key: keys_data.pni_signed_prekey_public.into_boxed_slice(),
            signature: keys_data.pni_signed_prekey_signature.into_boxed_slice(),
        },
        pq_last_resort_pre_key: SignedPreKeyBody {
            key_id: serialized.pni_pq_prekey.key_id,
            public_key: keys_data.pni_pq_prekey_public.into_boxed_slice(),
            signature: keys_data.pni_pq_prekey_signature.into_boxed_slice(),
        },
    };

    Ok(ForServiceIds {
        aci: aci_keys,
        pni: pni_keys,
    })
}

/// Look up a Signal user by their username
///
/// # Arguments
/// * `chat` - An unauthenticated chat connection
/// * `username` - The username to look up (e.g., "alice.42")
///
/// # Returns
/// * `Ok(Some(Aci))` - The user's ACI if found
/// * `Ok(None)` - No user found with that username
/// * `Err(...)` - Error occurred during lookup
async fn lookup_username(
    chat: &Unauth<ChatConnection>,
    username: &str,
) -> Result<Option<libsignal_core::Aci>> {
    // Parse and validate the username
    let username_obj = usernames::Username::new(username)?;

    // Get the hash of the username
    let hash = username_obj.hash();

    // Look up the username hash on the Signal server
    let result = chat.look_up_username_hash(&hash).await?;

    Ok(result)
}

/// Fetch a sender certificate from the Signal server
///
/// # Arguments
/// * `chat` - An authenticated chat connection
/// * `omit_e164` - If true, requests a certificate without phone number (privacy mode)
/// * `username` - The ACI (UUID) for authentication
/// * `password` - The account password for authentication
async fn get_sender_certificate(
    chat: &ChatConnection,
    omit_e164: bool,
    username: &str,
    password: &str,
) -> Result<SenderCertificate> {
    let path = if omit_e164 {
        "/v1/certificate/delivery?includeE164=false"
    } else {
        "/v1/certificate/delivery"
    };

    // Create Basic Auth header
    let auth_string = format!("{}:{}", username, password);
    let auth_encoded = STANDARD.encode(auth_string.as_bytes());
    let auth_header_value = format!("Basic {}", auth_encoded);

    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::AUTHORIZATION,
        HeaderValue::from_str(&auth_header_value)?,
    );

    let response = chat
        .send(
            Request {
                method: http::Method::GET,
                path: path.parse()?,
                headers,
                body: None,
            },
            Duration::from_secs(10),
        )
        .await?;

    // Parse the JSON response
    let response_body = response
        .body
        .ok_or_else(|| anyhow::anyhow!("Empty response body"))?;
    println!("response:");
    println!(
        "{}",
        String::from_utf8(response_body.clone().into()).unwrap()
    );
    let cert_response: SenderCertificateResponse = serde_json::from_slice(&response_body)?;

    // Decode the base64-encoded certificate
    let cert_bytes = STANDARD.decode(&cert_response.certificate)?;
    let sender_cert = SenderCertificate::deserialize(&cert_bytes)?;

    log::info!("Successfully fetched sender certificate from Signal server");
    Ok(sender_cert)
}

async fn read_user_input(prompt: &str) -> Result<String> {
    use tokio::io::{AsyncBufReadExt, BufReader};

    print!("{}", prompt);
    io::stdout().flush()?;

    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut input = String::new();
    reader.read_line(&mut input).await?;

    let mut res = input.trim().to_string();
    if res.len() >= 5 && &res[..5] == "FILE:" {
        res = fs::read_to_string(&res[5..])?;
    }

    Ok(res)
}
