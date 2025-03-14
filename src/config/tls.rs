use crate::config::base::{InboundTlsConfig, OutboundTlsConfig};
use log::{error, info};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::aws_lc_rs::default_provider;
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, ServerConfig};
use rustls::{DigitallySignedStruct, Error};
use rustls::{RootCertStore, SignatureScheme};
use std::sync::Arc;

/// Stub Certificate verifier that skips certificate verification. It is used when the user
/// explicitly allows insecure TLS connection in configuration file, by setting
///
/// ```json
/// {
///     ...,
///     outbound: {
///         ...,
///         tls: {
///             ...,
///             allow_insecure: true
///         }
///     }
/// }
/// ```
///
/// The option is not recommended for production level services, but could be handy in testing stages.
/// https://github.com/maplibre/martin/blob/main/martin/src/pg/tls.rs#L85
/// https://github.com/rustls/rustls/issues/578
#[derive(Debug)]
pub struct NoCertificateVerification {}

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Create ClientConfig for rustls based on the configurations in the config.json file. The function
/// will read the tls configuration under outbound,
///
/// ```json
/// {
///     outbound: {
///         tls: {
///             # Configurations here
///         }
///     }         
/// }
/// ```
pub fn make_client_config(config: &OutboundTlsConfig) -> ClientConfig {
    if config.allow_insecure {
        let mut config: ClientConfig = ClientConfig::builder()
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();

        config
            .dangerous()
            .set_certificate_verifier(Arc::new(NoCertificateVerification {}));

        config
    } else {
        let config = rustls_platform_verifier::tls_config();
        // config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        config
    }
}

/// Create ServerConfig for rustls based on the configurations in the config.json file. The function
/// will read the tls configuration under inbound,
///
/// ```json
/// {
///     inbound: {
///         tls: {
///             # Configurations here
///         }
///     }         
/// }
/// ```
pub fn make_server_config(config: &InboundTlsConfig) -> Option<ServerConfig> {
    info!("111ssssssssssssssssssssssssssssssss");
    let Ok(cert_file) = std::fs::read(&config.cert_path) else {
        return None;
    };
    let Ok(key_file) = std::fs::read(&config.key_path) else {
        return None;
    };

    println!("Loading certificate and key...");

    let Ok(certs) = rustls_pemfile::certs(&mut &*cert_file).collect::<Result<Vec<_>, _>>() else {
        return None;
    };

    let certs = certs
        .into_iter()
        .map(CertificateDer::from)
        .collect::<Vec<_>>();

    println!("Certificate loaded successfully");

    let key = {
        let mut reader = &mut &*key_file;
        let mut private_keys = Vec::new();

        for item in rustls_pemfile::read_all(&mut reader) {
            match item {
                Ok(rustls_pemfile::Item::Pkcs1Key(key)) => {
                    error!("Found PKCS1 key");
                    private_keys.push(PrivateKeyDer::Pkcs1(key));
                }
                Ok(rustls_pemfile::Item::Pkcs8Key(key)) => {
                    error!("Found PKCS8 key");
                    private_keys.push(PrivateKeyDer::Pkcs8(key));
                }
                Ok(rustls_pemfile::Item::Sec1Key(key)) => {
                    error!("Found Sec1 key");
                    private_keys.push(PrivateKeyDer::Sec1(key));
                }
                Ok(_) => error!("Found other item"),
                Err(e) => error!("Error reading key: {}", e),
            }
        }
        private_keys.into_iter().next().unwrap()
    };

    println!("Private key loaded successfully");

    let cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("bad certificate/key");

    // let cfg = ServerConfig::builder()
    //     // .with_safe_defaults()
    //     .with_no_client_auth()
    //     .with_single_cert(certificates, key.into_iter().next().unwrap())
    //     .expect("bad certificate/key");

    Some(cfg)
}
