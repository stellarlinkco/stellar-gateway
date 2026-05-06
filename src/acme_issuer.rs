use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use bytes::Bytes;
use http::{Request, StatusCode};
use hyper_rustls::HttpsConnector;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use instant_acme::{
    Account, AuthorizationStatus, BodyWrapper, BytesResponse, ChallengeType, Error as AcmeError,
    HttpClient, Identifier, NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use rustls::RootCertStore;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;

use crate::acme::Http01ChallengeStore;
use crate::cert_cache::{CertificateCacheEntry, CertificateMaterial};
use crate::config::GatewayConfig;
use crate::error::{GatewayError, Result};

#[async_trait]
pub trait AcmeIssuer: Send + Sync {
    async fn issue_certificate(
        &self,
        config: &GatewayConfig,
        hostname: &str,
        store: &Http01ChallengeStore,
    ) -> Result<CertificateCacheEntry>;
}

#[derive(Debug, Default)]
pub struct InstantAcmeIssuer;

#[async_trait]
impl AcmeIssuer for InstantAcmeIssuer {
    async fn issue_certificate(
        &self,
        config: &GatewayConfig,
        hostname: &str,
        store: &Http01ChallengeStore,
    ) -> Result<CertificateCacheEntry> {
        let account = create_account(config).await?;
        let identifiers = [Identifier::Dns(hostname.to_owned())];
        let mut order = account
            .new_order(&NewOrder::new(&identifiers))
            .await
            .map_err(|err| GatewayError::Acme(format!("failed to create order: {err}")))?;

        let mut active_tokens = Vec::new();
        {
            let mut authorizations = order.authorizations();
            while let Some(authz_result) = authorizations.next().await {
                let mut authz = authz_result.map_err(|err| {
                    GatewayError::Acme(format!("failed to fetch authorization: {err}"))
                })?;

                match authz.status {
                    AuthorizationStatus::Valid => continue,
                    AuthorizationStatus::Pending => {}
                    status => {
                        return Err(GatewayError::Acme(format!(
                            "authorization not pending: {status:?}"
                        )));
                    }
                }

                let mut challenge = authz.challenge(ChallengeType::Http01).ok_or_else(|| {
                    GatewayError::Acme("authorization did not offer HTTP-01 challenge".to_owned())
                })?;
                let token = challenge.token.clone();
                let key_authorization = challenge.key_authorization().as_str().to_owned();
                store.set_for_host(hostname, &token, &key_authorization);
                active_tokens.push(token);
                challenge.set_ready().await.map_err(|err| {
                    GatewayError::Acme(format!("failed to set challenge ready: {err}"))
                })?;
            }
        }

        let ready = order
            .poll_ready(&RetryPolicy::default())
            .await
            .map_err(|err| GatewayError::Acme(format!("failed while polling order: {err}")))?;
        if ready != OrderStatus::Ready {
            for token in &active_tokens {
                store.clear(token);
            }
            return Err(GatewayError::Acme(format!(
                "order did not become ready: {ready:?}"
            )));
        }

        let private_key_pem = order
            .finalize()
            .await
            .map_err(|err| GatewayError::Acme(format!("failed to finalize order: {err}")))?;
        let certificate_pem = order
            .poll_certificate(&RetryPolicy::default())
            .await
            .map_err(|err| GatewayError::Acme(format!("failed to fetch certificate: {err}")))?;

        for token in &active_tokens {
            store.clear(token);
        }

        Ok(CertificateCacheEntry::new(
            hostname,
            CertificateMaterial::new(certificate_pem, private_key_pem),
            SystemTime::now() + Duration::from_secs(60 * 60 * 24 * 90),
        ))
    }
}

async fn create_account(config: &GatewayConfig) -> Result<Account> {
    let contact = format!("mailto:{}", config.acme.email);
    let directory_url = config.acme.directory_url.to_string();
    let builder = match config.acme.ca_cert_path.as_deref() {
        Some(path) => Account::builder_with_http(Box::new(PebbleCompatClient::try_new(path)?)),
        None => Account::builder()
            .map_err(|err| GatewayError::Acme(format!("failed to build account client: {err}")))?,
    };
    let (account, _credentials) = builder
        .create(
            &NewAccount {
                contact: &[contact.as_str()],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            directory_url,
            None,
        )
        .await
        .map_err(|err| GatewayError::Acme(format!("failed to create account: {err}")))?;
    Ok(account)
}

struct PebbleCompatClient(HyperClient<HttpsConnector<HttpConnector>, BodyWrapper<Bytes>>);

impl PebbleCompatClient {
    fn try_new(root_path: &Path) -> Result<Self> {
        let root_der = CertificateDer::from_pem_file(root_path).map_err(|err| {
            GatewayError::Acme(format!(
                "failed to read ACME CA root `{}`: {err}",
                root_path.display()
            ))
        })?;
        let mut roots = RootCertStore::empty();
        roots.add(root_der).map_err(|err| {
            GatewayError::Acme(format!(
                "failed to add ACME CA root `{}`: {err}",
                root_path.display()
            ))
        })?;
        let connector = HttpsConnectorBuilder::new()
            .with_tls_config(
                rustls::ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
            )
            .https_only()
            .enable_http1()
            .enable_http2()
            .build();
        Ok(Self(
            HyperClient::builder(TokioExecutor::new()).build(connector),
        ))
    }
}

impl HttpClient for PebbleCompatClient {
    fn request(
        &self,
        req: Request<BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = std::result::Result<BytesResponse, AcmeError>> + Send>> {
        let fut = self.0.request(req);
        Box::pin(async move {
            let mut response = fut.await.map_err(|err| AcmeError::Other(Box::new(err)))?;
            if response.status() == StatusCode::NO_CONTENT {
                *response.status_mut() = StatusCode::OK;
            }
            Ok(BytesResponse::from(response))
        })
    }
}
