use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
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
    Account, AccountBuilder, AccountCredentials, AuthorizationStatus, BodyWrapper, BytesResponse,
    ChallengeType, Error as AcmeError, HttpClient, Identifier, NewAccount, NewOrder, OrderStatus,
    RetryPolicy,
};
use rustls::RootCertStore;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use serde::{Serialize, de::DeserializeOwned};
use tokio::sync::Mutex;

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
pub struct InstantAcmeIssuer {
    account_cache: AcmeAccountCache<Account, AccountCredentials>,
}

#[async_trait]
impl AcmeIssuer for InstantAcmeIssuer {
    async fn issue_certificate(
        &self,
        config: &GatewayConfig,
        hostname: &str,
        store: &Http01ChallengeStore,
    ) -> Result<CertificateCacheEntry> {
        let account = self.account(config).await?;
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

impl InstantAcmeIssuer {
    async fn account(&self, config: &GatewayConfig) -> Result<Account> {
        self.account_cache
            .get_or_create(
                account_credentials_path(config),
                || async { create_account(config).await },
                |credentials| async { load_account(config, credentials).await },
            )
            .await
    }
}

async fn load_account(config: &GatewayConfig, credentials: AccountCredentials) -> Result<Account> {
    account_builder(config)?
        .from_credentials(credentials)
        .await
        .map_err(|err| GatewayError::Acme(format!("failed to load account credentials: {err}")))
}

async fn create_account(config: &GatewayConfig) -> Result<(Account, AccountCredentials)> {
    let contact = format!("mailto:{}", config.acme.email);
    let directory_url = config.acme.directory_url.to_string();
    account_builder(config)?
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
        .map_err(|err| GatewayError::Acme(format!("failed to create account: {err}")))
}

fn account_builder(config: &GatewayConfig) -> Result<AccountBuilder> {
    match config.acme.ca_cert_path.as_deref() {
        Some(path) => Ok(Account::builder_with_http(Box::new(
            PebbleCompatClient::try_new(path)?,
        ))),
        None => Account::builder()
            .map_err(|err| GatewayError::Acme(format!("failed to build account client: {err}"))),
    }
}

struct AcmeAccountCache<A, C> {
    accounts: Mutex<HashMap<PathBuf, A>>,
    credentials: PhantomData<C>,
}

impl<A, C> AcmeAccountCache<A, C> {
    fn new() -> Self {
        Self {
            accounts: Mutex::new(HashMap::new()),
            credentials: PhantomData,
        }
    }
}

impl<A, C> Default for AcmeAccountCache<A, C> {
    fn default() -> Self {
        Self::new()
    }
}

impl<A, C> fmt::Debug for AcmeAccountCache<A, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AcmeAccountCache").finish_non_exhaustive()
    }
}

impl<A, C> AcmeAccountCache<A, C>
where
    A: Clone,
    C: DeserializeOwned + Serialize,
{
    async fn get_or_create<Create, CreateFut, Load, LoadFut>(
        &self,
        path: PathBuf,
        create: Create,
        load: Load,
    ) -> Result<A>
    where
        Create: FnOnce() -> CreateFut,
        CreateFut: Future<Output = Result<(A, C)>>,
        Load: FnOnce(C) -> LoadFut,
        LoadFut: Future<Output = Result<A>>,
    {
        let mut accounts = self.accounts.lock().await;
        if let Some(account) = accounts.get(&path) {
            return Ok(account.clone());
        }

        if path.exists() {
            let credentials = read_account_credentials(&path)?;
            let loaded = load(credentials).await?;
            accounts.insert(path, loaded.clone());
            return Ok(loaded);
        }

        let (created, credentials) = create().await?;
        write_account_credentials(&path, &credentials)?;
        accounts.insert(path, created.clone());
        Ok(created)
    }
}

fn account_credentials_path(config: &GatewayConfig) -> PathBuf {
    config.cert_cache.dir.join("acme-account.json")
}

fn read_account_credentials<C: DeserializeOwned>(path: &Path) -> Result<C> {
    let contents = std::fs::read_to_string(path).map_err(|err| {
        GatewayError::Acme(format!(
            "failed to read ACME account credentials `{}`: {err}",
            path.display()
        ))
    })?;
    serde_json::from_str(&contents).map_err(|err| {
        GatewayError::Acme(format!(
            "failed to parse ACME account credentials `{}`: {err}",
            path.display()
        ))
    })
}

fn write_account_credentials<C: Serialize>(path: &Path, credentials: &C) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| {
            GatewayError::Acme(format!(
                "failed to create ACME account directory `{}`: {err}",
                parent.display()
            ))
        })?;
    }

    let tmp_path = path.with_extension("json.tmp");
    let contents = serde_json::to_vec_pretty(credentials).map_err(|err| {
        GatewayError::Acme(format!(
            "failed to serialize ACME account credentials: {err}"
        ))
    })?;
    std::fs::write(&tmp_path, contents).map_err(|err| {
        GatewayError::Acme(format!(
            "failed to write ACME account credentials `{}`: {err}",
            tmp_path.display()
        ))
    })?;
    set_private_permissions(&tmp_path)?;
    std::fs::rename(&tmp_path, path).map_err(|err| {
        GatewayError::Acme(format!(
            "failed to move ACME account credentials `{}` to `{}`: {err}",
            tmp_path.display(),
            path.display()
        ))
    })?;
    Ok(())
}

#[cfg(unix)]
fn set_private_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|err| {
        GatewayError::Acme(format!(
            "failed to set ACME account credentials permissions `{}`: {err}",
            path.display()
        ))
    })
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &Path) -> Result<()> {
    Ok(())
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

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use serde::{Deserialize, Serialize};

    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct TestAccount(String);

    #[derive(Clone, Debug, Deserialize, Serialize)]
    struct TestCredentials {
        id: String,
    }

    #[tokio::test]
    async fn acme_account_cache_should_reuse_memory_and_persisted_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("account.json");
        let cache = AcmeAccountCache::<TestAccount, TestCredentials>::new();
        let create_calls = Arc::new(AtomicUsize::new(0));
        let load_calls = Arc::new(AtomicUsize::new(0));

        let first = cache
            .get_or_create(
                path.clone(),
                {
                    let create_calls = Arc::clone(&create_calls);
                    move || async move {
                        create_calls.fetch_add(1, Ordering::SeqCst);
                        Ok((
                            TestAccount("created".to_owned()),
                            TestCredentials {
                                id: "created".to_owned(),
                            },
                        ))
                    }
                },
                {
                    let load_calls = Arc::clone(&load_calls);
                    move |credentials| async move {
                        load_calls.fetch_add(1, Ordering::SeqCst);
                        Ok(TestAccount(credentials.id))
                    }
                },
            )
            .await
            .unwrap();
        let second = cache
            .get_or_create(
                path.clone(),
                || async { panic!("memory cache should avoid a second account registration") },
                |_| async { panic!("memory cache should avoid a credentials reload") },
            )
            .await
            .unwrap();

        let restarted_cache = AcmeAccountCache::<TestAccount, TestCredentials>::new();
        let third = restarted_cache
            .get_or_create(
                path,
                || async { panic!("persisted credentials should avoid account registration") },
                {
                    let load_calls = Arc::clone(&load_calls);
                    move |credentials| async move {
                        load_calls.fetch_add(1, Ordering::SeqCst);
                        Ok(TestAccount(credentials.id))
                    }
                },
            )
            .await
            .unwrap();

        assert_eq!(first, TestAccount("created".to_owned()));
        assert_eq!(second, TestAccount("created".to_owned()));
        assert_eq!(third, TestAccount("created".to_owned()));
        assert_eq!(create_calls.load(Ordering::SeqCst), 1);
        assert_eq!(load_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn acme_account_cache_should_singleflight_concurrent_creates() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("account.json");
        let cache = Arc::new(AcmeAccountCache::<TestAccount, TestCredentials>::new());
        let create_calls = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();

        for _ in 0..8 {
            let cache = Arc::clone(&cache);
            let path = path.clone();
            let create_calls = Arc::clone(&create_calls);
            handles.push(tokio::spawn(async move {
                cache
                    .get_or_create(
                        path,
                        || async move {
                            create_calls.fetch_add(1, Ordering::SeqCst);
                            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                            Ok((
                                TestAccount("created".to_owned()),
                                TestCredentials {
                                    id: "created".to_owned(),
                                },
                            ))
                        },
                        |credentials| async move { Ok(TestAccount(credentials.id)) },
                    )
                    .await
            }));
        }

        for handle in handles {
            assert_eq!(
                handle.await.unwrap().unwrap(),
                TestAccount("created".to_owned())
            );
        }
        assert_eq!(create_calls.load(Ordering::SeqCst), 1);
    }
}
