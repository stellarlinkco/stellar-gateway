use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use serde::{Deserialize, Serialize};

use crate::error::{GatewayError, Result};
use crate::routing::normalize_host;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateMaterial {
    certificate_pem: String,
    private_key_pem: String,
}

impl CertificateMaterial {
    pub fn new(certificate_pem: impl Into<String>, private_key_pem: impl Into<String>) -> Self {
        Self {
            certificate_pem: certificate_pem.into(),
            private_key_pem: private_key_pem.into(),
        }
    }

    pub fn certificate_pem(&self) -> &str {
        &self.certificate_pem
    }

    pub fn private_key_pem(&self) -> &str {
        &self.private_key_pem
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateCacheEntry {
    hostname: String,
    material: CertificateMaterial,
    expires_at: SystemTime,
}

impl CertificateCacheEntry {
    pub fn new(
        hostname: impl Into<String>,
        material: CertificateMaterial,
        expires_at: SystemTime,
    ) -> Self {
        Self {
            hostname: hostname.into(),
            material,
            expires_at,
        }
    }

    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    pub fn material(&self) -> &CertificateMaterial {
        &self.material
    }

    pub fn expires_at(&self) -> SystemTime {
        self.expires_at
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CacheEntryRejection {
    Expired,
    HostnameMismatch,
    Malformed,
    MissingMaterial,
}

#[derive(Debug, Clone)]
pub struct CacheRejectionRecord {
    pub class: CacheEntryRejection,
    pub path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct CertificateCache {
    dir: PathBuf,
    entries: HashMap<String, CertificateCacheEntry>,
    rejections: Vec<CacheRejectionRecord>,
}

impl CertificateCache {
    pub fn new(dir: impl AsRef<Path>) -> Self {
        Self {
            dir: dir.as_ref().to_path_buf(),
            entries: HashMap::new(),
            rejections: Vec::new(),
        }
    }

    pub fn load(dir: impl AsRef<Path>, now: SystemTime) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        let mut cache = Self::new(&dir);
        cache.refresh(now)?;
        Ok(cache)
    }

    pub fn lookup(&self, hostname: &str) -> Option<CertificateCacheEntry> {
        self.entries.get(hostname).cloned()
    }

    pub fn rejections(&self) -> &[CacheRejectionRecord] {
        &self.rejections
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    pub fn rejection_count(&self) -> usize {
        self.rejections.len()
    }

    pub fn store(&self, entry: &CertificateCacheEntry) -> Result<()> {
        std::fs::create_dir_all(&self.dir).map_err(|err| {
            GatewayError::CertificateCache(format!(
                "failed to create cert cache dir `{}`: {err}",
                self.dir.display()
            ))
        })?;

        let path = self.entry_path(entry.hostname());
        let wire = WireCacheEntry::from_entry(entry)?;
        let yaml = serde_yaml::to_string(&wire).map_err(|err| {
            GatewayError::CertificateCache(format!("failed to serialize entry: {err}"))
        })?;
        std::fs::write(&path, yaml).map_err(|err| {
            GatewayError::CertificateCache(format!("failed to write `{}`: {err}", path.display()))
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }

        tracing::info!(
            event = "cert_cache_store",
            hostname = %entry.hostname(),
            expires_at = ?entry.expires_at(),
            path = %path.display(),
            "stored certificate cache entry"
        );

        Ok(())
    }

    fn refresh(&mut self, now: SystemTime) -> Result<()> {
        self.entries.clear();
        self.rejections.clear();

        let read_dir = match std::fs::read_dir(&self.dir) {
            Ok(iter) => iter,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(err) => {
                return Err(GatewayError::CertificateCache(format!(
                    "failed to read cert cache dir `{}`: {err}",
                    self.dir.display()
                )));
            }
        };

        for entry in read_dir {
            let entry = match entry {
                Ok(e) => e,
                Err(err) => {
                    self.rejections.push(CacheRejectionRecord {
                        class: CacheEntryRejection::Malformed,
                        path: self.dir.clone(),
                    });
                    tracing::warn!(
                        event = "cert_cache_refresh",
                        cache_dir = %self.dir.display(),
                        rejection_class = ?CacheEntryRejection::Malformed,
                        "cert_cache_refresh"
                    );
                    return Err(GatewayError::CertificateCache(format!(
                        "failed to iterate cert cache dir `{}`: {err}",
                        self.dir.display()
                    )));
                }
            };
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("yaml") {
                continue;
            }

            let file_hostname = match path.file_stem().and_then(|s| s.to_str()) {
                Some(stem) if !stem.is_empty() => stem,
                _ => continue,
            };

            let contents = match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(_) => {
                    self.record_rejection(CacheEntryRejection::Malformed, path);
                    continue;
                }
            };

            let wire: WireCacheEntry = match serde_yaml::from_str(&contents) {
                Ok(v) => v,
                Err(_) => {
                    self.record_rejection(CacheEntryRejection::Malformed, path);
                    continue;
                }
            };

            let loaded = match wire.into_entry() {
                Ok(e) => e,
                Err(class) => {
                    self.record_rejection(class, path);
                    continue;
                }
            };

            if loaded.hostname() != file_hostname {
                self.record_rejection(CacheEntryRejection::HostnameMismatch, path);
                continue;
            }

            if loaded.expires_at() <= now {
                self.record_rejection(CacheEntryRejection::Expired, path);
                continue;
            }

            if !certificate_covers_hostname(loaded.material().certificate_pem(), loaded.hostname())
            {
                self.record_rejection(CacheEntryRejection::HostnameMismatch, path);
                continue;
            }

            let hostname = loaded.hostname().to_owned();
            self.entries.insert(hostname.clone(), loaded);
            tracing::info!(
                event = "cert_cache_refresh",
                hostname = %hostname,
                decision = "accepted",
                "cert_cache_refresh"
            );
        }

        tracing::info!(
            event = "cert_cache_refresh",
            cache_dir = %self.dir.display(),
            accepted = self.entries.len(),
            rejected = self.rejections.len(),
            "cert_cache_refresh"
        );
        Ok(())
    }

    fn record_rejection(&mut self, class: CacheEntryRejection, path: PathBuf) {
        tracing::warn!(
            event = "cert_cache_refresh",
            path = %path.display(),
            rejection_class = ?class,
            decision = "rejected",
            "cert_cache_refresh"
        );
        self.rejections.push(CacheRejectionRecord { class, path });
    }

    fn entry_path(&self, hostname: &str) -> PathBuf {
        self.dir.join(format!("{hostname}.yaml"))
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct WireCacheEntry {
    hostname: String,
    expires_at_unix: u64,
    certificate_pem: Option<String>,
    private_key_pem: Option<String>,
}

impl WireCacheEntry {
    fn from_entry(entry: &CertificateCacheEntry) -> Result<Self> {
        let expires_at_unix = entry
            .expires_at()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|err| {
                GatewayError::CertificateCache(format!(
                    "expires_at before unix epoch for {}: {err}",
                    entry.hostname()
                ))
            })?
            .as_secs();

        Ok(Self {
            hostname: entry.hostname().to_owned(),
            expires_at_unix,
            certificate_pem: Some(entry.material().certificate_pem().to_owned()),
            private_key_pem: Some(entry.material().private_key_pem().to_owned()),
        })
    }

    fn into_entry(self) -> std::result::Result<CertificateCacheEntry, CacheEntryRejection> {
        let certificate_pem = self
            .certificate_pem
            .ok_or(CacheEntryRejection::MissingMaterial)?;
        let private_key_pem = self
            .private_key_pem
            .ok_or(CacheEntryRejection::MissingMaterial)?;

        validate_certificate_key_pair(&certificate_pem, &private_key_pem)?;

        let expires_at = SystemTime::UNIX_EPOCH
            .checked_add(std::time::Duration::from_secs(self.expires_at_unix))
            .ok_or(CacheEntryRejection::Malformed)?;

        Ok(CertificateCacheEntry::new(
            self.hostname,
            CertificateMaterial::new(certificate_pem, private_key_pem),
            expires_at,
        ))
    }
}

fn validate_certificate_key_pair(
    certificate_pem: &str,
    private_key_pem: &str,
) -> std::result::Result<(), CacheEntryRejection> {
    let certificate =
        X509::from_pem(certificate_pem.as_bytes()).map_err(|_| CacheEntryRejection::Malformed)?;
    let private_key = PKey::<Private>::private_key_from_pem(private_key_pem.as_bytes())
        .map_err(|_| CacheEntryRejection::Malformed)?;
    let public_key = certificate
        .public_key()
        .map_err(|_| CacheEntryRejection::Malformed)?;

    if private_key.public_eq(&public_key) {
        Ok(())
    } else {
        Err(CacheEntryRejection::Malformed)
    }
}

fn certificate_covers_hostname(certificate_pem: &str, hostname: &str) -> bool {
    let Ok(certificate) = X509::from_pem(certificate_pem.as_bytes()) else {
        return false;
    };
    let Some(hostname) = normalize_host(hostname) else {
        return false;
    };

    if let Some(subject_alt_names) = certificate.subject_alt_names() {
        let mut saw_dns_name = false;
        for name in subject_alt_names {
            let Some(dns_name) = name.dnsname() else {
                continue;
            };
            saw_dns_name = true;
            if dns_pattern_matches_hostname(dns_name, &hostname) {
                return true;
            }
        }
        if saw_dns_name {
            return false;
        }
    }

    certificate
        .subject_name()
        .entries_by_nid(Nid::COMMONNAME)
        .filter_map(|entry| entry.data().as_utf8().ok())
        .any(|common_name| dns_pattern_matches_hostname(common_name.as_ref(), &hostname))
}

fn dns_pattern_matches_hostname(pattern: &str, hostname: &str) -> bool {
    let Some(pattern) = normalize_host(pattern) else {
        return false;
    };
    if let Some(suffix) = pattern.strip_prefix("*.") {
        let Some(prefix) = hostname.strip_suffix(suffix) else {
            return false;
        };
        return prefix.ends_with('.')
            && !prefix[..prefix.len().saturating_sub(1)].contains('.')
            && prefix.len() > 1;
    }
    pattern == hostname
}
