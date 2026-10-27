// Copyright 2025 The NativeLink Authors. All rights reserved.
//
// Licensed under the Functional Source License, Version 1.1, Apache 2.0 Future License (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    See LICENSE file for details
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use core::convert::Into;
use core::time::Duration;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use futures::StreamExt;
use nativelink_config::cas_server::{FetchConfig, FetchDownloaderConfig, WithInstanceName};
use nativelink_error::{Code, Error, ResultExt, make_err, make_input_err};
use nativelink_proto::build::bazel::remote::asset::v1::fetch_server::{
    Fetch, FetchServer as Server,
};
use nativelink_proto::build::bazel::remote::asset::v1::{
    FetchBlobRequest, FetchBlobResponse, FetchDirectoryRequest, FetchDirectoryResponse, Qualifier,
};
use nativelink_proto::google::rpc::Status as GoogleStatus;
use nativelink_store::store_manager::StoreManager;
use nativelink_util::common::DigestInfo;
use nativelink_util::digest_hasher::{
    DigestHasher, DigestHasherFunc, default_digest_hasher_func, digest_hasher_func_from_context,
    make_ctx_for_hash_func,
};
use nativelink_util::fs;
use nativelink_util::store_trait::{Store, StoreLike, UploadSizeInfo};
use opentelemetry::context::FutureExt;
use prost::Message;
use prost_types::Timestamp;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use sha2::{Digest as _, Sha256, Sha384, Sha512};
use tokio::io::{AsyncSeekExt, AsyncWriteExt};
use tonic::{Request, Response, Status};
use tracing::{Instrument, Level, error_span, info, instrument, warn};

use crate::remote_asset_proto::{RemoteAssetArtifact, RemoteAssetQuery};

/// The qualifier carrying a Subresource Integrity checksum of the blob.
const QUALIFIER_CHECKSUM_SRI: &str = "checksum.sri";
/// A header for every URI: `http_header:<name>`.
const QUALIFIER_HTTP_HEADER: &str = "http_header:";
/// A header for one URI: `http_header_url:<index>:<name>`.
const QUALIFIER_HTTP_HEADER_URL: &str = "http_header_url:";
/// Qualifiers that only name or describe the asset; they key the cache entry
/// and change nothing about the download.
const DESCRIPTIVE_QUALIFIERS: [&str; 2] = ["bazel.canonical_id", "resource_type"];

#[derive(Debug, Clone)]
pub struct FetchStoreInfo {
    store: Store,
    downloader: Option<Arc<Downloader>>,
}

#[derive(Debug, Clone)]
pub struct FetchServer {
    stores: HashMap<String, FetchStoreInfo>,
}

impl FetchServer {
    pub fn new(
        configs: &[WithInstanceName<FetchConfig>],
        store_manager: &StoreManager,
    ) -> Result<Self, Error> {
        let mut stores = HashMap::with_capacity(configs.len());
        for config in configs {
            let store = store_manager
                .get_store(&config.fetch_store)
                .ok_or_else(|| {
                    make_input_err!("'fetch_store': '{}' does not exist", config.fetch_store)
                })?;
            let downloader = config
                .downloader
                .as_ref()
                .map(|downloader| Downloader::new(downloader, store_manager).map(Arc::new))
                .transpose()?;
            stores.insert(
                config.instance_name.clone(),
                FetchStoreInfo { store, downloader },
            );
        }
        Ok(Self { stores })
    }

    pub fn into_service(self) -> Server<Self> {
        Server::new(self)
    }

    /// The stored mapping for `uri`, if it may be served: fresh enough for
    /// the request and, with a downloader, its blob still in the CAS.
    async fn lookup(
        store_info: &FetchStoreInfo,
        uri: &str,
        request: &FetchBlobRequest,
    ) -> Result<Option<RemoteAssetArtifact>, Error> {
        let asset_digest =
            RemoteAssetQuery::new(uri.to_owned(), request.qualifiers.clone()).digest();
        let Ok(asset_response_raw) = store_info
            .store
            .get_part_unchunked(asset_digest, 0, None)
            .await
        else {
            info!(uri, digest = %asset_digest, "Fetch asset not in fetch_store");
            return Ok(None);
        };
        let asset = RemoteAssetArtifact::decode(asset_response_raw)
            .err_tip(|| "Failed to decode stored RemoteAssetArtifact")?;
        info!(uri, digest = %asset_digest, "Looked up fetch asset");

        let Some(downloader) = &store_info.downloader else {
            // Lookup only: whatever was pushed is served as it is.
            return Ok(Some(asset));
        };
        if !is_fresh(&asset, request.oldest_content_accepted.as_ref()) {
            info!(uri, "Fetch asset older than the request accepts");
            return Ok(None);
        }
        let Some(blob_digest) = asset.blob_digest.as_ref() else {
            return Ok(None);
        };
        let blob_digest = DigestInfo::try_from(blob_digest)
            .err_tip(|| "Stored RemoteAssetArtifact has an invalid blob digest")?;
        if downloader.cas_store.has(blob_digest).await?.is_none() {
            // The mapping outlived its blob: download it again rather than
            // return a digest the client cannot read.
            info!(uri, %blob_digest, "Fetch asset's blob was evicted from the CAS");
            return Ok(None);
        }
        Ok(Some(asset))
    }

    async fn inner_fetch_blob(
        &self,
        request: FetchBlobRequest,
    ) -> Result<Response<FetchBlobResponse>, Error> {
        let instance_name = &request.instance_name;
        let store_info = self
            .stores
            .get(instance_name)
            .err_tip(|| format!("'instance_name' not configured for '{instance_name}'"))?;

        if request.uris.is_empty() {
            return Err(Error::new(
                Code::InvalidArgument,
                "No uris in fetch request".to_owned(),
            ));
        }
        // Checked before the lookup, so a request the downloader would refuse
        // is refused whether or not it is cached.
        let download_request = store_info
            .downloader
            .as_ref()
            .map(|_| DownloadRequest::parse(&request))
            .transpose()?;

        for uri in &request.uris {
            if let Some(asset) = Self::lookup(store_info, uri, &request).await? {
                return Ok(Response::new(FetchBlobResponse {
                    status: Some(GoogleStatus {
                        code: Code::Ok.into(),
                        message: "Fetch object found".to_owned(),
                        details: vec![],
                    }),
                    uri: asset.uri,
                    qualifiers: asset.qualifiers,
                    expires_at: asset.expire_at,
                    blob_digest: asset.blob_digest,
                    digest_function: asset.digest_function,
                }));
            }
        }

        let (Some(downloader), Some(download_request)) =
            (store_info.downloader.as_ref(), download_request)
        else {
            return Ok(not_found(&request, make_err!(Code::NotFound, "No item found")));
        };

        let hasher_func = digest_hasher_func_from_context();
        let timeout = request
            .timeout
            .and_then(|timeout| Duration::try_from(timeout).ok())
            .filter(|timeout| !timeout.is_zero())
            .map_or(downloader.timeout, |timeout| timeout.min(downloader.timeout));

        let mut last_err = make_err!(Code::NotFound, "No uri could be downloaded");
        for (index, uri) in request.uris.iter().enumerate() {
            let headers = download_request.headers_for(index);
            let result = tokio::time::timeout(
                timeout,
                downloader.download(uri, headers, download_request.sri.as_ref(), hasher_func),
            )
            .await
            .unwrap_or_else(|_| {
                Err(make_err!(
                    Code::DeadlineExceeded,
                    "Download of {uri} took over {timeout:?}"
                ))
            });
            match result {
                Ok(blob_digest) => {
                    let asset = Self::store_mappings(
                        store_info,
                        &request,
                        uri,
                        blob_digest,
                        hasher_func,
                    )
                    .await?;
                    return Ok(Response::new(FetchBlobResponse {
                        status: Some(GoogleStatus {
                            code: Code::Ok.into(),
                            message: "Fetch object downloaded".to_owned(),
                            details: vec![],
                        }),
                        uri: uri.clone(),
                        qualifiers: asset.qualifiers,
                        expires_at: None,
                        blob_digest: asset.blob_digest,
                        digest_function: asset.digest_function,
                    }));
                }
                Err(err) => {
                    warn!(uri, ?err, "Fetch download failed");
                    last_err = err;
                }
            }
        }
        Ok(not_found(&request, last_err))
    }

    /// Records the download under every URI of the request, so a later
    /// request naming any of them is served from the cache.
    async fn store_mappings(
        store_info: &FetchStoreInfo,
        request: &FetchBlobRequest,
        uri: &str,
        blob_digest: DigestInfo,
        hasher_func: DigestHasherFunc,
    ) -> Result<RemoteAssetArtifact, Error> {
        // Header values (credentials, often) are never stored.
        let qualifiers: Vec<Qualifier> = request
            .qualifiers
            .iter()
            .filter(|qualifier| !is_header_qualifier(&qualifier.name))
            .cloned()
            .collect();
        let mut asset = RemoteAssetArtifact::new(
            uri.to_owned(),
            qualifiers,
            blob_digest.into(),
            None,
            hasher_func.proto_digest_func().into(),
        );
        asset.fetched_at = Some(Timestamp::from(SystemTime::now()));
        let encoded = asset.as_bytes();
        for request_uri in &request.uris {
            let key =
                RemoteAssetQuery::new(request_uri.clone(), request.qualifiers.clone()).digest();
            store_info
                .store
                .update_oneshot(key, encoded.clone())
                .await
                .err_tip(|| format!("Failed to store the fetch mapping for {request_uri}"))?;
        }
        Ok(asset)
    }
}

fn not_found(request: &FetchBlobRequest, err: Error) -> Response<FetchBlobResponse> {
    Response::new(FetchBlobResponse {
        status: Some(err.into()),
        uri: request.uris.first().cloned().unwrap_or_default(),
        qualifiers: vec![],
        expires_at: None,
        blob_digest: None,
        digest_function: default_digest_hasher_func().proto_digest_func().into(),
    })
}

fn is_header_qualifier(name: &str) -> bool {
    name.starts_with(QUALIFIER_HTTP_HEADER) || name.starts_with(QUALIFIER_HTTP_HEADER_URL)
}

/// Whether a downloaded asset is recent enough for the request and not past
/// its expiry. A pushed asset (no `fetched_at`) is taken as fresh.
fn is_fresh(asset: &RemoteAssetArtifact, oldest_content_accepted: Option<&Timestamp>) -> bool {
    let to_time = |timestamp: &Timestamp| SystemTime::try_from(*timestamp).ok();
    if let Some(expire_at) = asset.expire_at.as_ref().and_then(to_time) {
        if expire_at <= SystemTime::now() {
            return false;
        }
    }
    match (
        asset.fetched_at.as_ref().and_then(to_time),
        oldest_content_accepted.and_then(to_time),
    ) {
        (Some(fetched_at), Some(oldest)) => fetched_at >= oldest,
        _ => true,
    }
}

/// A Subresource Integrity checksum: `<algorithm>-<base64 digest>`.
#[derive(Debug, Clone)]
struct Sri {
    algorithm: SriAlgorithm,
    expected: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
enum SriAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Debug)]
enum SriHasher {
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
}

impl Sri {
    fn parse(value: &str) -> Result<Self, Error> {
        let (algorithm, encoded) = value
            .split_once('-')
            .ok_or_else(|| make_input_err!("Malformed checksum.sri: {value}"))?;
        let algorithm = match algorithm {
            "sha256" => SriAlgorithm::Sha256,
            "sha384" => SriAlgorithm::Sha384,
            "sha512" => SriAlgorithm::Sha512,
            other => return Err(make_input_err!("Unsupported checksum.sri algorithm: {other}")),
        };
        let expected = BASE64
            .decode(encoded)
            .map_err(|err| make_input_err!("Malformed checksum.sri digest {encoded}: {err}"))?;
        Ok(Self {
            algorithm,
            expected,
        })
    }

    fn hasher(&self) -> SriHasher {
        match self.algorithm {
            SriAlgorithm::Sha256 => SriHasher::Sha256(Sha256::new()),
            SriAlgorithm::Sha384 => SriHasher::Sha384(Sha384::new()),
            SriAlgorithm::Sha512 => SriHasher::Sha512(Sha512::new()),
        }
    }
}

impl SriHasher {
    fn update(&mut self, data: &[u8]) {
        match self {
            Self::Sha256(hasher) => hasher.update(data),
            Self::Sha384(hasher) => hasher.update(data),
            Self::Sha512(hasher) => hasher.update(data),
        }
    }

    fn finalize(self) -> Vec<u8> {
        match self {
            Self::Sha256(hasher) => hasher.finalize().to_vec(),
            Self::Sha384(hasher) => hasher.finalize().to_vec(),
            Self::Sha512(hasher) => hasher.finalize().to_vec(),
        }
    }
}

/// What a `FetchBlobRequest`'s qualifiers ask of a download.
#[derive(Debug)]
struct DownloadRequest {
    sri: Option<Sri>,
    headers: HeaderMap,
    url_headers: HashMap<usize, HeaderMap>,
}

impl DownloadRequest {
    /// Every qualifier must be one the downloader honours: the Remote Asset
    /// API has servers refuse the request otherwise.
    fn parse(request: &FetchBlobRequest) -> Result<Self, Error> {
        let mut parsed = Self {
            sri: None,
            headers: HeaderMap::new(),
            url_headers: HashMap::new(),
        };
        for qualifier in &request.qualifiers {
            let name = qualifier.name.as_str();
            if name == QUALIFIER_CHECKSUM_SRI {
                parsed.sri = Some(Sri::parse(&qualifier.value)?);
            } else if let Some(rest) = name.strip_prefix(QUALIFIER_HTTP_HEADER_URL) {
                let (index, header) = rest
                    .split_once(':')
                    .ok_or_else(|| make_input_err!("Malformed qualifier: {name}"))?;
                let index: usize = index
                    .parse()
                    .map_err(|_| make_input_err!("Malformed qualifier: {name}"))?;
                if index >= request.uris.len() {
                    return Err(make_input_err!("Qualifier {name} names no uri"));
                }
                append_header(
                    parsed.url_headers.entry(index).or_default(),
                    header,
                    &qualifier.value,
                )?;
            } else if let Some(header) = name.strip_prefix(QUALIFIER_HTTP_HEADER) {
                append_header(&mut parsed.headers, header, &qualifier.value)?;
            } else if !DESCRIPTIVE_QUALIFIERS.contains(&name) {
                return Err(make_input_err!("Unsupported qualifier: {name}"));
            }
        }
        Ok(parsed)
    }

    fn headers_for(&self, index: usize) -> HeaderMap {
        let mut headers = self.headers.clone();
        if let Some(url_headers) = self.url_headers.get(&index) {
            for (name, value) in url_headers {
                headers.insert(name, value.clone());
            }
        }
        headers
    }
}

fn append_header(headers: &mut HeaderMap, name: &str, value: &str) -> Result<(), Error> {
    let name = HeaderName::from_bytes(name.as_bytes())
        .map_err(|err| make_input_err!("Invalid header name {name}: {err}"))?;
    let value = HeaderValue::from_str(value)
        .map_err(|err| make_input_err!("Invalid value for header {name}: {err}"))?;
    headers.append(name, value);
    Ok(())
}

#[derive(Debug)]
struct Downloader {
    cas_store: Store,
    client: reqwest::Client,
    max_size_bytes: u64,
    allowed_url_prefixes: Vec<String>,
    timeout: Duration,
    temp_path: PathBuf,
}

impl Downloader {
    fn new(config: &FetchDownloaderConfig, store_manager: &StoreManager) -> Result<Self, Error> {
        let cas_store = store_manager.get_store(&config.cas_store).ok_or_else(|| {
            make_input_err!("'downloader.cas_store': '{}' does not exist", config.cas_store)
        })?;
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls_config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|err| make_err!(Code::Internal, "Fetch downloader TLS config: {err}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
        // Redirects are followed (release downloads redirect to a CDN), and
        // HTTPS_PROXY and NO_PROXY from the environment are honoured.
        let client = reqwest::Client::builder()
            .use_preconfigured_tls(tls_config)
            .connect_timeout(Duration::from_secs(30))
            .build()
            .map_err(|err| make_err!(Code::Internal, "Fetch downloader HTTP client: {err}"))?;
        let temp_path = if config.temp_path.is_empty() {
            std::env::temp_dir()
        } else {
            PathBuf::from(&config.temp_path)
        };
        Ok(Self {
            cas_store,
            client,
            max_size_bytes: config.max_size_bytes,
            allowed_url_prefixes: config.allowed_url_prefixes.clone(),
            timeout: Duration::from_secs(config.timeout_s),
            temp_path,
        })
    }

    fn allows(&self, uri: &str) -> bool {
        (uri.starts_with("https://") || uri.starts_with("http://"))
            && (self.allowed_url_prefixes.is_empty()
                || self
                    .allowed_url_prefixes
                    .iter()
                    .any(|prefix| uri.starts_with(prefix.as_str())))
    }

    /// Downloads `uri` into the CAS, through a temporary file so a large blob
    /// never sits in memory, and returns its digest.
    async fn download(
        &self,
        uri: &str,
        headers: HeaderMap,
        sri: Option<&Sri>,
        hasher_func: DigestHasherFunc,
    ) -> Result<DigestInfo, Error> {
        if !self.allows(uri) {
            return Err(make_err!(
                Code::PermissionDenied,
                "{uri} is not an allowed download"
            ));
        }
        let path = self
            .temp_path
            .join(format!("fetch-{}", uuid::Uuid::new_v4().simple()));
        let result = self
            .download_to(uri, headers, sri, hasher_func, path.clone())
            .await;
        // The CAS may have taken the file already (a filesystem store moves it
        // into place).
        if let Err(err) = tokio::fs::remove_file(&path).await {
            if err.kind() != std::io::ErrorKind::NotFound {
                warn!(path = %path.display(), ?err, "Failed to remove a fetch download");
            }
        }
        result
    }

    async fn download_to(
        &self,
        uri: &str,
        headers: HeaderMap,
        sri: Option<&Sri>,
        hasher_func: DigestHasherFunc,
        path: PathBuf,
    ) -> Result<DigestInfo, Error> {
        let response = self
            .client
            .get(uri)
            .headers(headers)
            .send()
            .await
            .map_err(|err| make_err!(Code::Unavailable, "Downloading {uri}: {err}"))?;
        let status = response.status();
        if !status.is_success() {
            let code = if status == reqwest::StatusCode::NOT_FOUND {
                Code::NotFound
            } else {
                Code::Unavailable
            };
            return Err(make_err!(code, "Downloading {uri}: HTTP {status}"));
        }
        if let Some(length) = response.content_length() {
            if length > self.max_size_bytes {
                return Err(make_err!(
                    Code::ResourceExhausted,
                    "{uri} is {length} bytes, over the {} allowed",
                    self.max_size_bytes
                ));
            }
        }

        let mut file = fs::create_file(&path).await?;
        let mut digest_hasher = hasher_func.hasher();
        let mut sri_hasher = sri.map(Sri::hasher);
        let mut size: u64 = 0;
        let mut body = response.bytes_stream();
        while let Some(chunk) = body.next().await {
            let chunk =
                chunk.map_err(|err| make_err!(Code::Unavailable, "Downloading {uri}: {err}"))?;
            size = size.saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
            if size > self.max_size_bytes {
                return Err(make_err!(
                    Code::ResourceExhausted,
                    "{uri} is over the {} bytes allowed",
                    self.max_size_bytes
                ));
            }
            digest_hasher.update(&chunk);
            if let Some(sri_hasher) = sri_hasher.as_mut() {
                sri_hasher.update(&chunk);
            }
            file.write_all(&chunk)
                .await
                .err_tip(|| format!("Writing the download of {uri}"))?;
        }
        if let (Some(sri), Some(sri_hasher)) = (sri, sri_hasher) {
            let actual = sri_hasher.finalize();
            if actual != sri.expected {
                return Err(make_err!(
                    Code::InvalidArgument,
                    "{uri} does not match its checksum.sri: got {}",
                    BASE64.encode(actual)
                ));
            }
        }
        let digest = digest_hasher.finalize_digest();
        file.flush()
            .await
            .err_tip(|| format!("Flushing the download of {uri}"))?;
        file.rewind()
            .await
            .err_tip(|| format!("Rewinding the download of {uri}"))?;
        self.cas_store
            .update_with_whole_file(
                digest,
                path.into_os_string(),
                file,
                UploadSizeInfo::ExactSize(size),
            )
            .await
            .err_tip(|| format!("Uploading the download of {uri} to the CAS"))?;
        info!(uri, %digest, "Downloaded fetch asset");
        Ok(digest)
    }
}

#[tonic::async_trait]
impl Fetch for FetchServer {
    #[allow(clippy::blocks_in_conditions)]
    #[instrument(
        err(level = Level::WARN),
        ret(level = Level::INFO),
        skip_all,
        fields(request = ?grpc_request.get_ref())
    )]
    async fn fetch_blob(
        &self,
        grpc_request: Request<FetchBlobRequest>,
    ) -> Result<Response<FetchBlobResponse>, Status> {
        let request = grpc_request.into_inner();
        let digest_function = request.digest_function;
        self.inner_fetch_blob(request)
            .instrument(error_span!("fetch_server_fetch_blob"))
            .with_context(
                make_ctx_for_hash_func(digest_function).err_tip(|| "In FetchServer::fetch_blob")?,
            )
            .await
            .err_tip(|| "Failed on fetch_blob() command")
            .map_err(Into::into)
    }

    #[allow(clippy::blocks_in_conditions)]
    #[instrument(
        err(level = Level::WARN),
        ret(level = Level::INFO),
        skip_all,
        fields(request = ?_grpc_request.get_ref())
    )]
    async fn fetch_directory(
        &self,
        _grpc_request: Request<FetchDirectoryRequest>,
    ) -> Result<Response<FetchDirectoryResponse>, Status> {
        Err(Status::unimplemented("FetchDirectory not implemented"))
    }
}
