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

use core::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use nativelink_config::cas_server::{FetchConfig, FetchDownloaderConfig, WithInstanceName};
use nativelink_config::stores::{MemorySpec, StoreSpec};
use nativelink_error::Error;
use nativelink_macro::nativelink_test;
use nativelink_proto::build::bazel::remote::asset::v1::fetch_server::Fetch;
use nativelink_proto::build::bazel::remote::asset::v1::{
    FetchBlobRequest, FetchBlobResponse, Qualifier,
};
use nativelink_proto::build::bazel::remote::execution::v2::Digest;
use nativelink_proto::google::rpc::Status as GoogleStatus;
use nativelink_service::fetch_server::FetchServer;
use nativelink_service::remote_asset_proto::{RemoteAssetArtifact, RemoteAssetQuery};
use nativelink_store::default_store_factory::store_factory;
use nativelink_store::memory_store::MemoryStore;
use nativelink_store::store_manager::StoreManager;
use nativelink_util::common::DigestInfo;
use nativelink_util::store_trait::StoreLike;
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tonic::{Code, Request, Status};

async fn make_store_manager() -> Result<Arc<StoreManager>, Error> {
    let store_manager = Arc::new(StoreManager::new());
    store_manager.add_store(
        "test_fetch_store",
        store_factory(
            &StoreSpec::Memory(MemorySpec::default()),
            &store_manager,
            None,
        )
        .await?,
    )?;
    store_manager.add_store(
        "test_cas_store",
        store_factory(
            &StoreSpec::Memory(MemorySpec::default()),
            &store_manager,
            None,
        )
        .await?,
    )?;
    Ok(store_manager)
}

#[nativelink_test]
async fn test_fetch_blob() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let instance_name = "foo_instance_name".to_string();
    let fs = FetchServer::new(
        &[WithInstanceName {
            instance_name: instance_name.clone(),
            config: FetchConfig {
                fetch_store: String::from("test_fetch_store"),
                downloader: None,
            },
        }],
        &store_manager,
    )
    .expect("FetchServer config error");

    let remote_asset = RemoteAssetArtifact::new(
        "http://1234".to_owned(),
        vec![Qualifier {
            name: "resource_type".to_owned(),
            value: "test".to_owned(),
        }],
        Digest {
            hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
            size_bytes: 4,
        },
        None,
        0,
    );
    let fetch_store = store_manager.get_store("test_fetch_store").unwrap();
    let digest = remote_asset.digest();
    fetch_store
        .update_oneshot(digest, remote_asset.as_bytes())
        .await
        .unwrap();

    let raw_response: tonic::Response<FetchBlobResponse> = fs
        .fetch_blob(Request::new(FetchBlobRequest {
            instance_name,
            timeout: None,
            oldest_content_accepted: None,
            uris: vec!["http://1234".to_owned()],
            qualifiers: vec![Qualifier {
                name: "resource_type".to_owned(),
                value: "test".to_owned(),
            }],
            digest_function: 0,
        }))
        .await?;
    assert_eq!(
        raw_response.into_inner(),
        FetchBlobResponse {
            status: Some(GoogleStatus {
                code: 0,
                message: "Fetch object found".to_owned(),
                details: vec![]
            }),
            uri: "http://1234".to_owned(),
            qualifiers: vec![Qualifier {
                name: "resource_type".to_owned(),
                value: "test".to_owned(),
            }],
            expires_at: None,
            blob_digest: Some(Digest {
                hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_owned(),
                size_bytes: 4
            }),
            digest_function: 0
        }
    );
    Ok(())
}

/// A corrupt store entry must return an error, not panic.
#[nativelink_test]
async fn test_fetch_blob_corrupt_store_entry_returns_error() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let instance_name = "foo_instance_name".to_string();
    let fs = FetchServer::new(
        &[WithInstanceName {
            instance_name: instance_name.clone(),
            config: FetchConfig {
                fetch_store: String::from("test_fetch_store"),
                downloader: None,
            },
        }],
        &store_manager,
    )
    .expect("FetchServer config error");

    let query = RemoteAssetQuery::new("http://1234".to_owned(), vec![]);
    let digest = query.digest();
    let fetch_store = store_manager.get_store("test_fetch_store").unwrap();
    fetch_store
        .update_oneshot(digest, bytes::Bytes::from_static(&[0xFF, 0xFF, 0xFF]))
        .await
        .unwrap();

    let result = fs
        .fetch_blob(Request::new(FetchBlobRequest {
            instance_name,
            timeout: None,
            oldest_content_accepted: None,
            uris: vec!["http://1234".to_owned()],
            qualifiers: vec![],
            digest_function: 0,
        }))
        .await;
    assert!(
        result.is_err(),
        "corrupt store entry should return an error, not panic: {result:?}"
    );
    Ok(())
}

const ASSET: &[u8] = b"a downloaded asset";

/// An HTTP server answering every request with `body`, counting requests.
async fn serve(body: &'static [u8]) -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            counter.fetch_add(1, Ordering::SeqCst);
            let mut request = [0u8; 4096];
            drop(socket.read(&mut request).await);
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            drop(socket.write_all(head.as_bytes()).await);
            drop(socket.write_all(body).await);
            drop(socket.shutdown().await);
        }
    });
    (format!("http://{address}/asset.tar.gz"), hits)
}

fn sri_of(body: &[u8]) -> String {
    format!("sha256-{}", BASE64.encode(Sha256::digest(body)))
}

fn downloading_server(store_manager: &StoreManager) -> FetchServer {
    FetchServer::new(
        &[WithInstanceName {
            instance_name: String::new(),
            config: FetchConfig {
                fetch_store: String::from("test_fetch_store"),
                downloader: Some(FetchDownloaderConfig {
                    cas_store: String::from("test_cas_store"),
                    max_size_bytes: 1024,
                    allowed_url_prefixes: vec![],
                    timeout_s: 30,
                    temp_path: String::new(),
                }),
            },
        }],
        store_manager,
    )
    .expect("FetchServer config error")
}

fn fetch_request(uri: &str, qualifiers: Vec<Qualifier>) -> Request<FetchBlobRequest> {
    Request::new(FetchBlobRequest {
        instance_name: String::new(),
        timeout: None,
        oldest_content_accepted: None,
        uris: vec![uri.to_owned()],
        qualifiers,
        digest_function: 0,
    })
}

fn sri_qualifier(body: &[u8]) -> Vec<Qualifier> {
    vec![Qualifier {
        name: "checksum.sri".to_owned(),
        value: sri_of(body),
    }]
}

fn asset_digest() -> DigestInfo {
    DigestInfo::new(Sha256::digest(ASSET).into(), ASSET.len() as u64)
}

#[nativelink_test]
async fn test_fetch_blob_downloads_on_miss() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = downloading_server(&store_manager);
    let (uri, hits) = serve(ASSET).await;

    let response = fs
        .fetch_blob(fetch_request(&uri, sri_qualifier(ASSET)))
        .await?
        .into_inner();
    assert_eq!(response.status.unwrap().code, 0);
    assert_eq!(response.uri, uri);
    assert_eq!(response.blob_digest, Some(asset_digest().into()));
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    let cas = store_manager.get_store("test_cas_store").unwrap();
    let stored = cas
        .get_part_unchunked(asset_digest(), 0, None)
        .await
        .expect("downloaded blob should be in the CAS");
    assert_eq!(&stored[..], ASSET);
    Ok(())
}

#[nativelink_test]
async fn test_fetch_blob_reuses_download() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = downloading_server(&store_manager);
    let (uri, hits) = serve(ASSET).await;

    for _ in 0..2 {
        let response = fs
            .fetch_blob(fetch_request(&uri, sri_qualifier(ASSET)))
            .await?
            .into_inner();
        assert_eq!(response.blob_digest, Some(asset_digest().into()));
    }
    assert_eq!(hits.load(Ordering::SeqCst), 1, "second fetch should be cached");
    Ok(())
}

#[nativelink_test]
async fn test_fetch_blob_refetches_evicted_blob() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = downloading_server(&store_manager);
    let (uri, hits) = serve(ASSET).await;

    fs.fetch_blob(fetch_request(&uri, sri_qualifier(ASSET)))
        .await?;
    let cas = store_manager.get_store("test_cas_store").unwrap();
    assert!(
        cas.downcast_ref::<MemoryStore>(None)
            .unwrap()
            .remove_entry(asset_digest().into())
            .await
    );

    let response = fs
        .fetch_blob(fetch_request(&uri, sri_qualifier(ASSET)))
        .await?
        .into_inner();
    assert_eq!(response.blob_digest, Some(asset_digest().into()));
    assert_eq!(hits.load(Ordering::SeqCst), 2, "evicted blob should be downloaded again");
    assert!(cas.has(asset_digest()).await?.is_some());
    Ok(())
}

#[nativelink_test]
async fn test_fetch_blob_rejects_checksum_mismatch() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = downloading_server(&store_manager);
    let (uri, _hits) = serve(ASSET).await;

    let response = fs
        .fetch_blob(fetch_request(&uri, sri_qualifier(b"something else")))
        .await?
        .into_inner();
    assert_eq!(response.status.unwrap().code, i32::from(Code::InvalidArgument));
    assert_eq!(response.blob_digest, None);
    let cas = store_manager.get_store("test_cas_store").unwrap();
    assert!(cas.has(asset_digest()).await?.is_none());
    Ok(())
}

#[nativelink_test]
async fn test_fetch_blob_rejects_unsupported_qualifier() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = downloading_server(&store_manager);
    let (uri, hits) = serve(ASSET).await;

    let result = fs
        .fetch_blob(fetch_request(
            &uri,
            vec![Qualifier {
                name: "vcs.commit".to_owned(),
                value: "abc".to_owned(),
            }],
        ))
        .await;
    assert_eq!(result.unwrap_err().code(), Code::InvalidArgument);
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    Ok(())
}

#[nativelink_test]
async fn test_fetch_blob_respects_allowed_prefixes() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = FetchServer::new(
        &[WithInstanceName {
            instance_name: String::new(),
            config: FetchConfig {
                fetch_store: String::from("test_fetch_store"),
                downloader: Some(FetchDownloaderConfig {
                    cas_store: String::from("test_cas_store"),
                    max_size_bytes: 1024,
                    allowed_url_prefixes: vec!["https://example.com/".to_owned()],
                    timeout_s: 30,
                    temp_path: String::new(),
                }),
            },
        }],
        &store_manager,
    )
    .expect("FetchServer config error");
    let (uri, hits) = serve(ASSET).await;

    let response = fs
        .fetch_blob(fetch_request(&uri, sri_qualifier(ASSET)))
        .await?
        .into_inner();
    assert_eq!(response.status.unwrap().code, i32::from(Code::PermissionDenied));
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    Ok(())
}

#[nativelink_test]
async fn test_fetch_blob_never_caches_unpinned() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = downloading_server(&store_manager);
    let (uri, hits) = serve(ASSET).await;

    for _ in 0..2 {
        let response = fs.fetch_blob(fetch_request(&uri, vec![])).await?.into_inner();
        assert_eq!(response.blob_digest, Some(asset_digest().into()));
    }
    assert_eq!(
        hits.load(Ordering::SeqCst),
        2,
        "a download without checksum.sri should not be served from the cache"
    );
    Ok(())
}
