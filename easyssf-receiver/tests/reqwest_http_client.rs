//! Port of `JdkSsfHttpClientTests`: the bound on the response bodies of [`ReqwestSsfHttpClient`].
#![cfg(feature = "reqwest")]

use easyssf_receiver::http::{ReqwestSsfHttpClient, SsfHttpClient, SsfHttpRequest, SsfHttpResponse};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use url::Url;

/// Answers every request with the same response, written as given: a test server that sets its
/// own headers could not send a `Content-Length` that the body does not keep.
struct OneResponseServer {
    url: Url,
    task: tokio::task::JoinHandle<()>,
}

impl OneResponseServer {
    async fn start(head: &str, body: Vec<u8>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        let mut response = head.as_bytes().to_vec();
        response.extend_from_slice(&body);
        let task = tokio::spawn(async move {
            while let Ok((mut connection, _)) = listener.accept().await {
                let response = response.clone();
                tokio::spawn(async move {
                    // the request ends with an empty line
                    let mut request = Vec::new();
                    let mut buffer = [0u8; 1024];
                    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                        match connection.read(&mut buffer).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => request.extend_from_slice(&buffer[..n]),
                        }
                    }
                    // the client may go away before it read everything
                    let _ = connection.write_all(&response).await;
                    let _ = connection.shutdown().await;
                });
            }
        });
        Self { url, task }
    }
}

impl Drop for OneResponseServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn chunked(body: &[u8]) -> Vec<u8> {
    let mut chunked = format!("{:x}\r\n", body.len()).into_bytes();
    chunked.extend_from_slice(body);
    chunked.extend_from_slice(b"\r\n0\r\n\r\n");
    chunked
}

#[tokio::test]
async fn cuts_off_response_larger_than_the_maximum() {
    let body = vec![b'x'; 1000];
    // a response that declares its length is refused before it is read, one without (chunked) is
    // cut off while it is read
    let declared = OneResponseServer::start(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Length: 1000\r\nConnection: close\r\n\r\n",
        body.clone(),
    )
    .await;
    let chunked = OneResponseServer::start(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
        chunked(&body),
    )
    .await;

    let client = ReqwestSsfHttpClient::new().with_max_response_size(999);
    for server in [&declared, &chunked] {
        let error = client
            .execute(SsfHttpRequest::get(server.url.clone()))
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("larger than the 999 bytes accepted"),
            "{error}"
        );
    }

    let client = client.with_max_response_size(1000);
    let response = client.execute(SsfHttpRequest::get(declared.url.clone())).await.unwrap();
    assert_eq!(response.body.as_bytes(), body);
    let response = client.execute(SsfHttpRequest::get(chunked.url.clone())).await.unwrap();
    assert_eq!(response.body.len(), 1000);
}

#[tokio::test]
async fn decodes_the_body_in_the_charset_of_the_content_type() {
    let server = OneResponseServer::start(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=\"ISO-8859-1\"\r\nContent-Length: 3\r\nConnection: close\r\n\r\n",
        vec![b'"', 0xE9, b'"'],
    )
    .await;
    let response = ReqwestSsfHttpClient::new()
        .execute(SsfHttpRequest::get(server.url.clone()))
        .await
        .unwrap();
    assert_eq!(response.body, "\"é\"");
}

#[test]
fn response_bodies_are_bounded_by_default() {
    assert_eq!(SsfHttpResponse::DEFAULT_MAX_BODY_SIZE, 4 * 1024 * 1024);
    assert_eq!(
        ReqwestSsfHttpClient::new().max_response_size(),
        SsfHttpResponse::DEFAULT_MAX_BODY_SIZE
    );
    assert!(std::panic::catch_unwind(|| ReqwestSsfHttpClient::new().with_max_response_size(0)).is_err());
}
