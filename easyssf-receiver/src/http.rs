//! The HTTP client the receiver calls the transmitter with. All calls go through
//! [`SsfHttpClient`]; implement it to use the HTTP client of your framework, or use
//! [`ReqwestSsfHttpClient`] (feature `reqwest`, on by default).

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use url::Url;

use crate::BoxError;

/// An HTTP request to the transmitter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsfHttpRequest {
    /// The HTTP method.
    pub method: String,
    /// The target of the request.
    pub url: Url,
    /// The request headers, in order.
    pub headers: Vec<(String, String)>,
    /// The request body, `None` for none.
    pub body: Option<String>,
    /// How long to wait for the response, `None` for the timeout of the client; a long poll (RFC
    /// 8936) waits longer than other calls.
    pub timeout: Option<Duration>,
}

impl SsfHttpRequest {
    /// A request without headers and body.
    pub fn of(method: &str, url: Url) -> Self {
        Self {
            method: method.to_owned(),
            url,
            headers: Vec::new(),
            body: None,
            timeout: None,
        }
    }

    /// A `GET` that accepts JSON.
    pub fn get(url: Url) -> Self {
        Self::of("GET", url).with_header("Accept", "application/json")
    }

    /// Adds or replaces a header.
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers
            .retain(|(existing, _)| !existing.eq_ignore_ascii_case(name));
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    /// Sets how long to wait for the response of this request, instead of the timeout of the
    /// client.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Adds an `Authorization` header with the given bearer token, if there is one.
    pub fn with_bearer_token(self, access_token: Option<&str>) -> Self {
        match access_token {
            Some(token) => self.with_header("Authorization", &format!("Bearer {token}")),
            None => self,
        }
    }

    /// Sets the body and its content type.
    pub fn with_body(mut self, content_type: &str, body: String) -> Self {
        self.body = Some(body);
        self.with_header("Content-Type", content_type)
    }

    /// Sets a JSON body.
    pub fn with_json_body(self, json: String) -> Self {
        self.with_body("application/json", json)
    }

    /// The first value of the header with the given name, ignoring its case.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// The response of the transmitter to an [`SsfHttpRequest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsfHttpResponse {
    /// The HTTP status.
    pub status: u16,
    /// The response headers.
    pub headers: Vec<(String, String)>,
    /// The response body, empty if there was none.
    pub body: String,
}

impl SsfHttpResponse {
    /// How large a response body may be unless an [`SsfHttpClient`] is configured otherwise, 4
    /// MiB. The receiver reads transmitter metadata, JWK Sets, stream configurations and poll
    /// responses, none of which comes near that, so a larger response is a fault or an attack
    /// and is cut off rather than buffered. Implementations of [`SsfHttpClient`] should bound
    /// their responses as well.
    pub const DEFAULT_MAX_BODY_SIZE: usize = 4 * 1024 * 1024;

    /// A response with a status and a body and no headers.
    pub fn new(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: body.into(),
        }
    }

    /// Adds a header.
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    /// Whether the status is 2xx.
    pub fn is_successful(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// The first value of the header with the given name, ignoring its case.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Sends HTTP requests to the transmitter. All calls of the receiver go through this trait,
/// implement it to use the HTTP client of your framework.
#[async_trait]
pub trait SsfHttpClient: Send + Sync + 'static {
    /// Sends the request and returns the response, whatever its status. An error means no
    /// response was received.
    async fn execute(&self, request: SsfHttpRequest) -> Result<SsfHttpResponse, BoxError>;
}

#[async_trait]
impl<T: SsfHttpClient> SsfHttpClient for Arc<T> {
    async fn execute(&self, request: SsfHttpRequest) -> Result<SsfHttpResponse, BoxError> {
        (**self).execute(request).await
    }
}

#[async_trait]
impl SsfHttpClient for Arc<dyn SsfHttpClient> {
    async fn execute(&self, request: SsfHttpRequest) -> Result<SsfHttpResponse, BoxError> {
        (**self).execute(request).await
    }
}

/// [`SsfHttpClient`] on [`reqwest`]. Feature `reqwest`.
///
/// A response body larger than [the maximum](Self::with_max_response_size) is not buffered: the
/// call fails as if no response was received.
#[cfg(feature = "reqwest")]
#[derive(Debug, Clone)]
pub struct ReqwestSsfHttpClient {
    client: reqwest::Client,
    timeout: Duration,
    max_response_size: usize,
}

#[cfg(feature = "reqwest")]
impl ReqwestSsfHttpClient {
    /// A client with 5 seconds of connect and read timeout.
    pub fn new() -> Self {
        Self::with_timeout(Duration::from_secs(5))
    }

    /// A client whose requests wait `timeout` for the response unless the request says
    /// otherwise.
    pub fn with_timeout(timeout: Duration) -> Self {
        let client = reqwest::Client::builder()
            .connect_timeout(timeout)
            .build()
            .expect("a reqwest client with default settings");
        Self::from_client(client, timeout)
    }

    /// A client of your own, for example one with a `User-Agent`; `timeout` applies to requests
    /// that do not set their own.
    pub fn from_client(client: reqwest::Client, timeout: Duration) -> Self {
        Self {
            client,
            timeout,
            max_response_size: SsfHttpResponse::DEFAULT_MAX_BODY_SIZE,
        }
    }

    /// Sets the `User-Agent` header to send with every request.
    pub fn with_user_agent(self, user_agent: &str) -> Self {
        let client = reqwest::Client::builder()
            .connect_timeout(self.timeout)
            .user_agent(user_agent)
            .build()
            .expect("a reqwest client with a user agent");
        Self { client, ..self }
    }

    /// Bounds the response bodies, [4 MiB](SsfHttpResponse::DEFAULT_MAX_BODY_SIZE) by default. A
    /// transmitter that sends more is treated as unavailable: the receiver never buffers a
    /// response of a size the transmitter chooses.
    ///
    /// # Panics
    ///
    /// If `max_response_size` is zero.
    pub fn with_max_response_size(mut self, max_response_size: usize) -> Self {
        assert!(max_response_size > 0, "max_response_size must be positive");
        self.max_response_size = max_response_size;
        self
    }

    /// The largest response body read, in bytes.
    pub fn max_response_size(&self) -> usize {
        self.max_response_size
    }
}

#[cfg(feature = "reqwest")]
impl Default for ReqwestSsfHttpClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "reqwest")]
#[async_trait]
impl SsfHttpClient for ReqwestSsfHttpClient {
    async fn execute(&self, request: SsfHttpRequest) -> Result<SsfHttpResponse, BoxError> {
        let method = reqwest::Method::from_bytes(request.method.as_bytes())?;
        let mut builder = self
            .client
            .request(method, request.url)
            .timeout(request.timeout.unwrap_or(self.timeout));
        for (name, value) in &request.headers {
            builder = builder.header(name, value);
        }
        if let Some(body) = request.body {
            builder = builder.body(body);
        }
        let mut response = builder.send().await?;
        let status = response.status().as_u16();
        let headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_str().unwrap_or("").to_owned()))
            .collect();
        let max = self.max_response_size;
        // a response that declares its length is refused before it is read, one without
        // (chunked) is cut off while it is read; dropping the response ends the connection
        if let Some(declared) = response.content_length()
            && declared > max as u64
        {
            return Err(format!(
                "The response of {} is {declared} bytes, larger than the {max} bytes accepted",
                response.url()
            )
            .into());
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if bytes.len() + chunk.len() > max {
                return Err(format!(
                    "The response of {} is larger than the {max} bytes accepted and was cut off",
                    response.url()
                )
                .into());
            }
            bytes.extend_from_slice(&chunk);
        }
        let content_type = headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
            .map(|(_, value)| value.as_str());
        let (body, _, _) = charset_of(content_type).decode(&bytes);
        Ok(SsfHttpResponse {
            status,
            headers,
            body: body.into_owned(),
        })
    }
}

/// The charset the `Content-Type` header names, UTF-8 if it names none or an unknown one.
#[cfg(feature = "reqwest")]
fn charset_of(content_type: Option<&str>) -> &'static encoding_rs::Encoding {
    content_type
        .into_iter()
        .flat_map(|value| value.split(';'))
        .map(str::trim)
        .find_map(|parameter| {
            let (name, value) = parameter.split_once('=')?;
            name.trim()
                .eq_ignore_ascii_case("charset")
                .then(|| value.trim().trim_matches('"'))
        })
        .and_then(|label| encoding_rs::Encoding::for_label(label.as_bytes()))
        .unwrap_or(encoding_rs::UTF_8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_builders_replace_headers_and_add_the_bearer_token() {
        let request = SsfHttpRequest::get(Url::parse("https://t.example/x").unwrap())
            .with_header("accept", "text/plain")
            .with_bearer_token(Some("tok"))
            .with_bearer_token(None)
            .with_json_body("{}".to_owned())
            .with_timeout(Duration::from_secs(1));
        assert_eq!(request.header("Accept"), Some("text/plain"));
        assert_eq!(request.headers.len(), 3);
        assert_eq!(request.header("authorization"), Some("Bearer tok"));
        assert_eq!(request.header("content-type"), Some("application/json"));
        assert_eq!(request.body.as_deref(), Some("{}"));
        assert_eq!(request.timeout, Some(Duration::from_secs(1)));
    }

    #[test]
    fn response_tells_success_and_headers_ignoring_case() {
        let response = SsfHttpResponse::new(204, "").with_header("Retry-After", "5");
        assert!(response.is_successful());
        assert_eq!(response.header("retry-after"), Some("5"));
        assert!(!SsfHttpResponse::new(503, "").is_successful());
    }
}
