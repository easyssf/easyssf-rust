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
#[cfg(feature = "reqwest")]
#[derive(Debug, Clone)]
pub struct ReqwestSsfHttpClient {
    client: reqwest::Client,
    timeout: Duration,
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
        Self { client, timeout }
    }

    /// A client of your own, for example one with a `User-Agent`; `timeout` applies to requests
    /// that do not set their own.
    pub fn from_client(client: reqwest::Client, timeout: Duration) -> Self {
        Self { client, timeout }
    }

    /// Sets the `User-Agent` header to send with every request.
    pub fn with_user_agent(self, user_agent: &str) -> Self {
        let client = reqwest::Client::builder()
            .connect_timeout(self.timeout)
            .user_agent(user_agent)
            .build()
            .expect("a reqwest client with a user agent");
        Self {
            client,
            timeout: self.timeout,
        }
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
        let response = builder.send().await?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_str().unwrap_or("").to_owned()))
            .collect();
        let body = response.text().await?;
        Ok(SsfHttpResponse { status, headers, body })
    }
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
