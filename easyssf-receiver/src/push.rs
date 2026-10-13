//! Push delivery (RFC 8935) without the HTTP: header and body in, status and body out.

use std::sync::Arc;

use easyssf_core::SsfDeliveryMethod;
use serde_json::json;
use subtle::ConstantTimeEq;

use crate::metrics::{NoopSsfReceiverMetrics, SsfReceiverMetrics, SsfSetOutcome};
use crate::set::{SsfErrorCode, SsfSetProcessingError, SsfSetProcessor, SsfSetVerificationError, unverified_issuer};

/// The response to a push request (RFC 8935, section 2.2 to 2.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsfPushResponse {
    /// The HTTP status.
    pub status: u16,
    /// The JSON error document, `None` if the response has no body; send it with the
    /// [`CONTENT_TYPE`](Self::CONTENT_TYPE) and [`CONTENT_LANGUAGE`](Self::CONTENT_LANGUAGE)
    /// headers.
    pub body: Option<String>,
}

impl SsfPushResponse {
    /// The content type of the body.
    pub const CONTENT_TYPE: &'static str = "application/json";
    /// The language of the description in the body, to be sent as `Content-Language` header (RFC
    /// 8935, section 2.3).
    pub const CONTENT_LANGUAGE: &'static str = "en";

    /// Whether the SET was accepted.
    pub fn is_accepted(&self) -> bool {
        self.status == 202
    }

    fn error(status: u16, code: &str, description: &str) -> Self {
        Self {
            status,
            body: Some(json!({ "err": code, "description": description }).to_string()),
        }
    }

    fn status(status: u16) -> Self {
        Self { status, body: None }
    }
}

/// The `Authorization` header a transmitter has to send, by the issuer of its SETs.
pub type ExpectedAuthorizationHeaders = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

#[derive(Clone)]
enum ExpectedHeader {
    Fixed(Option<Arc<str>>),
    ByIssuer(ExpectedAuthorizationHeaders),
}

/// Handles SETs delivered using HTTP push (RFC 8935), independent of the web framework: call
/// [`handle`](Self::handle) from the endpoint the transmitter posts SETs to and send the returned
/// response.
///
/// A SET is verified and handled before it is acknowledged with `202 Accepted`. Invalid SETs are
/// rejected with `400 Bad Request` and an error document. When the SET could not be processed for
/// a reason the transmitter is not responsible for (its keys are temporarily not retrievable, an
/// event handler failed) a `5xx` status asks it to deliver the SET again.
#[derive(Clone)]
pub struct SsfPushHandler {
    processor: Arc<SsfSetProcessor>,
    expected: ExpectedHeader,
    metrics: Arc<dyn SsfReceiverMetrics>,
}

impl SsfPushHandler {
    /// The maximum size of a SET in bytes. An endpoint does not need to read more than one byte
    /// beyond it.
    pub const MAX_SET_SIZE: usize = 256 * 1024;

    const AUTHENTICATION_FAILED: &'static str = "authentication_failed";

    /// A handler that expects exactly this `Authorization` header, or none.
    pub fn new(processor: Arc<SsfSetProcessor>, expected_authorization_header: Option<&str>) -> Self {
        Self {
            processor,
            expected: ExpectedHeader::Fixed(
                expected_authorization_header
                    .filter(|h| !h.trim().is_empty())
                    .map(Arc::from),
            ),
            metrics: Arc::new(NoopSsfReceiverMetrics),
        }
    }

    /// For a receiver with several transmitters: the `Authorization` header a transmitter has to
    /// send is looked up by the issuer of the SET, which is read before the SET is verified.
    pub fn by_issuer(
        processor: Arc<SsfSetProcessor>,
        expected_authorization_headers: ExpectedAuthorizationHeaders,
    ) -> Self {
        Self {
            processor,
            expected: ExpectedHeader::ByIssuer(expected_authorization_headers),
            metrics: Arc::new(NoopSsfReceiverMetrics),
        }
    }

    /// Records what the handler does.
    pub fn with_metrics(mut self, metrics: Arc<dyn SsfReceiverMetrics>) -> Self {
        self.metrics = metrics;
        self
    }

    /// The processor the SETs go to.
    pub fn processor(&self) -> &Arc<SsfSetProcessor> {
        &self.processor
    }

    /// Handles a push request: the `Authorization` header of the request, if any, and the body,
    /// the SET in JWS compact serialization.
    pub async fn handle(&self, authorization_header: Option<&str>, body: &[u8]) -> SsfPushResponse {
        if let ExpectedHeader::Fixed(expected) = &self.expected
            && !authenticated(expected.as_deref(), authorization_header)
        {
            self.metrics
                .set_received(None, SsfDeliveryMethod::Push, SsfSetOutcome::Unauthenticated);
            return SsfPushResponse::error(
                401,
                Self::AUTHENTICATION_FAILED,
                "The transmitter could not be authenticated",
            );
        }
        if body.len() > Self::MAX_SET_SIZE {
            return SsfPushResponse::error(413, SsfErrorCode::InvalidRequest.as_str(), "The SET is too large");
        }
        let Ok(encoded_set) = std::str::from_utf8(body) else {
            return SsfPushResponse::error(400, SsfErrorCode::InvalidRequest.as_str(), "The SET is not UTF-8");
        };
        let encoded_set = encoded_set.trim();
        if let ExpectedHeader::ByIssuer(headers) = &self.expected {
            let issuer = unverified_issuer(encoded_set);
            let expected = issuer.as_deref().and_then(|issuer| headers(issuer));
            if !authenticated(expected.as_deref(), authorization_header) {
                self.metrics.set_received(
                    issuer.as_deref(),
                    SsfDeliveryMethod::Push,
                    SsfSetOutcome::Unauthenticated,
                );
                return SsfPushResponse::error(
                    401,
                    Self::AUTHENTICATION_FAILED,
                    "The transmitter could not be authenticated",
                );
            }
        }
        match self.processor.process(encoded_set, SsfDeliveryMethod::Push).await {
            Ok(_) => SsfPushResponse::status(202),
            Err(SsfSetProcessingError::Verification(SsfSetVerificationError::Rejected { code, description })) => {
                tracing::debug!(code = code.as_str(), description, "Rejecting SET");
                SsfPushResponse::error(400, code.as_str(), &description)
            }
            Err(SsfSetProcessingError::Verification(SsfSetVerificationError::TransmitterUnavailable(error))) => {
                tracing::warn!(%error, "Could not verify SET, asking the transmitter to deliver it again");
                SsfPushResponse::status(503)
            }
            // temporary: the transmitter delivers the SET again
            Err(SsfSetProcessingError::InProgress) => SsfPushResponse::status(503),
            // already logged per handler
            Err(SsfSetProcessingError::Handling { .. }) => SsfPushResponse::status(500),
            Err(SsfSetProcessingError::Store(error)) => {
                tracing::error!(%error, "The dedup store failed, asking the transmitter to deliver the SET again");
                SsfPushResponse::status(500)
            }
        }
    }
}

fn authenticated(expected: Option<&str>, given: Option<&str>) -> bool {
    match expected {
        None => true,
        Some(expected) => {
            let given = given.unwrap_or_default();
            bool::from(expected.as_bytes().ct_eq(given.as_bytes()))
        }
    }
}
