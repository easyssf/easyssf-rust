//! Validates the access tokens of the identity provider, the part Spring Security's resource server support
//! plays in the Java example: the signature against the keys of the issuer (found through OpenID
//! Connect discovery), `iss` and `exp`. The claims are left on the request as [`AccessToken`] for
//! the handlers and as [`SsfTokenClaims`] for the revocation layer of the receiver, which reads
//! `iss`, `sub`, `sid` and `iat` from them.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use easyssf_receiver::revocation::SsfTokenClaims;
use http::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use http::{HeaderValue, StatusCode};
use jsonwebtoken::jwk::{Jwk, JwkSet};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde_json::{Map, Value};
use tokio::sync::RwLock;

/// The claims of a validated access token.
#[derive(Debug, Clone)]
pub struct AccessToken(pub Map<String, Value>);

impl AccessToken {
    /// A string claim.
    pub fn string(&self, claim: &str) -> Option<&str> {
        self.0.get(claim).and_then(Value::as_str)
    }

    /// A numeric date claim (`iat`, `exp`), seconds since the epoch.
    pub fn time(&self, claim: &str) -> Option<SystemTime> {
        self.0
            .get(claim)
            .and_then(Value::as_u64)
            .map(|seconds| UNIX_EPOCH + Duration::from_secs(seconds))
    }

    /// The claims the revocation check of the receiver reads.
    pub fn claims(&self) -> SsfTokenClaims {
        SsfTokenClaims {
            issuer: self.string("iss").map(str::to_owned),
            subject: self.string("sub").map(str::to_owned),
            session_id: self.string("sid").map(str::to_owned),
            issued_at: self.time("iat"),
        }
    }
}

/// Validates access tokens of one issuer with the keys of its `jwks_uri`. The keys are loaded on
/// first use and again, at most every ten seconds, when a token names a key that is not known:
/// identity providers rotate them.
pub struct AccessTokens {
    issuer: String,
    http: reqwest::Client,
    keys: RwLock<Option<Keys>>,
}

struct Keys {
    jwks: JwkSet,
    fetched_at: Instant,
}

const ACCEPTED_ALGORITHMS: [Algorithm; 9] = [
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::EdDSA,
];

impl AccessTokens {
    /// Validates the tokens `issuer` signs.
    pub fn new(issuer: &str) -> Self {
        Self {
            issuer: issuer.trim_end_matches('/').to_owned(),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("HTTP client"),
            keys: RwLock::new(None),
        }
    }

    /// The claims of the token, if it is valid.
    pub async fn validate(&self, token: &str) -> Result<AccessToken, String> {
        let header = jsonwebtoken::decode_header(token).map_err(|error| format!("not a JWT: {error}"))?;
        if !ACCEPTED_ALGORITHMS.contains(&header.alg) {
            return Err(format!("unsupported algorithm {:?}", header.alg));
        }
        let kid = header.kid.ok_or("the token names no key (kid)")?;
        let jwk = self.key(&kid).await?;
        let key = DecodingKey::from_jwk(&jwk).map_err(|error| format!("unusable key {kid}: {error}"))?;
        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[&self.issuer]);
        // which audience an access token carries depends on the identity provider and its
        // configuration, so this example does not check it; a real resource server does
        validation.validate_aud = false;
        validation.leeway = 30;
        let data = jsonwebtoken::decode::<Map<String, Value>>(token, &key, &validation)
            .map_err(|error| format!("invalid token: {error}"))?;
        Ok(AccessToken(data.claims))
    }

    async fn key(&self, kid: &str) -> Result<Jwk, String> {
        if let Some(keys) = self.keys.read().await.as_ref()
            && let Some(jwk) = keys.jwks.find(kid)
        {
            return Ok(jwk.clone());
        }
        let mut keys = self.keys.write().await;
        if keys
            .as_ref()
            .is_none_or(|keys| keys.fetched_at.elapsed() > Duration::from_secs(10))
        {
            *keys = Some(Keys {
                jwks: self.fetch_keys().await?,
                fetched_at: Instant::now(),
            });
        }
        keys.as_ref()
            .and_then(|keys| keys.jwks.find(kid).cloned())
            .ok_or_else(|| format!("unknown key {kid}"))
    }

    async fn fetch_keys(&self) -> Result<JwkSet, String> {
        let discovery = format!("{}/.well-known/openid-configuration", self.issuer);
        let metadata: Value = self
            .http
            .get(&discovery)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|error| format!("could not load {discovery}: {error}"))?
            .json()
            .await
            .map_err(|error| format!("could not read {discovery}: {error}"))?;
        let jwks_uri = metadata
            .get("jwks_uri")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{discovery} has no jwks_uri"))?;
        let jwks: JwkSet = self
            .http
            .get(jwks_uri)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|error| format!("could not load {jwks_uri}: {error}"))?
            .json()
            .await
            .map_err(|error| format!("could not read {jwks_uri}: {error}"))?;
        tracing::info!(jwks_uri, keys = jwks.keys.len(), "Loaded the keys of {}", self.issuer);
        Ok(jwks)
    }
}

/// Requires a valid access token in the `Authorization` header and leaves its claims on the
/// request; answers 401 with a `WWW-Authenticate` challenge (RFC 6750) otherwise.
pub async fn require_access_token(
    State(tokens): State<Arc<AccessTokens>>,
    mut request: Request,
    next: Next,
) -> Response {
    let bearer = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value
                .get(..7)
                .filter(|scheme| scheme.eq_ignore_ascii_case("bearer "))
                .map(|_| value[7..].trim().to_owned())
        });
    let Some(token) = bearer else {
        return unauthorized(None);
    };
    match tokens.validate(&token).await {
        Ok(access_token) => {
            request.extensions_mut().insert(access_token.claims());
            request.extensions_mut().insert(access_token);
            next.run(request).await
        }
        Err(reason) => {
            tracing::debug!(reason, "Rejecting the access token");
            unauthorized(Some(&reason))
        }
    }
}

fn unauthorized(reason: Option<&str>) -> Response {
    let challenge = match reason {
        Some(reason) => format!(
            r#"Bearer error="invalid_token", error_description="{}""#,
            reason.replace('"', "'")
        ),
        None => "Bearer".to_owned(),
    };
    let challenge = HeaderValue::from_str(&challenge).unwrap_or_else(|_| HeaderValue::from_static("Bearer"));
    (StatusCode::UNAUTHORIZED, [(WWW_AUTHENTICATE, challenge)]).into_response()
}
