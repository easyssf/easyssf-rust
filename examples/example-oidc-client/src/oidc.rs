//! The login with Keycloak: OpenID Connect discovery, the authorization code flow with PKCE and
//! the validation of the ID token, on `openidconnect`. Spring Security does this for the Java
//! example, the OpenIdConnect handler for the .NET one.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use easyssf_receiver::BoxError;
use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreIdToken};
use openidconnect::reqwest;
use openidconnect::{
    AccessTokenHash, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndSessionUrl, EndpointMaybeSet,
    EndpointNotSet, EndpointSet, IssuerUrl, LogoutRequest, Nonce, OAuth2TokenResponse, PkceCodeChallenge,
    PkceCodeVerifier, PostLogoutRedirectUrl, ProviderMetadataWithLogout, RedirectUrl, Scope, TokenResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::OnceCell;
use tower_sessions::Session;
use url::Url;

/// The `keycloak` section of the configuration.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct OidcConfig {
    /// The issuer, the realm of Keycloak.
    pub issuer: String,
    /// The client of this application in the realm.
    pub client_id: String,
    /// Its secret.
    pub client_secret: String,
    /// The scopes of the login.
    pub scopes: Vec<String>,
}

impl Default for OidcConfig {
    fn default() -> Self {
        Self {
            issuer: "http://localhost:8080/realms/ssf-demo".to_owned(),
            client_id: "example-oidc-client".to_owned(),
            client_secret: "example-oidc-client-secret".to_owned(),
            scopes: vec!["openid".to_owned(), "profile".to_owned(), "email".to_owned()],
        }
    }
}

/// The user of a local session: the claims of the ID token the page and the revocation check
/// use, and the ID token itself for the logout.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggedInUser {
    /// `preferred_username`.
    pub username: Option<String>,
    /// `sub`.
    pub subject: String,
    /// `sid`, the Keycloak session.
    pub sid: Option<String>,
    /// `iss`.
    pub issuer: String,
    /// The ID token, sent as `id_token_hint` with the logout.
    pub id_token: String,
}

/// The query of the redirect URI.
#[derive(Debug, Deserialize)]
pub struct CallbackParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

/// What a login in progress keeps in the session.
#[derive(Debug, Serialize, Deserialize)]
struct PendingLogin {
    state: String,
    nonce: String,
    pkce_verifier: String,
}

const PENDING_KEY: &str = "oidc.pending";

type Client =
    CoreClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointMaybeSet, EndpointMaybeSet>;

struct Provider {
    client: Client,
    end_session_endpoint: Option<EndSessionUrl>,
}

/// The relying party. Discovery runs on the first login, not at startup, so that the application
/// starts without Keycloak.
pub struct Oidc {
    config: OidcConfig,
    redirect_uri: Url,
    http: reqwest::Client,
    provider: OnceCell<Provider>,
}

impl Oidc {
    /// A relying party for the client of `config` with `redirect_uri` as its redirect URI.
    pub fn new(config: OidcConfig, redirect_uri: Url) -> Self {
        Self {
            config,
            redirect_uri,
            // following redirects would let an authorization server send the client elsewhere
            http: reqwest::ClientBuilder::new()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("HTTP client"),
            provider: OnceCell::new(),
        }
    }

    async fn provider(&self) -> Result<&Provider, BoxError> {
        self.provider
            .get_or_try_init(|| async {
                let issuer = IssuerUrl::new(self.config.issuer.clone())?;
                let metadata = ProviderMetadataWithLogout::discover_async(issuer, &self.http).await?;
                let end_session_endpoint = metadata.additional_metadata().end_session_endpoint.clone();
                let client = CoreClient::from_provider_metadata(
                    metadata,
                    ClientId::new(self.config.client_id.clone()),
                    Some(ClientSecret::new(self.config.client_secret.clone())),
                )
                .set_redirect_uri(RedirectUrl::from_url(self.redirect_uri.clone()));
                tracing::info!(issuer = self.config.issuer, "Discovered the OpenID provider");
                Ok(Provider {
                    client,
                    end_session_endpoint,
                })
            })
            .await
    }

    /// The authorization URL of a new login; state, nonce and PKCE verifier go into the session.
    pub async fn start_login(&self, session: &Session) -> Result<Url, BoxError> {
        let provider = self.provider().await?;
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let mut request = provider
            .client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .set_pkce_challenge(pkce_challenge);
        for scope in &self.config.scopes {
            if scope != "openid" {
                request = request.add_scope(Scope::new(scope.clone()));
            }
        }
        let (url, state, nonce) = request.url();
        let pending = PendingLogin {
            state: state.secret().clone(),
            nonce: nonce.secret().clone(),
            pkce_verifier: pkce_verifier.secret().clone(),
        };
        session.insert(PENDING_KEY, &pending).await?;
        Ok(url)
    }

    /// Finishes the login the redirect URI was called for: checks the state, exchanges the code
    /// and validates the ID token against the nonce.
    pub async fn finish_login(&self, session: &Session, params: CallbackParams) -> Result<LoggedInUser, BoxError> {
        let pending: PendingLogin = session
            .remove(PENDING_KEY)
            .await?
            .ok_or("no login in progress for this session")?;
        if let Some(error) = params.error {
            return Err(format!("[{error}] {}", params.error_description.unwrap_or_default()).into());
        }
        if params.state.as_deref() != Some(pending.state.as_str()) {
            return Err("the state of the response does not match the login".into());
        }
        let code = params.code.ok_or("the response carries no code")?;
        let provider = self.provider().await?;
        let tokens = provider
            .client
            .exchange_code(AuthorizationCode::new(code))?
            .set_pkce_verifier(PkceCodeVerifier::new(pending.pkce_verifier))
            .request_async(&self.http)
            .await?;
        let id_token = tokens.id_token().ok_or("the token response carries no ID token")?;
        let verifier = provider.client.id_token_verifier();
        let claims = id_token.claims(&verifier, &Nonce::new(pending.nonce))?;
        if let Some(expected) = claims.access_token_hash() {
            let actual = AccessTokenHash::from_token(
                tokens.access_token(),
                id_token.signing_alg()?,
                id_token.signing_key(&verifier)?,
            )?;
            if actual != *expected {
                return Err("the access token hash of the ID token does not match".into());
            }
        }
        Ok(LoggedInUser {
            username: claims.preferred_username().map(|name| name.as_str().to_owned()),
            subject: claims.subject().as_str().to_owned(),
            // `sid` (OpenID Connect Front-Channel Logout 1.0, section 3) is not a standard claim
            // of openidconnect; read it from the payload of the verified token
            sid: unverified_claim(id_token, "sid"),
            issuer: claims.issuer().as_str().to_owned(),
            id_token: id_token.to_string(),
        })
    }

    /// The URL of the end session endpoint for the user, with the ID token as hint so that Keycloak
    /// logs out without asking, and the base URL as post-logout redirect URI; `None` when the
    /// provider has no end session endpoint.
    pub async fn logout_url(&self, user: &LoggedInUser, base_url: &Url) -> Result<Option<Url>, BoxError> {
        let provider = self.provider().await?;
        let Some(end_session_endpoint) = provider.end_session_endpoint.clone() else {
            return Ok(None);
        };
        let id_token: CoreIdToken = user.id_token.parse()?;
        let url = LogoutRequest::from(end_session_endpoint)
            .set_id_token_hint(&id_token)
            .set_post_logout_redirect_uri(PostLogoutRedirectUrl::from_url(base_url.join("/")?))
            .http_get_url();
        Ok(Some(url))
    }
}

/// A string claim of the payload of a JWS whose signature was verified before.
fn unverified_claim(id_token: &CoreIdToken, claim: &str) -> Option<String> {
    let token = id_token.to_string();
    let payload = token.split('.').nth(1)?;
    let payload = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let claims: Value = serde_json::from_slice(&payload).ok()?;
    claims.get(claim)?.as_str().map(str::to_owned)
}
