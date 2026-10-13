//! The router of a configured receiver and the tower-sessions hook.

use axum::body::Body;
use easyssf_receiver::SsfReceiver;
use easyssf_receiver::config::SsfReceiverConfig;
use easyssf_receiver_axum::push_router_for;
use easyssf_test::TestTransmitter;
use easyssf_test::subjects::iss_sub;
use http::{Request, StatusCode};
use tower::ServiceExt;

fn config(transmitter: &TestTransmitter) -> SsfReceiverConfig {
    toml::from_str(&format!(
        r#"
        transmitter-issuer = "{}"
        expected-audience = "{}"
        [push]
        endpoint-path = "/events/ssf"
        expected-auth-header = "Bearer s3cr3t"
        "#,
        transmitter.issuer(),
        TestTransmitter::AUDIENCE
    ))
    .unwrap()
}

#[tokio::test]
async fn push_router_mounts_the_endpoint_at_the_configured_path() {
    let transmitter = TestTransmitter::new();
    let receiver = SsfReceiver::builder(config(&transmitter))
        .http_client(transmitter.clone())
        .build()
        .unwrap();
    let app = push_router_for(&receiver);
    let set = transmitter.set("CaepSessionRevoked", Some(iss_sub(transmitter.issuer(), "alice")));
    let request = Request::post("/events/ssf")
        .header("authorization", "Bearer s3cr3t")
        .body(Body::from(set.clone()))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(request).await.unwrap().status(),
        StatusCode::ACCEPTED
    );
    let request = Request::post("/ssf/push")
        .header("authorization", "Bearer s3cr3t")
        .body(Body::from(set))
        .unwrap();
    assert_eq!(app.oneshot(request).await.unwrap().status(), StatusCode::NOT_FOUND);
}

/// The tower-sessions hook, feature `tower-sessions`.
#[cfg(feature = "tower-sessions")]
#[tokio::test]
async fn revoked_session_is_flushed_on_its_next_request() {
    use axum::Router;
    use axum::routing::get;
    use easyssf_receiver_axum::sessions::{SsfSessionLogin, SsfSessionRevocationLayer, login, record_login};
    use easyssf_test::subjects::{complex, opaque};
    use tower_sessions::{MemoryStore, Session, SessionManagerLayer};

    let transmitter = TestTransmitter::new();
    let receiver = SsfReceiver::builder(config(&transmitter))
        .http_client(transmitter.clone())
        .build()
        .unwrap();
    let issuer = transmitter.issuer().to_owned();
    let app = Router::new()
        .route(
            "/login/{sid}",
            get(
                move |session: Session, axum::extract::Path(sid): axum::extract::Path<String>| {
                    let issuer = issuer.clone();
                    async move {
                        record_login(&session, &SsfSessionLogin::new(issuer, Some("alice"), Some(&sid)))
                            .await
                            .unwrap();
                        "logged in"
                    }
                },
            ),
        )
        .route(
            "/me",
            get(|session: Session| async move {
                match login(&session).await.unwrap() {
                    Some(login) => (StatusCode::OK, login.subject.unwrap_or_default()),
                    None => (StatusCode::UNAUTHORIZED, String::new()),
                }
            }),
        )
        .layer(SsfSessionRevocationLayer::new(receiver.token_revocation_store()))
        .layer(SessionManagerLayer::new(MemoryStore::default()).with_secure(false))
        .merge(push_router_for(&receiver));

    let login_response = app
        .clone()
        .oneshot(Request::get("/login/session-1").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let cookie = login_response.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let me = |cookie: String| {
        let app = app.clone();
        async move {
            app.oneshot(
                Request::get("/me")
                    .header("cookie", cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
        }
    };
    assert_eq!(me(cookie.clone()).await, StatusCode::OK);

    // the transmitter revokes another session: nothing happens
    let other = transmitter.set(
        "CaepSessionRevoked",
        Some(complex(
            Some(iss_sub(transmitter.issuer(), "alice")),
            Some(opaque("session-2")),
        )),
    );
    let request = Request::post("/events/ssf")
        .header("authorization", "Bearer s3cr3t")
        .body(Body::from(other))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(request).await.unwrap().status(),
        StatusCode::ACCEPTED
    );
    assert_eq!(me(cookie.clone()).await, StatusCode::OK);

    // then the session of the login
    let set = transmitter.set(
        "CaepSessionRevoked",
        Some(complex(
            Some(iss_sub(transmitter.issuer(), "alice")),
            Some(opaque("session-1")),
        )),
    );
    let request = Request::post("/events/ssf")
        .header("authorization", "Bearer s3cr3t")
        .body(Body::from(set))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(request).await.unwrap().status(),
        StatusCode::ACCEPTED
    );
    assert_eq!(me(cookie.clone()).await, StatusCode::UNAUTHORIZED);
    assert_eq!(
        me(cookie).await,
        StatusCode::UNAUTHORIZED,
        "flushed, not only rejected once"
    );
}
