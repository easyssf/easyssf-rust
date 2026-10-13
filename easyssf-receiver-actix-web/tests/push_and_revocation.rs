//! The push endpoint and the revocation middleware, end to end through an actix-web app.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::SystemTime;

use actix_web::dev::{Service, ServiceRequest, ServiceResponse};
use actix_web::http::StatusCode;
use actix_web::{App, HttpMessage, HttpRequest, test, web};
use easyssf_receiver::SsfReceiver;
use easyssf_receiver::config::SsfReceiverConfig;
use easyssf_receiver::event::{SsfEventContext, for_event};
use easyssf_receiver::push::SsfPushHandler;
use easyssf_receiver::revocation::SsfTokenClaims;
use easyssf_receiver_actix_web::{SsfRevocation, configure_push, configure_push_for};
use easyssf_test::TestTransmitter;
use easyssf_test::subjects::{complex, iss_sub, opaque};
use serde_json::Value;

const SECRET: &str = "Bearer s3cr3t";

fn config(transmitter: &TestTransmitter) -> SsfReceiverConfig {
    toml::from_str(&format!(
        r#"
        transmitter-issuer = "{}"
        expected-audience = "{}"
        [push]
        expected-auth-header = "{SECRET}"
        "#,
        transmitter.issuer(),
        TestTransmitter::AUDIENCE
    ))
    .unwrap()
}

fn receiver(transmitter: &TestTransmitter, handled: Arc<AtomicUsize>) -> Arc<SsfReceiver> {
    let receiver = SsfReceiver::builder(config(transmitter))
        .http_client(transmitter.clone())
        .handler(for_event("CaepSessionRevoked", move |_: SsfEventContext| {
            let handled = handled.clone();
            async move {
                handled.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }))
        .build()
        .unwrap();
    Arc::new(receiver)
}

/// Stands in for the JWT middleware of the application: claims arrive in the `x-sid` header.
async fn fake_authentication(
    request: ServiceRequest,
    next: actix_web::middleware::Next<impl actix_web::body::MessageBody>,
) -> Result<ServiceResponse<impl actix_web::body::MessageBody>, actix_web::Error> {
    if let Some(sid) = request
        .headers()
        .get("x-sid")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
    {
        request.extensions_mut().insert(SsfTokenClaims {
            issuer: Some("https://transmitter.example/realms/test".to_owned()),
            subject: Some("alice".to_owned()),
            session_id: Some(sid),
            issued_at: Some(SystemTime::now()),
        });
    }
    next.call(request).await
}

fn session_revoked(transmitter: &TestTransmitter, sub: &str, session: &str) -> String {
    transmitter.set(
        "CaepSessionRevoked",
        Some(complex(Some(iss_sub(transmitter.issuer(), sub)), Some(opaque(session)))),
    )
}

#[actix_web::test]
async fn accepts_set_hands_it_to_handlers_once_and_revokes_the_session() {
    let transmitter = TestTransmitter::new();
    let handled = Arc::new(AtomicUsize::new(0));
    let receiver = receiver(&transmitter, handled.clone());
    let app = test::init_service(
        App::new().configure(configure_push_for(&receiver)).service(
            web::scope("/api")
                .wrap(SsfRevocation::new(
                    receiver.token_revocation_store(),
                    |request: &HttpRequest| request.extensions().get::<SsfTokenClaims>().cloned(),
                ))
                .wrap(actix_web::middleware::from_fn(fake_authentication))
                .route("", web::get().to(|| async { "ok" })),
        ),
    )
    .await;
    let api = |sid: &str| {
        test::TestRequest::get()
            .uri("/api")
            .insert_header(("x-sid", sid))
            .to_request()
    };
    assert_eq!(
        test::call_service(&app, api("session-1")).await.status(),
        StatusCode::OK
    );

    let set = session_revoked(&transmitter, "alice", "session-1");
    let push = |authorization: Option<&str>, body: String| {
        let mut request = test::TestRequest::post().uri("/ssf/push");
        if let Some(authorization) = authorization {
            request = request.insert_header(("authorization", authorization));
        }
        request.set_payload(body).to_request()
    };
    assert_eq!(
        test::call_service(&app, push(None, set.clone())).await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        test::call_service(&app, push(Some(SECRET), set.clone())).await.status(),
        StatusCode::ACCEPTED
    );
    assert_eq!(handled.load(Ordering::SeqCst), 1);
    // a redelivery is acknowledged and not handled again
    assert_eq!(
        test::call_service(&app, push(Some(SECRET), set)).await.status(),
        StatusCode::ACCEPTED
    );
    assert_eq!(handled.load(Ordering::SeqCst), 1);

    let response = test::call_service(&app, api("session-1")).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(
        response
            .headers()
            .get("www-authenticate")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("invalid_token")
    );
    assert_eq!(
        test::call_service(&app, api("session-2")).await.status(),
        StatusCode::OK
    );
    // anonymous requests pass
    assert_eq!(
        test::call_service(&app, test::TestRequest::get().uri("/api").to_request())
            .await
            .status(),
        StatusCode::OK
    );
}

#[actix_web::test]
async fn rejects_invalid_sets_with_an_error_document_and_oversized_bodies() {
    let transmitter = TestTransmitter::new();
    let receiver = receiver(&transmitter, Arc::new(AtomicUsize::new(0)));
    let app = test::init_service(App::new().configure(configure_push(receiver.push_handler()))).await;
    let mut claims = transmitter.set_claims("CaepSessionRevoked", Some(iss_sub(transmitter.issuer(), "alice")));
    claims.insert("aud".to_owned(), Value::String("https://other.example".to_owned()));
    let request = test::TestRequest::post()
        .uri("/ssf/push")
        .insert_header(("authorization", SECRET))
        .set_payload(transmitter.sign_set(&claims))
        .to_request();
    let response = test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response.headers().get("content-type").unwrap(), "application/json");
    assert_eq!(response.headers().get("content-language").unwrap(), "en");
    let body: Value = test::read_body_json(response).await;
    assert_eq!(body["err"], "invalid_audience");

    let request = test::TestRequest::post()
        .uri("/ssf/push")
        .insert_header(("authorization", SECRET))
        .set_payload("a".repeat(SsfPushHandler::MAX_SET_SIZE + 1))
        .to_request();
    let response = app.call(request).await;
    let status = match response {
        Ok(response) => response.status(),
        Err(error) => error.as_response_error().status_code(),
    };
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}

/// The actix-session hook, feature `actix-session`.
#[cfg(feature = "actix-session")]
#[actix_web::test]
async fn revoked_session_is_purged_on_its_next_request() {
    use actix_web::HttpResponse;
    use actix_web::cookie::Key;
    use easyssf_receiver_actix_web::sessions::{SsfSessionLogin, SsfSessionRevocation, login, record_login};

    let transmitter = TestTransmitter::new();
    let receiver = receiver(&transmitter, Arc::new(AtomicUsize::new(0)));
    let issuer = transmitter.issuer().to_owned();
    let app = test::init_service(
        App::new().configure(configure_push_for(&receiver)).service(
            web::scope("")
                .wrap(SsfSessionRevocation::new(receiver.token_revocation_store()))
                .wrap(
                    actix_session::SessionMiddleware::builder(
                        actix_session::storage::CookieSessionStore::default(),
                        Key::from(&[7u8; 64]),
                    )
                    .cookie_secure(false)
                    .build(),
                )
                .route(
                    "/login/{sid}",
                    web::get().to(move |session: actix_session::Session, sid: web::Path<String>| {
                        let issuer = issuer.clone();
                        async move {
                            record_login(&session, &SsfSessionLogin::new(issuer, Some("alice"), Some(&sid))).unwrap();
                            HttpResponse::Ok().finish()
                        }
                    }),
                )
                .route(
                    "/me",
                    web::get().to(|session: actix_session::Session| async move {
                        match login(&session).unwrap() {
                            Some(login) => HttpResponse::Ok().body(login.subject.unwrap_or_default()),
                            None => HttpResponse::Unauthorized().finish(),
                        }
                    }),
                ),
        ),
    )
    .await;
    let login_response = test::call_service(&app, test::TestRequest::get().uri("/login/session-1").to_request()).await;
    let cookie = login_response
        .response()
        .cookies()
        .next()
        .expect("a session cookie")
        .into_owned();
    let me =
        |cookie: actix_web::cookie::Cookie<'static>| test::TestRequest::get().uri("/me").cookie(cookie).to_request();
    assert_eq!(
        test::call_service(&app, me(cookie.clone())).await.status(),
        StatusCode::OK
    );

    let set = session_revoked(&transmitter, "alice", "session-1");
    let request = test::TestRequest::post()
        .uri("/ssf/push")
        .insert_header(("authorization", SECRET))
        .set_payload(set)
        .to_request();
    assert_eq!(test::call_service(&app, request).await.status(), StatusCode::ACCEPTED);
    let response = test::call_service(&app, me(cookie.clone())).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    // the cookie session is purged: the response removes the cookie
    let removed = response
        .response()
        .cookies()
        .any(|c| c.value().is_empty() || c.max_age().is_some_and(|age| age.is_zero()));
    assert!(removed, "the session cookie was removed");
}
