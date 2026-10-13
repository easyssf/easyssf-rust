//! The one page of the application.

use crate::oidc::LoggedInUser;

/// The page: who is logged in, the Keycloak session, and the script that checks the session.
pub fn page(user: &LoggedInUser, local_session: &str, account_console: &str, csrf_token: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>SSF example OIDC client</title></head>
<body>
<h1>Hello {username}</h1>
<table>
<tr><td>Subject (sub)</td><td><code>{subject}</code></td></tr>
<tr><td>Keycloak session (sid)</td><td><code>{sid}</code></td></tr>
<tr><td>Local session</td><td><code>{local_session}</code></td></tr>
</table>
<p>Sign out in the <a href="{account_console}" target="_blank">Keycloak account console</a>: Keycloak reports
the revoked session with a security event and the local session is gone. This page checks its
session every few seconds and whenever the tab becomes visible, and sends you to the login
once the session has ended.</p>
<p id="status">Session check: pending</p>
<form method="post" action="/logout">
<input type="hidden" name="_csrf" value="{csrf_token}">
<button type="submit">Log out here (and in Keycloak)</button>
</form>
<script>
(function () {{
    const status = document.getElementById("status");
    let checks = 0;
    function checkSession() {{
        // GET /auth/check answers 200 as long as the local session exists, 401 once it is gone.
        // No call to Keycloak is needed: the receiver ends the local session on the event.
        fetch("/auth/check", {{ headers: {{ "Accept": "application/json" }}, cache: "no-store",
                               credentials: "same-origin", redirect: "manual" }})
            .then(function (response) {{
                if (response.status !== 200) {{
                    status.textContent = "Session check: session ended, redirecting to the login";
                    window.location.reload();
                    return;
                }}
                checks++;
                status.textContent = "Session check " + checks + ": active at "
                        + new Date().toLocaleTimeString();
            }})
            .catch(function () {{
                status.textContent = "Session check: application not reachable";
            }});
    }}
    document.addEventListener("visibilitychange", function () {{
        if (!document.hidden) {{
            checkSession();
        }}
    }});
    setInterval(checkSession, 5000);
    checkSession();
}})();
</script>
</body>
</html>
"#,
        username = escape(user.username.as_deref().unwrap_or("")),
        subject = escape(&user.subject),
        sid = escape(user.sid.as_deref().unwrap_or("")),
        local_session = escape(local_session),
        account_console = escape(account_console),
        csrf_token = escape(csrf_token),
    )
}

/// Escapes text for HTML.
pub fn escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            c => escaped.push(c),
        }
    }
    escaped
}
