//! Standing allowance over HTTP: mocks and disposable data only.

use super::*;
use konsensus_api::pairing::allowance::{AllowanceTerms, STANDING_ALLOWANCE_CAPABILITY};

/// The fixture node, restarted with `[pairing] standing_allowance_v1` as
/// given, and a second app paired through a ticket carrying the owner's
/// default terms.
async fn with_allowance(switch: bool) -> (Fx, String, SigningKey) {
    let mut fx = fixture().await;
    let fingerprint = fx.service.bound_fingerprint();
    fx.service = Arc::new(
        PairingService::open(fx.tmp.path(), fingerprint, true)
            .unwrap()
            .with_owner_console(Box::new(fx.console.clone()))
            .without_stdout_code()
            .with_standing_allowance(switch),
    );
    fx.state = Arc::new(AppState {
        pairing: Some(Arc::clone(&fx.service)),
        ..(*fx.state).clone()
    });
    let key = SigningKey::from_bytes(&[0x61; 32]);
    let terms = AllowanceTerms::owner_defaults(chrono::Utc::now().timestamp());
    let client = fx
        .service
        .create_ticket_remote_pairing_with_allowance(
            "phone",
            &hex::encode(key.verifying_key().to_bytes()),
            &[0x62; 32],
            "ticket",
            Some(&terms),
        )
        .unwrap();
    (fx, client.client_id, key)
}

async fn capabilities(fx: &Fx) -> Vec<Value> {
    let (status, body) = fx
        .call("GET", "/api/v1/status", None, Some(auth_header(&fx.state).trim_start_matches("Bearer ")))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["api_capabilities"].as_array().unwrap().clone()
}

fn used(fx: &Fx, client: &str) -> u64 {
    fx.service
        .snapshot()
        .grants
        .iter()
        .filter(|g| g.client_id == client)
        .filter_map(|g| g.budget.as_ref())
        .map(|b| b.used_msat)
        .sum()
}

#[tokio::test]
async fn the_app_asks_once_and_spends_inside_the_allowance_without_the_owner() {
    let (fx, client, key) = with_allowance(true).await;
    assert!(capabilities(&fx).await.contains(&json!(STANDING_ALLOWANCE_CAPABILITY)));
    let read = fx.token_as(&client, &key).await;
    let (status, op) = fx
        .call(
            "POST",
            "/api/v1/pair/elevation-request",
            Some(json!({"scopes": ["spend"], "budget": {"budget_msat": 2_000_000, "per_call_max_msat": 700_000, "ttl_secs": 86_400}})),
            Some(&read),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{op}");
    assert!(!op["owner_action"].as_str().unwrap().contains("konsensus"), "{op}");
    let (status, body) = fx
        .call("GET", &format!("/api/v1/pair/elevation/{}", op["op_id"].as_str().unwrap()), None, Some(&read))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "granted");
    assert_eq!(body["owner_confirmation_required"], false);
    assert!(fx.service.snapshot().pending_elevations.is_empty());

    let token = fx.token_as(&client, &key).await;
    assert_eq!(fx.keysend(&token, OTHER_LN, 1_000).await.0, StatusCode::OK);
    assert_eq!(used(&fx, &client), 1_000);
    assert_eq!(fx.service.allowance_view(&client).unwrap().remaining_msat, 2_500_000 - 2_000_000);

    // Above the allowance: the owner path, exactly as today.
    let (status, op) = fx
        .call("POST", "/api/v1/pair/elevation-request", Some(json!({"scopes": ["spend"], "budget": {"budget_msat": 2_500_001}})), Some(&read))
        .await;
    assert_eq!(status, StatusCode::OK, "{op}");
    assert!(op["owner_action"].as_str().unwrap().contains("konsensus grant"), "{op}");
    assert_eq!(fx.service.snapshot().pending_elevations.len(), 1);
    // It stays pending until the owner acts, although a window is live.
    let (status, body) = fx
        .call("GET", &format!("/api/v1/pair/elevation/{}", op["op_id"].as_str().unwrap()), None, Some(&read))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "pending", "{body}");
    assert_eq!(body["owner_confirmation_required"], true);
}

#[tokio::test]
async fn a_request_body_cannot_carry_allowance_terms() {
    let (fx, client, key) = with_allowance(true).await;
    let read = fx.token_as(&client, &key).await;
    let before = fx.service.allowance_view(&client).unwrap();
    for body in [
        json!({"scopes": ["spend"], "budget": {"budget_msat": 1_000}, "allowance": {"daily_msat": 9_000_000}}),
        json!({"scopes": ["spend"], "budget": {"budget_msat": 1_000, "daily_msat": 9_000_000}}),
        json!({"scopes": ["spend"], "budget": {"budget_msat": 1_000, "until": 9_999_999_999i64}}),
        json!({"scopes": ["spend"], "budget": {"budget_msat": 1_000, "set_by": "cli"}}),
        json!({"scopes": ["spend"], "budget": {"budget_msat": 1_000, "breakers": {"max_payments_per_minute": 1_000_000}}}),
    ] {
        let (status, response) = fx.call("POST", "/api/v1/pair/elevation-request", Some(body.clone()), Some(&read)).await;
        assert!(status.is_client_error(), "{body} -> {status} {response}");
    }
    assert_eq!(fx.service.allowance_view(&client), Some(before));
    assert!(fx.service.snapshot().grants.iter().all(|g| g.client_id != client));
}

#[tokio::test]
async fn with_the_switch_off_the_same_request_waits_for_the_owner() {
    let (fx, client, key) = with_allowance(false).await;
    assert!(!capabilities(&fx).await.contains(&json!(STANDING_ALLOWANCE_CAPABILITY)));
    assert!(fx.service.allowance_view(&client).is_none());
    let read = fx.token_as(&client, &key).await;
    let (status, op) = fx
        .call(
            "POST",
            "/api/v1/pair/elevation-request",
            Some(json!({"scopes": ["spend"], "budget": {"budget_msat": 2_000_000, "per_call_max_msat": 700_000, "ttl_secs": 86_400}})),
            Some(&read),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{op}");
    assert!(op["owner_action"].as_str().unwrap().contains("konsensus grant"), "{op}");
    let (_, body) = fx
        .call("GET", &format!("/api/v1/pair/elevation/{}", op["op_id"].as_str().unwrap()), None, Some(&read))
        .await;
    assert_eq!(body["status"], "pending");
    let token = fx.token_as(&client, &key).await;
    assert!(!fx.keysend(&token, OTHER_LN, 1_000).await.0.is_success());
    assert_eq!(used(&fx, &client), 0);
}

// ── A live owner window and a new request: the status says what is in force ──

/// The app asks for `budget`; returns the request and its status reply.
async fn ask_with(fx: &Fx, read: &str, budget: Value) -> (Value, Value) {
    let (status, op) = fx
        .call("POST", "/api/v1/pair/elevation-request", Some(json!({"scopes": ["spend"], "budget": budget})), Some(read))
        .await;
    assert_eq!(status, StatusCode::OK, "{op}");
    let (status, body) = fx
        .call("GET", &format!("/api/v1/pair/elevation/{}", op["op_id"].as_str().unwrap()), None, Some(read))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    (op, body)
}

/// [`ask_with`], then withdraw the request so the next one has room: a
/// pairing may hold only a few pending requests at once. Returns the status.
async fn status_of(fx: &Fx, read: &str, budget: Value) -> Value {
    let (op, body) = ask_with(fx, read, budget).await;
    let (status, gone) = fx
        .call("DELETE", &format!("/api/v1/pair/elevation/{}", op["op_id"].as_str().unwrap()), None, Some(read))
        .await;
    assert!(status.is_success(), "{gone}");
    body
}

fn owner_window(fx: &Fx, client: &str) -> pairing::SpendGrant {
    let grants: Vec<_> = fx
        .service
        .snapshot()
        .grants
        .into_iter()
        .filter(|g| g.client_id == client && g.is_live(chrono::Utc::now().timestamp()))
        .collect();
    assert_eq!(grants.len(), 1, "{grants:?}");
    assert_eq!(grants[0].granted_by, "cli");
    grants.into_iter().next().unwrap()
}

#[tokio::test]
async fn a_live_owner_window_that_covers_the_request_reads_granted() {
    for switch in [true, false] {
        let (fx, client, key) = with_allowance(switch).await;
        fx.grant_as(&client, &key, None, GrantTerms::new(2_000_000).per_call(700_000)).await;
        let before = owner_window(&fx, &client);
        let read = fx.token_as(&client, &key).await;
        let (op, body) =
            ask_with(&fx, &read, json!({"budget_msat": 1_000_000, "per_call_max_msat": 500_000, "ttl_secs": 3_600})).await;
        assert_eq!(body["status"], "granted", "switch {switch}: {body}");
        assert_eq!(body["owner_confirmation_required"], false, "switch {switch}");
        // Nothing was opened or replaced: the owner's window is what is in force.
        assert_eq!(owner_window(&fx, &client), before, "switch {switch}");
        assert!(op["owner_action"].as_str().unwrap().contains("konsensus grant"), "switch {switch}: {op}");
    }
}

#[tokio::test]
async fn a_live_owner_window_smaller_than_the_request_does_not_read_granted() {
    for switch in [true, false] {
        let (fx, client, key) = with_allowance(switch).await;
        fx.grant_as(&client, &key, None, GrantTerms::new(300_000).per_call(200_000).for_secs(1_800)).await;
        let before = owner_window(&fx, &client);
        let read = fx.token_as(&client, &key).await;
        // Inside the allowance, but more than the owner's window allows.
        let (op, body) =
            ask_with(&fx, &read, json!({"budget_msat": 1_000_000, "per_call_max_msat": 700_000, "ttl_secs": 3_600})).await;
        assert_eq!(body["status"], "pending", "switch {switch}: {body}");
        assert_eq!(body["owner_confirmation_required"], true, "switch {switch}");
        assert!(op["owner_action"].as_str().unwrap().contains("konsensus grant"), "switch {switch}: {op}");
        assert!(!op["owner_action"].as_str().unwrap().starts_with("none"), "switch {switch}: {op}");
        assert_eq!(owner_window(&fx, &client), before, "switch {switch}");
        let pending = fx.service.snapshot().pending_elevations;
        assert!(pending.iter().any(|e| Some(e.op_id.as_str()) == op["op_id"].as_str()), "switch {switch}");

        // Each term counts on its own: a larger per-call limit, a longer
        // window or a larger budget is not in force either. Each case asks for
        // more than the window on exactly one term; the control below asks
        // for the same within every term and reads granted.
        let body =
            status_of(&fx, &read, json!({"budget_msat": 250_000, "per_call_max_msat": 200_000, "ttl_secs": 1_200})).await;
        assert_eq!(body["status"], "granted", "switch {switch}: {body}");
        for budget in [
            json!({"budget_msat": 250_000, "per_call_max_msat": 250_000, "ttl_secs": 1_200}),
            json!({"budget_msat": 100_000, "per_call_max_msat": 100_000, "ttl_secs": 86_400}),
            json!({"budget_msat": 400_000, "per_call_max_msat": 100_000, "ttl_secs": 1_200}),
        ] {
            let body = status_of(&fx, &read, budget.clone()).await;
            assert_eq!(body["status"], "pending", "switch {switch}: {budget} -> {body}");
            assert_eq!(body["owner_confirmation_required"], true, "switch {switch}: {budget}");
        }
        assert_eq!(owner_window(&fx, &client), before, "switch {switch}");
    }
}

#[tokio::test]
async fn a_request_the_owner_window_did_not_cover_reads_granted_once_the_owner_approves_it() {
    let (fx, client, key) = with_allowance(true).await;
    fx.grant_as(&client, &key, None, GrantTerms::new(300_000).per_call(200_000).for_secs(1_800)).await;
    let read = fx.token_as(&client, &key).await;
    let (op, body) =
        ask_with(&fx, &read, json!({"budget_msat": 1_000_000, "per_call_max_msat": 700_000, "ttl_secs": 3_600})).await;
    assert_eq!(body["status"], "pending", "{body}");
    let op_id = op["op_id"].as_str().unwrap().to_string();
    let pending = fx.service.snapshot().pending_elevations.into_iter().find(|e| e.op_id == op_id).unwrap();
    let phrase = fx.console.confirmation(&pairing::grant_confirmation_phrase(&pending));
    let resp = control::handle(
        &fx.control(),
        ControlRequest::Grant {
            op_id: op_id.clone(),
            confirmation: phrase,
            terms: GrantTerms::new(1_000_000).per_call(700_000).for_secs(3_600),
        },
    );
    assert!(matches!(resp, ControlResponse::Ok { .. }), "{resp:?}");
    let (_, body) = fx.call("GET", &format!("/api/v1/pair/elevation/{op_id}"), None, Some(&read)).await;
    assert_eq!(body["status"], "granted", "{body}");
    assert_eq!(body["owner_confirmation_required"], false);
    assert_eq!(owner_window(&fx, &client).op_id, op_id);
}
