//! Standing allowance over HTTP: mocks and disposable data only.

use super::*;
use konsensus_api::pairing::allowance::{AllowanceTerms, ALLOWANCE_GRANTED_BY, MAX_LEDGER_WINDOWS, STANDING_ALLOWANCE_CAPABILITY};

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

/// Every status in `cases` (request budget, expected status), each request
/// withdrawn after it is read.
async fn expect_statuses(fx: &Fx, read: &str, label: &str, cases: Vec<(Value, &str)>) {
    for (budget, expected) in cases {
        let body = status_of(fx, read, budget.clone()).await;
        assert_eq!(body["status"], expected, "{label}: {budget} -> {body}");
        assert_eq!(body["owner_confirmation_required"], expected == "pending", "{label}: {budget}");
    }
}

#[tokio::test]
async fn a_live_owner_window_with_narrower_terms_does_not_read_granted() {
    for switch in [true, false] {
        // Budget, per-call limit and duration all cover every request below;
        // only the narrower term differs. The first case of each window is
        // the control: the same request within that term reads granted.
        let wide = json!({"budget_msat": 1_000_000, "per_call_max_msat": 500_000, "ttl_secs": 3_600});
        let with = |extra: Value| {
            let mut budget = wide.clone();
            budget.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
            budget
        };

        // Payee allowlist: a window held to one payee does not answer a
        // request for any payee, or for a payee outside it.
        let (fx, client, key) = with_allowance(switch).await;
        let mut terms = GrantTerms::new(2_000_000).per_call(700_000);
        terms.payee_allowlist = Some([OTHER_LN.to_string()].into());
        fx.grant_as(&client, &key, None, terms).await;
        let before = owner_window(&fx, &client);
        let read = fx.token_as(&client, &key).await;
        expect_statuses(&fx, &read, &format!("payees, switch {switch}"), vec![
            (with(json!({"payee_allowlist": [OTHER_LN]})), "granted"),
            (wide.clone(), "pending"),
            (with(json!({"payee_allowlist": [PEER_LN]})), "pending"),
            (with(json!({"payee_allowlist": [OTHER_LN, PEER_LN]})), "pending"),
        ])
        .await;
        assert_eq!(owner_window(&fx, &client), before, "switch {switch}");

        // Per-recipient budget: a window that holds one recipient to less
        // than the request may pay it does not answer the request.
        let (fx, client, key) = with_allowance(switch).await;
        fx.grant_as(&client, &key, None, GrantTerms::new(2_000_000).per_call(700_000).recipient(OTHER_LN, 100_000)).await;
        let before = owner_window(&fx, &client);
        let read = fx.token_as(&client, &key).await;
        expect_statuses(&fx, &read, &format!("per recipient, switch {switch}"), vec![
            (with(json!({"per_recipient_msat": {OTHER_LN: 100_000}})), "granted"),
            (wide.clone(), "pending"),
            (with(json!({"per_recipient_msat": {OTHER_LN: 150_000}})), "pending"),
            // A request that cannot pay the capped recipient is not held to its cap.
            (with(json!({"payee_allowlist": [PEER_LN]})), "granted"),
            (with(json!({"payee_allowlist": [PEER_LN, OTHER_LN]})), "pending"),
        ])
        .await;
        assert_eq!(owner_window(&fx, &client), before, "switch {switch}");

        // Liquidity fees: a window without them does not answer a request
        // that asks for them.
        let (fx, client, key) = with_allowance(switch).await;
        fx.grant_as(&client, &key, None, GrantTerms::new(2_000_000).per_call(700_000)).await;
        let before = owner_window(&fx, &client);
        let read = fx.token_as(&client, &key).await;
        expect_statuses(&fx, &read, &format!("liquidity fees, switch {switch}"), vec![
            (wide.clone(), "granted"),
            (with(json!({"allow_liquidity_fees": true})), "pending"),
        ])
        .await;
        assert_eq!(owner_window(&fx, &client), before, "switch {switch}");
    }
}

#[tokio::test]
async fn a_relation_grant_does_not_read_as_granted_for_a_spend_request() {
    // A relation grant pays only recipients with a live envelope. Its total,
    // per-call limit, duration and the envelope's own budget all cover this
    // request; it still does not answer it.
    let (fx, _, _) = super::messaging_cap::approved_grant(fixture().await, true, 6_000, None).await;
    let window = fx.service.snapshot().grants.into_iter().find(|g| g.client_id == fx.client_id).unwrap();
    assert!(window.budget.as_ref().unwrap().recipients_only, "{window:?}");
    let read = fx.token().await;
    let (op, body) = ask_with(&fx, &read, json!({"budget_msat": 5_000, "per_call_max_msat": 5_000, "ttl_secs": 600})).await;
    assert_eq!(body["status"], "pending", "{body}");
    assert_eq!(body["owner_confirmation_required"], true);
    assert!(op["owner_action"].as_str().unwrap().contains("konsensus grant"), "{op}");

    // Nor does it answer a spend request without a budget: that asks for
    // general spend, and the relation grant pays only its recipients.
    let (status, op) =
        fx.call("POST", "/api/v1/pair/elevation-request", Some(json!({"scopes": ["spend"]})), Some(&read)).await;
    assert_eq!(status, StatusCode::OK, "{op}");
    let (status, body) =
        fx.call("GET", &format!("/api/v1/pair/elevation/{}", op["op_id"].as_str().unwrap()), None, Some(&read)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "pending", "a no-budget spend request read as granted over a relation grant: {body}");
    assert_eq!(body["owner_confirmation_required"], true, "{body}");
}

#[tokio::test]
async fn what_is_left_of_a_live_owner_window_bounds_what_reads_granted() {
    for switch in [true, false] {
        let (fx, client, key) = with_allowance(switch).await;
        let token = fx.grant_as(&client, &key, None, GrantTerms::new(300_000)).await;
        let read = fx.token_as(&client, &key).await;
        let ask = |budget_msat: u64| json!({"budget_msat": budget_msat, "per_call_max_msat": 1_000, "ttl_secs": 3_600});
        expect_statuses(&fx, &read, &format!("unspent, switch {switch}"), vec![(ask(250_000), "granted")]).await;

        assert_eq!(fx.keysend(&token, OTHER_LN, 200_000).await.0, StatusCode::OK);
        let spent = used(&fx, &client);
        assert!(spent >= 200_000, "switch {switch}: {spent}");
        let left = 300_000 - spent;
        assert_eq!(owner_window(&fx, &client).budget.unwrap().remaining_msat(), left, "switch {switch}");
        expect_statuses(&fx, &read, &format!("partly spent, switch {switch}"), vec![
            (ask(left), "granted"),
            (ask(left + 1), "pending"),
            (ask(250_000), "pending"),
        ])
        .await;
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

// ── Exact edges of "covers": what reads granted, and one step past it ──

/// The app files `request` as the whole body; returns its status reply and
/// the second the node filed it, then withdraws it.
async fn filed(fx: &Fx, read: &str, request: Value) -> (Value, i64) {
    let (status, op) = fx.call("POST", "/api/v1/pair/elevation-request", Some(request.clone()), Some(read)).await;
    assert_eq!(status, StatusCode::OK, "{request} -> {op}");
    let op_id = op["op_id"].as_str().unwrap().to_string();
    let created_at = fx.service.snapshot().pending_elevations.iter().find(|e| e.op_id == op_id).unwrap().created_at;
    let (status, body) = fx.call("GET", &format!("/api/v1/pair/elevation/{op_id}"), None, Some(read)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, gone) = fx.call("DELETE", &format!("/api/v1/pair/elevation/{op_id}"), None, Some(read)).await;
    assert!(status.is_success(), "{gone}");
    (body, created_at)
}

#[tokio::test]
async fn a_live_general_owner_window_answers_a_spend_request_without_a_budget() {
    for switch in [true, false] {
        let plain = GrantTerms::new(2_000_000).per_call(700_000);
        let mut payees = plain.clone();
        payees.payee_allowlist = Some([OTHER_LN.to_string()].into());
        let capped = plain.clone().recipient(OTHER_LN, 100_000);
        for (label, terms) in [("plain", plain), ("payee allowlist", payees), ("recipient cap", capped)] {
            let (fx, client, key) = with_allowance(switch).await;
            fx.grant_as(&client, &key, None, terms).await;
            let before = owner_window(&fx, &client);
            assert!(!before.budget.as_ref().unwrap().recipients_only, "{label}");
            let read = fx.token_as(&client, &key).await;
            for request in [json!({"scopes": ["spend"]}), json!({"scopes": ["spend"], "budget": null})] {
                let (body, _) = filed(&fx, &read, request.clone()).await;
                assert_eq!(body["status"], "granted", "{label}, switch {switch}: {request} -> {body}");
                assert_eq!(body["owner_confirmation_required"], false, "{label}, switch {switch}: {request}");
            }
            assert_eq!(owner_window(&fx, &client), before, "{label}, switch {switch}");
        }
    }
}

#[tokio::test]
async fn a_relation_grant_does_not_answer_a_request_with_a_null_budget() {
    let (fx, _, _) = super::messaging_cap::approved_grant(fixture().await, true, 6_000, None).await;
    let window = fx.service.snapshot().grants.into_iter().find(|g| g.client_id == fx.client_id).unwrap();
    assert!(window.budget.as_ref().unwrap().recipients_only, "{window:?}");
    let read = fx.token().await;
    let (body, _) = filed(&fx, &read, json!({"scopes": ["spend"], "budget": null})).await;
    assert_eq!(body["status"], "pending", "{body}");
    assert_eq!(body["owner_confirmation_required"], true, "{body}");
}

#[tokio::test]
async fn the_owner_window_covers_a_request_up_to_each_term_exactly() {
    for switch in [true, false] {
        let (fx, client, key) = with_allowance(switch).await;
        fx.grant_as(&client, &key, None, GrantTerms::new(300_000).per_call(200_000).for_secs(1_800)).await;
        let expires_at = owner_window(&fx, &client).expires_at;
        let read = fx.token_as(&client, &key).await;

        // Budget and per-call limit: equal is covered, one msat more is not.
        expect_statuses(&fx, &read, &format!("budget and per call, switch {switch}"), vec![
            (json!({"budget_msat": 300_000, "per_call_max_msat": 1_000, "ttl_secs": 600}), "granted"),
            (json!({"budget_msat": 300_001, "per_call_max_msat": 1_000, "ttl_secs": 600}), "pending"),
            (json!({"budget_msat": 250_000, "per_call_max_msat": 200_000, "ttl_secs": 600}), "granted"),
            (json!({"budget_msat": 250_000, "per_call_max_msat": 200_001, "ttl_secs": 600}), "pending"),
        ])
        .await;

        // Duration, counted from the second the request is filed: a request
        // ending a minute inside the window is covered, one ending a minute
        // past it is not. The margins keep this independent of when the
        // request is filed; the exact second is checked by the crate's own
        // owner-window test on fixed clock values.
        for (past_window, expected) in [(-60, "granted"), (60, "pending")] {
            let ttl = expires_at + past_window - chrono::Utc::now().timestamp();
            let request = json!({"scopes": ["spend"], "budget": {"budget_msat": 100_000, "per_call_max_msat": 1_000, "ttl_secs": ttl}});
            let (body, _) = filed(&fx, &read, request).await;
            assert_eq!(body["status"], expected, "{past_window} s past the window, switch {switch}: {body}");
        }
    }
}

#[tokio::test]
async fn a_window_the_allowance_opened_does_not_answer_another_request() {
    let (mut fx, client, key) = with_allowance(true).await;
    // Hundreds of requests in a burst: lift the per-address limit for this test.
    fx.state = Arc::new(AppState { rate_limiter: Arc::new(konsensus_api::RateLimiter::new(1_000_000)), ..(*fx.state).clone() });
    let read = fx.token_as(&client, &key).await;
    // The same request, asked until the allowance opens no more windows (it
    // counts at most MAX_LEDGER_WINDOWS a day). Each one before that renews
    // the allowance window with exactly these terms; the last takes the owner
    // path while that window is live and covers every term it asks for.
    let ask = json!({"budget_msat": 1_000_000, "per_call_max_msat": 500_000, "ttl_secs": 3_600});
    let mut renewals = 0;
    let (op, body) = loop {
        let (op, body) = ask_with(&fx, &read, ask.clone()).await;
        if op["owner_action"].as_str().unwrap().contains("konsensus grant") {
            break (op, body);
        }
        assert_eq!(body["status"], "granted", "{body}");
        renewals += 1;
        assert!(renewals <= MAX_LEDGER_WINDOWS, "the allowance never sent a request to the owner");
    };
    assert_eq!(renewals, MAX_LEDGER_WINDOWS);
    let live: Vec<_> = fx
        .service
        .snapshot()
        .grants
        .into_iter()
        .filter(|g| g.client_id == client && g.is_live(chrono::Utc::now().timestamp()))
        .collect();
    assert_eq!(live.len(), 1, "{live:?}");
    assert_eq!(live[0].granted_by, ALLOWANCE_GRANTED_BY);
    let window = live[0].budget.as_ref().unwrap();
    assert!(window.remaining_msat() >= 1_000_000 && window.per_call_max_msat >= 500_000, "{window:?}");
    assert!(live[0].expires_at >= chrono::Utc::now().timestamp() + 3_000, "{:?}", live[0]);
    assert!(fx.service.snapshot().pending_elevations.iter().any(|e| Some(e.op_id.as_str()) == op["op_id"].as_str()));
    assert_eq!(body["owner_confirmation_required"], true, "{body}");
    // The request that hit the cap asked for the window's whole hour, so a
    // second's tick alone could keep it pending. A request well inside the
    // live window on every term, duration included, still is not answered.
    let (short, body) = ask_with(&fx, &read, json!({"budget_msat": 1_000_000, "per_call_max_msat": 500_000, "ttl_secs": 600})).await;
    assert!(short["owner_action"].as_str().unwrap().contains("konsensus grant"), "{short}");
    assert!(live[0].expires_at >= chrono::Utc::now().timestamp() + 600 + 60, "{:?}", live[0]);
    assert_eq!(body["status"], "pending", "{body}");
    assert_eq!(body["owner_confirmation_required"], true, "{body}");
}

#[tokio::test]
async fn wider_owner_terms_cover_narrower_requests() {
    let wide = json!({"budget_msat": 1_000_000, "per_call_max_msat": 500_000, "ttl_secs": 3_600});
    let with = |extra: Value| {
        let mut budget = wide.clone();
        budget.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        budget
    };
    for switch in [true, false] {
        // No payee allowlist: any payee set asked for is inside it.
        let (fx, client, key) = with_allowance(switch).await;
        fx.grant_as(&client, &key, None, GrantTerms::new(2_000_000).per_call(700_000).for_secs(86_400)).await;
        let read = fx.token_as(&client, &key).await;
        expect_statuses(&fx, &read, &format!("no allowlist, switch {switch}"), vec![
            (with(json!({"payee_allowlist": []})), "granted"),
            (with(json!({"payee_allowlist": [OTHER_LN]})), "granted"),
            // No caps on the window: caps the request names are inside it.
            (with(json!({"per_recipient_msat": {OTHER_LN: 100_000}})), "granted"),
        ])
        .await;

        // Two payees: one of them, or none, is inside.
        let (fx, client, key) = with_allowance(switch).await;
        let mut terms = GrantTerms::new(2_000_000).per_call(700_000).for_secs(86_400);
        terms.payee_allowlist = Some([OTHER_LN.to_string(), PEER_LN.to_string()].into());
        fx.grant_as(&client, &key, None, terms).await;
        let read = fx.token_as(&client, &key).await;
        expect_statuses(&fx, &read, &format!("two payees, switch {switch}"), vec![
            (with(json!({"payee_allowlist": [OTHER_LN]})), "granted"),
            (with(json!({"payee_allowlist": []})), "granted"),
            (with(json!({"payee_allowlist": [OTHER_LN, PEER_LN]})), "granted"),
        ])
        .await;

        // Liquidity fees allowed: a request with or without them is inside.
        let (fx, client, key) = with_allowance(switch).await;
        let mut terms = GrantTerms::new(2_000_000).per_call(700_000).for_secs(86_400);
        terms.allow_liquidity_fees = true;
        fx.grant_as(&client, &key, None, terms).await;
        let read = fx.token_as(&client, &key).await;
        expect_statuses(&fx, &read, &format!("liquidity fees, switch {switch}"), vec![
            (with(json!({"allow_liquidity_fees": true})), "granted"),
            (wide.clone(), "granted"),
        ])
        .await;
    }
}

#[tokio::test]
async fn each_recipient_cap_bounds_the_request_by_what_is_left_of_it() {
    let wide = json!({"budget_msat": 1_000_000, "per_call_max_msat": 500_000, "ttl_secs": 3_600});
    let with = |extra: Value| {
        let mut budget = wide.clone();
        budget.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        budget
    };
    for switch in [true, false] {
        // A cap partly used: what is left of it is covered, one msat more is not.
        let (fx, client, key) = with_allowance(switch).await;
        let token =
            fx.grant_as(&client, &key, None, GrantTerms::new(2_000_000).per_call(700_000).for_secs(86_400).recipient(OTHER_LN, 100_000)).await;
        assert_eq!(fx.keysend(&token, OTHER_LN, 40_000).await.0, StatusCode::OK);
        let window = owner_window(&fx, &client).budget.unwrap();
        let spent = window.used_by_recipient.get(OTHER_LN).copied().unwrap_or(0);
        assert!(spent >= 40_000, "switch {switch}: {spent}");
        let left = 100_000 - spent;
        let read = fx.token_as(&client, &key).await;
        expect_statuses(&fx, &read, &format!("partly used cap, switch {switch}"), vec![
            (with(json!({"per_recipient_msat": {OTHER_LN: left}})), "granted"),
            (with(json!({"per_recipient_msat": {OTHER_LN: left + 1}})), "pending"),
        ])
        .await;

        // Two caps: each is checked; a key only the request names is
        // bounded by the total alone.
        let (fx, client, key) = with_allowance(switch).await;
        let terms = GrantTerms::new(2_000_000).per_call(700_000).for_secs(86_400).recipient(OTHER_LN, 100_000).recipient(PEER_LN, 50_000);
        fx.grant_as(&client, &key, None, terms).await;
        let read = fx.token_as(&client, &key).await;
        expect_statuses(&fx, &read, &format!("two caps, switch {switch}"), vec![
            (with(json!({"per_recipient_msat": {OTHER_LN: 100_000, PEER_LN: 50_000}})), "granted"),
            (with(json!({"per_recipient_msat": {OTHER_LN: 100_000, PEER_LN: 50_001}})), "pending"),
            (with(json!({"per_recipient_msat": {OTHER_LN: 100_001, PEER_LN: 50_000}})), "pending"),
            (with(json!({"per_recipient_msat": {OTHER_LN: 100_000}})), "pending"),
        ])
        .await;

        let (fx, client, key) = with_allowance(switch).await;
        fx.grant_as(&client, &key, None, GrantTerms::new(2_000_000).per_call(700_000).for_secs(86_400).recipient(OTHER_LN, 100_000)).await;
        let read = fx.token_as(&client, &key).await;
        expect_statuses(&fx, &read, &format!("key only in the request, switch {switch}"), vec![
            (with(json!({"per_recipient_msat": {OTHER_LN: 100_000, PEER_LN: 200_000}})), "granted"),
        ])
        .await;
    }
}
