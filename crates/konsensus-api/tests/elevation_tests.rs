//! Owner-approved elevation: bindings, the seven negatives, and the positive
//! controls that stop the suite passing by refusing everything (#76).
//!
//! Every negative asserts the **side effect** — no grant record written, no
//! identity material written, no pairing scope changed — not merely the status
//! or error. That is the #74 lesson applied before it can recur, and it is why
//! each case is paired with a positive control: a suite that only proves
//! refusals cannot tell "correctly denied" from "broken for everyone".

use std::sync::Arc;

#[path = "common/owner_console.rs"]
mod owner_console;
use owner_console::OwnerConsole;

use ed25519_dalek::{Signer, SigningKey};

use konsensus_api::auth::Scope;
use konsensus_api::control::{self, ControlContext, ControlRequest, ControlResponse};
use konsensus_api::pairing::{self, PairedClient, PairingError, PairingService};

/// Two distinct valid BIP-39 vectors: the live identity and the destination.
const CURRENT_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const REPLACEMENT_MNEMONIC: &str =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";

fn client_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// Pair a client the way the ceremony does: read the challenge from the
/// protected file under the data directory and sign it.
fn pair(service: &PairingService, key: &SigningKey, name: &str) -> PairedClient {
    let pubkey = hex::encode(key.verifying_key().to_bytes());
    let outcome = service.request_pairing(name, &pubkey).unwrap();
    let challenge =
        std::fs::read(service.dir().join(format!("challenge-{}", outcome.pair_id))).unwrap();
    let msg = PairingService::proof_message(&outcome.pair_id, &pubkey, &challenge);
    let sig = hex::encode(key.sign(&msg).to_bytes());
    service
        .confirm_pairing(&outcome.pair_id, &sig, pairing::default_pairing_scopes())
        .unwrap()
}

/// An owner-run node: a control socket exists, so grants can be written.
fn owner_run_service(dir: &std::path::Path) -> (Arc<PairingService>, OwnerConsole) {
    let console = OwnerConsole::default();
    let service = Arc::new(
        PairingService::open(dir, current_fingerprint(), true)
            .unwrap()
            .with_owner_console(Box::new(console.clone()))
            .without_stdout_code(),
    );
    (service, console)
}

fn current_fingerprint() -> String {
    let id = konsensus_core::NodeIdentity::from_mnemonic(CURRENT_MNEMONIC, "").unwrap();
    pairing::identity_fingerprint(&id.node_id().to_hex())
}

fn replacement_fingerprint() -> String {
    let id = konsensus_core::NodeIdentity::from_mnemonic(REPLACEMENT_MNEMONIC, "").unwrap();
    pairing::identity_fingerprint(&id.node_id().to_hex())
}

fn ctx(service: &Arc<PairingService>, data_dir: &std::path::Path) -> ControlContext {
    ControlContext {
        service: Arc::clone(service),
        identity_fingerprint: current_fingerprint(),
        data_dir: data_dir.to_path_buf(),
        mnemonic_path: data_dir.join("mnemonic.txt"),
        replacement_guard: control::ReplacementGuard {
            layout: konsensus_api::bootstrap::DataDirLayout::new(data_dir),
            uses_identity_derived_keys: false,
            has_identity_passphrase: false,
        },
    }
}

/// Rewrite the durable store with an expired approval and reopen the service.
///
/// The durable file is the source of truth, so ageing the record on disk is the
/// honest way to reach the expiry branch — no production test seam needed.
fn expire_approvals_on_disk(dir: &std::path::Path) -> (Arc<PairingService>, OwnerConsole) {
    let path = dir.join("pairing").join("clients.json");
    let mut file: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let past = chrono::Utc::now().timestamp() - 10;
    for approval in file["replacement_approvals"].as_array_mut().unwrap() {
        approval["expires_at"] = serde_json::json!(past);
    }
    for op in file["pending_elevations"].as_array_mut().unwrap() {
        op["expires_at"] = serde_json::json!(past);
    }
    std::fs::write(&path, serde_json::to_vec_pretty(&file).unwrap()).unwrap();
    owner_run_service(dir)
}

// ─── Spend grants ──────────────────────────────────────────────────

#[test]
fn spend_grant_binding_enforced() {
    let tmp = tempfile::tempdir().unwrap();
    let (service, console) = owner_run_service(tmp.path());
    let key_a = client_key(1);
    let key_b = client_key(2);
    let a = pair(&service, &key_a, "client A");
    service.open_pairing_window(std::time::Duration::from_secs(60));
    let b = pair(&service, &key_b, "client B");

    let op = service
        .create_elevation_request(&a.client_id, vec![Scope::Spend])
        .unwrap();

    // Only `spend` is ever grantable: asking for more is refused at creation,
    // so no pending record exists to confirm later.
    for forbidden in [Scope::Identity, Scope::Credential, Scope::Admin] {
        let err = service
            .create_elevation_request(&a.client_id, vec![forbidden])
            .unwrap_err();
        assert!(matches!(err, PairingError::NotGrantable(_)), "{err}");
    }
    assert_eq!(
        service.reload_from_disk().unwrap().pending_elevations.len(),
        1,
        "a non-grantable request must not create a pending record"
    );

    // POSITIVE CONTROL: the owner's typed confirmation writes the grant, and it
    // reaches the client's token.
    let phrase = console.confirmation(&pairing::grant_confirmation_phrase(&op));
    let grant = service.grant_elevation(&op.op_id, &phrase, konsensus_api::spend_budget::GrantTerms::new(1_000_000)).unwrap();
    assert_eq!(grant.client_id, a.client_id);
    assert_eq!(grant.granted_by, "cli");
    assert_eq!(grant.scopes, vec![Scope::Spend]);

    let challenge = service.issue_token_challenge(&a.client_id).unwrap();
    let sig = hex::encode(key_a.sign(challenge.as_bytes()).to_bytes());
    let issued = service
        .issue_token(
            "node",
            "test-secret-at-least-32-bytes-long!",
            &a.client_id,
            &challenge,
            &sig,
        )
        .unwrap();
    assert!(issued.scopes.contains(&Scope::Spend));

    // BOUND TO THE CLIENT: B's token never carries A's grant.
    let challenge_b = service.issue_token_challenge(&b.client_id).unwrap();
    let sig_b = hex::encode(key_b.sign(challenge_b.as_bytes()).to_bytes());
    let issued_b = service
        .issue_token(
            "node",
            "test-secret-at-least-32-bytes-long!",
            &b.client_id,
            &challenge_b,
            &sig_b,
        )
        .unwrap();
    assert!(
        !issued_b.scopes.contains(&Scope::Spend),
        "a grant must not be transferable to another client"
    );

    // BOUND TO THE EPOCH: revoking drops the grant with it.
    service.bump_epoch(&a.client_id).unwrap();
    assert!(
        service.reload_from_disk().unwrap().grants.is_empty(),
        "a revocation must not leave a spend grant waiting"
    );
}

#[test]
fn sidecar_reopen_does_not_inherit_owner_granted_spend() {
    // P1-2: the grant file is shared by every process that opens the data
    // directory. An owner grants `spend` with the control socket up; a packaged
    // sidecar later reopens the same directory. The sidecar is read+receive by
    // design, so the persisted grant must reach neither a freshly issued token
    // nor the per-request binding check on a token minted in owner mode.
    let tmp = tempfile::tempdir().unwrap();
    let key = client_key(5);
    let secret = "test-secret-at-least-32-bytes-long!";
    let (client, owner_token_scopes) = {
        let (owner, console) = owner_run_service(tmp.path());
        let client = pair(&owner, &key, "desktop app");
        let op = owner
            .create_elevation_request(&client.client_id, vec![Scope::Spend])
            .unwrap();
        owner
            .grant_elevation(
                &op.op_id,
                &console.confirmation(&pairing::grant_confirmation_phrase(&op)),
                konsensus_api::spend_budget::GrantTerms::new(1_000_000),
            )
            .unwrap();
        // POSITIVE CONTROL: in owner mode the grant reaches the token.
        let challenge = owner.issue_token_challenge(&client.client_id).unwrap();
        let sig = hex::encode(key.sign(challenge.as_bytes()).to_bytes());
        let issued = owner
            .issue_token("node", secret, &client.client_id, &challenge, &sig)
            .unwrap();
        assert!(issued.scopes.contains(&Scope::Spend));
        owner
            .verify_token_binding(
                &client.client_id,
                client.epoch,
                &current_fingerprint(),
                &issued.scopes,
            )
            .unwrap();
        (client, issued.scopes)
    };

    // Reopen the SAME directory without owner control: the sidecar deployment.
    let sidecar = Arc::new(
        PairingService::open(tmp.path(), current_fingerprint(), false)
            .unwrap()
            .without_stdout_code(),
    );
    assert_eq!(
        sidecar.reload_from_disk().unwrap().grants.len(),
        1,
        "the owner's grant stays on disk — it is ignored, not erased"
    );

    // A fresh token must not carry spend.
    let challenge = sidecar.issue_token_challenge(&client.client_id).unwrap();
    let sig = hex::encode(key.sign(challenge.as_bytes()).to_bytes());
    let issued = sidecar
        .issue_token("node", secret, &client.client_id, &challenge, &sig)
        .unwrap();
    assert!(
        !issued.scopes.contains(&Scope::Spend),
        "a sidecar token must not carry an owner-granted spend: {:?}",
        issued.scopes
    );
    assert_eq!(issued.scopes, pairing::default_pairing_scopes());
    let claims = konsensus_api::auth::validate_token(&issued.token, secret).unwrap();
    assert!(
        !claims.scp.contains(&Scope::Spend),
        "the signed claims must not carry spend either: {:?}",
        claims.scp
    );

    // A token minted in owner mode that still claims spend fails the binding
    // check on the sidecar, so the spend path is closed for it too.
    let err = sidecar
        .verify_token_binding(
            &client.client_id,
            client.epoch,
            &current_fingerprint(),
            &owner_token_scopes,
        )
        .unwrap_err();
    assert!(
        matches!(err, PairingError::PairingInvalid(_)),
        "expected a binding refusal for spend on a sidecar, got: {err}"
    );
    // ...while the read+receive part of the same pairing still verifies.
    sidecar
        .verify_token_binding(
            &client.client_id,
            client.epoch,
            &current_fingerprint(),
            &pairing::default_pairing_scopes(),
        )
        .unwrap();

    // The sidecar must not report the grant as in effect either.
    let durable = sidecar.reload_from_disk().unwrap();
    assert_eq!(
        sidecar.elevation_status(&durable.grants[0].op_id),
        pairing::ElevationStatus::Absent
    );

    // POSITIVE CONTROL: reopening with owner control honours the same grant
    // again, so the refusal above is the deployment lock, not a lost grant.
    drop(sidecar);
    let (owner_again, _) = owner_run_service(tmp.path());
    let challenge = owner_again
        .issue_token_challenge(&client.client_id)
        .unwrap();
    let sig = hex::encode(key.sign(challenge.as_bytes()).to_bytes());
    let issued = owner_again
        .issue_token("node", secret, &client.client_id, &challenge, &sig)
        .unwrap();
    assert!(issued.scopes.contains(&Scope::Spend));
}

#[test]
fn sidecar_elevation_unavailable() {
    // The packaged sidecar deployment: no owner control socket, so elevation
    // can be REQUESTED and never obtained. This is the operator lock, asserted
    // by effect: not a scope check that a cleverer caller might satisfy.
    let tmp = tempfile::tempdir().unwrap();
    let sidecar = Arc::new(
        PairingService::open(tmp.path(), current_fingerprint(), false)
            .unwrap()
            .without_stdout_code(),
    );
    let key = client_key(3);
    let client = pair(&sidecar, &key, "packaged app");

    let op = sidecar
        .create_elevation_request(&client.client_id, vec![Scope::Spend])
        .unwrap();
    let phrase = pairing::grant_confirmation_phrase(&op);

    let err = sidecar.grant_elevation(&op.op_id, &phrase, konsensus_api::spend_budget::GrantTerms::new(1_000_000)).unwrap_err();
    assert!(
        matches!(err, PairingError::OwnerChannelUnavailable),
        "sidecar elevation must be unavailable, got: {err}"
    );
    assert!(
        sidecar.reload_from_disk().unwrap().grants.is_empty(),
        "no grant may be written without an owner channel"
    );

    // Even a correctly-formed approval consumption refuses.
    let err = sidecar
        .consume_replacement_approval("whatever", &client.client_id, "a", "b")
        .unwrap_err();
    assert!(
        matches!(err, PairingError::OwnerChannelUnavailable),
        "{err}"
    );

    // POSITIVE CONTROL: the very same request succeeds on an owner-run node,
    // so the refusal above is the deployment lock and not a broken code path.
    let tmp2 = tempfile::tempdir().unwrap();
    let (owner, owner_console) = owner_run_service(tmp2.path());
    let owner_client = pair(&owner, &key, "owner-run app");
    let op2 = owner
        .create_elevation_request(&owner_client.client_id, vec![Scope::Spend])
        .unwrap();
    owner
        .grant_elevation(
            &op2.op_id,
            &owner_console.confirmation(&pairing::grant_confirmation_phrase(&op2)),
            konsensus_api::spend_budget::GrantTerms::new(1_000_000),
        )
        .unwrap();
    assert_eq!(owner.reload_from_disk().unwrap().grants.len(), 1);
}

#[test]
fn owner_cli_confirmation_succeeds() {
    // The control-socket request/response path the CLI drives, including the
    // rendered summary and the exact phrase the owner must type.
    let tmp = tempfile::tempdir().unwrap();
    let (service, console) = owner_run_service(tmp.path());
    let key = client_key(4);
    let client = pair(&service, &key, "desktop app");
    let op = service
        .create_elevation_request(&client.client_id, vec![Scope::Spend])
        .unwrap();
    let context = ctx(&service, tmp.path());

    let described = control::handle(
        &context,
        ControlRequest::Describe {
            op_id: op.op_id.clone(),
        },
    );
    let phrase = match described {
        ControlResponse::Describe {
            summary,
            confirmation_label,
            ..
        } => {
            assert!(summary.contains(&client.client_id));
            assert!(summary.contains("desktop app"));
            assert!(
                confirmation_label.contains(&op.op_id),
                "the phrase must name the operation"
            );
            console.confirmation(&confirmation_label)
        }
        other => panic!("expected a description, got {other:?}"),
    };

    // A message arriving on the socket is not consent: a phrase that does not
    // name this operation writes nothing.
    let refused = control::handle(
        &context,
        ControlRequest::Grant {
            op_id: op.op_id.clone(),
            confirmation: "yes".into(),
            terms: konsensus_api::spend_budget::GrantTerms::new(1_000_000),
        },
    );
    assert!(
        matches!(refused, ControlResponse::Error { .. }),
        "{refused:?}"
    );
    assert!(service.reload_from_disk().unwrap().grants.is_empty());

    // POSITIVE CONTROL: the typed phrase writes the grant.
    let ok = control::handle(
        &context,
        ControlRequest::Grant {
            op_id: op.op_id.clone(),
            confirmation: phrase,
            terms: konsensus_api::spend_budget::GrantTerms::new(1_000_000),
        },
    );
    assert!(matches!(ok, ControlResponse::Ok { .. }), "{ok:?}");
    let durable = service.reload_from_disk().unwrap();
    assert_eq!(durable.grants.len(), 1);
    assert_eq!(durable.grants[0].client_id, client.client_id);
    assert!(
        durable.pending_elevations.is_empty(),
        "the pending request is consumed by the grant"
    );
}

// ─── Live-identity replacement: the five-field binding ─────────────

/// Set up an owner-run node with one paired client and a pending, owner-
/// approved-by-phrase replacement bound to `REPLACEMENT_MNEMONIC`.
fn pending_replacement(
    dir: &std::path::Path,
) -> (Arc<PairingService>, PairedClient, String, OwnerConsole) {
    let (service, console) = owner_run_service(dir);
    let key = client_key(7);
    let client = pair(&service, &key, "recovery wizard");
    let approval = service
        .create_replacement_request(
            &client.client_id,
            &current_fingerprint(),
            REPLACEMENT_MNEMONIC,
        )
        .unwrap();
    (service, client, approval.op_id, console)
}

#[test]
fn replacement_five_field_binding_enforced() {
    let tmp = tempfile::tempdir().unwrap();
    let (service, client, op_id, console) = pending_replacement(tmp.path());
    let approval = service.replacement_approval(&op_id).unwrap();

    // The destination is fixed at request time, computed from the phrase
    // BEFORE anything is written — the owner approves one identity, not
    // "whatever the app sends afterwards".
    assert_eq!(
        approval.replacement_identity_fingerprint,
        replacement_fingerprint()
    );
    assert_eq!(approval.current_identity_fingerprint, current_fingerprint());
    assert_eq!(approval.client_id, client.client_id);
    assert!(approval.expires_at > chrono::Utc::now().timestamp());
    assert!(!approval.approved, "creation is not approval");

    // POSITIVE CONTROL: all five fields matching, after the owner's typed
    // confirmation, consumes exactly once.
    service
        .approve_replacement(
            &op_id,
            &console.confirmation(&pairing::replacement_confirmation_phrase(&approval)),
        )
        .unwrap();
    let consumed = service
        .consume_replacement_approval(
            &op_id,
            &client.client_id,
            &current_fingerprint(),
            &replacement_fingerprint(),
        )
        .unwrap();
    assert_eq!(consumed.op_id, op_id);
    assert!(
        service
            .reload_from_disk()
            .unwrap()
            .replacement_approvals
            .is_empty(),
        "consumption is a compare-and-DELETE"
    );
}

#[test]
fn no_approval_no_effect() {
    let tmp = tempfile::tempdir().unwrap();
    let (service, client, op_id, console) = pending_replacement(tmp.path());

    // Created but never confirmed by the owner.
    let err = service
        .consume_replacement_approval(
            &op_id,
            &client.client_id,
            &current_fingerprint(),
            &replacement_fingerprint(),
        )
        .unwrap_err();
    assert!(matches!(err, PairingError::NotApproved), "{err}");

    // EFFECTS: the approval is still pending and unapproved, no grant was
    // written, no identity material exists, and the pairing still holds
    // exactly its default scopes.
    let durable = service.reload_from_disk().unwrap();
    assert_eq!(durable.replacement_approvals.len(), 1);
    assert!(!durable.replacement_approvals[0].approved);
    assert!(durable.grants.is_empty());
    assert!(!tmp.path().join("mnemonic.txt").exists());
    assert_eq!(durable.clients[0].scopes, pairing::default_pairing_scopes());
    assert_no_authority_or_identity_effect(&service, tmp.path());

    // POSITIVE CONTROL: with the owner's confirmation, the same call succeeds.
    let approval = service.replacement_approval(&op_id).unwrap();
    service
        .approve_replacement(
            &op_id,
            &console.confirmation(&pairing::replacement_confirmation_phrase(&approval)),
        )
        .unwrap();
    assert!(service
        .consume_replacement_approval(
            &op_id,
            &client.client_id,
            &current_fingerprint(),
            &replacement_fingerprint(),
        )
        .is_ok());
}

#[test]
fn wrong_client_no_effect() {
    let tmp = tempfile::tempdir().unwrap();
    let (service, client, op_id, console) = pending_replacement(tmp.path());
    let approval = service.replacement_approval(&op_id).unwrap();
    service
        .approve_replacement(
            &op_id,
            &console.confirmation(&pairing::replacement_confirmation_phrase(&approval)),
        )
        .unwrap();

    // Approval issued for client A, consumed by client B.
    let err = service
        .consume_replacement_approval(
            &op_id,
            "b".repeat(32).as_str(),
            &current_fingerprint(),
            &replacement_fingerprint(),
        )
        .unwrap_err();
    assert!(matches!(err, PairingError::BindingMismatch), "{err}");

    // EFFECTS: nothing written, and the owner's approval is NOT burned — an
    // attacker guessing wrong must not be able to spend the owner's decision.
    let durable = service.reload_from_disk().unwrap();
    assert_eq!(durable.replacement_approvals.len(), 1);
    assert!(durable.replacement_approvals[0].approved);
    assert!(!tmp.path().join("mnemonic.txt").exists());
    assert_no_authority_or_identity_effect(&service, tmp.path());

    // POSITIVE CONTROL: the bound client still succeeds afterwards.
    assert!(service
        .consume_replacement_approval(
            &op_id,
            &client.client_id,
            &current_fingerprint(),
            &replacement_fingerprint(),
        )
        .is_ok());
}

#[test]
fn wrong_current_identity_no_effect() {
    let tmp = tempfile::tempdir().unwrap();
    let (service, client, op_id, console) = pending_replacement(tmp.path());
    let approval = service.replacement_approval(&op_id).unwrap();
    service
        .approve_replacement(
            &op_id,
            &console.confirmation(&pairing::replacement_confirmation_phrase(&approval)),
        )
        .unwrap();

    let err = service
        .consume_replacement_approval(
            &op_id,
            &client.client_id,
            "0000000000000000000000000000dead",
            &replacement_fingerprint(),
        )
        .unwrap_err();
    assert!(matches!(err, PairingError::BindingMismatch), "{err}");

    let durable = service.reload_from_disk().unwrap();
    assert_eq!(durable.replacement_approvals.len(), 1);
    assert!(!tmp.path().join("mnemonic.txt").exists());
    assert_no_authority_or_identity_effect(&service, tmp.path());

    // POSITIVE CONTROL.
    assert!(service
        .consume_replacement_approval(
            &op_id,
            &client.client_id,
            &current_fingerprint(),
            &replacement_fingerprint(),
        )
        .is_ok());
}

#[test]
fn wrong_replacement_identity_no_effect() {
    let tmp = tempfile::tempdir().unwrap();
    let (service, client, op_id, console) = pending_replacement(tmp.path());
    let approval = service.replacement_approval(&op_id).unwrap();
    service
        .approve_replacement(
            &op_id,
            &console.confirmation(&pairing::replacement_confirmation_phrase(&approval)),
        )
        .unwrap();

    // Substituting the destination identity: the owner approved ONE identity.
    let substituted = pairing::fingerprint_for_mnemonic(CURRENT_MNEMONIC).unwrap();
    let err = service
        .consume_replacement_approval(
            &op_id,
            &client.client_id,
            &current_fingerprint(),
            &substituted,
        )
        .unwrap_err();
    assert!(matches!(err, PairingError::BindingMismatch), "{err}");

    let durable = service.reload_from_disk().unwrap();
    assert_eq!(durable.replacement_approvals.len(), 1);
    assert!(!tmp.path().join("mnemonic.txt").exists());

    // The same substitution over the control socket, where the phrase is
    // supplied by the owner: the derived fingerprint does not match the bound
    // one, so the write never happens.
    let refused = control::handle(
        &ctx(&service, tmp.path()),
        ControlRequest::ApproveReplacement {
            op_id: op_id.clone(),
            confirmation: console
                .confirmation(&pairing::replacement_confirmation_phrase(&approval)),
            mnemonic: CURRENT_MNEMONIC.into(),
        },
    );
    assert!(
        matches!(refused, ControlResponse::Error { .. }),
        "{refused:?}"
    );
    assert!(!tmp.path().join("mnemonic.txt").exists());
    assert_no_authority_or_identity_effect(&service, tmp.path());

    // POSITIVE CONTROL: the bound destination succeeds, and only then is the
    // identity material written.
    let ok = control::handle(
        &ctx(&service, tmp.path()),
        ControlRequest::ApproveReplacement {
            op_id,
            confirmation: console
                .confirmation(&pairing::replacement_confirmation_phrase(&approval)),
            mnemonic: REPLACEMENT_MNEMONIC.into(),
        },
    );
    assert!(matches!(ok, ControlResponse::Ok { .. }), "{ok:?}");
    let written = std::fs::read_to_string(tmp.path().join("mnemonic.txt")).unwrap();
    assert_eq!(written, REPLACEMENT_MNEMONIC);
}

#[test]
fn replay_no_second_effect() {
    let tmp = tempfile::tempdir().unwrap();
    let (service, client, op_id, console) = pending_replacement(tmp.path());
    let approval = service.replacement_approval(&op_id).unwrap();
    service
        .approve_replacement(
            &op_id,
            &console.confirmation(&pairing::replacement_confirmation_phrase(&approval)),
        )
        .unwrap();

    // POSITIVE CONTROL first: one consumption succeeds.
    assert!(service
        .consume_replacement_approval(
            &op_id,
            &client.client_id,
            &current_fingerprint(),
            &replacement_fingerprint(),
        )
        .is_ok());

    // The replay: the op_id is gone, so it is refused.
    let err = service
        .consume_replacement_approval(
            &op_id,
            &client.client_id,
            &current_fingerprint(),
            &replacement_fingerprint(),
        )
        .unwrap_err();
    assert!(matches!(err, PairingError::UnknownOperation), "{err}");
    assert!(service
        .reload_from_disk()
        .unwrap()
        .replacement_approvals
        .is_empty());
    assert_no_authority_or_identity_effect(&service, tmp.path());
}

#[test]
fn replacement_uses_configured_identity_path() {
    let tmp = tempfile::tempdir().unwrap();
    let (service, _, op_id, console) = pending_replacement(tmp.path());
    let approval = service.replacement_approval(&op_id).unwrap();
    let mut context = ctx(&service, tmp.path());
    let identity_dir = tmp.path().join("identity");
    std::fs::create_dir(&identity_dir).unwrap();
    context.mnemonic_path = identity_dir.join("mnemonic.txt");
    std::fs::write(&context.mnemonic_path, CURRENT_MNEMONIC).unwrap();
    let response = control::handle(
        &context,
        ControlRequest::ApproveReplacement {
            op_id,
            confirmation: console
                .confirmation(&pairing::replacement_confirmation_phrase(&approval)),
            mnemonic: REPLACEMENT_MNEMONIC.into(),
        },
    );
    assert!(
        matches!(response, ControlResponse::Ok { .. }),
        "{response:?}"
    );
    assert_eq!(
        std::fs::read_to_string(&context.mnemonic_path).unwrap(),
        REPLACEMENT_MNEMONIC
    );
    assert!(!tmp.path().join("mnemonic.txt").exists());
}

#[test]
fn encrypted_replacement_refuses_without_consuming_approval() {
    let tmp = tempfile::tempdir().unwrap();
    let (service, _, op_id, console) = pending_replacement(tmp.path());
    let approval = service.replacement_approval(&op_id).unwrap();
    let mut context = ctx(&service, tmp.path());
    context.mnemonic_path = tmp.path().join("mnemonic.enc");
    std::fs::write(&context.mnemonic_path, b"encrypted fixture").unwrap();
    let before = serde_json::to_value(service.snapshot()).unwrap();
    let response = control::handle(
        &context,
        ControlRequest::ApproveReplacement {
            op_id,
            confirmation: console
                .confirmation(&pairing::replacement_confirmation_phrase(&approval)),
            mnemonic: REPLACEMENT_MNEMONIC.into(),
        },
    );
    assert!(matches!(response, ControlResponse::Error { .. }));
    assert_eq!(
        std::fs::read(&context.mnemonic_path).unwrap(),
        b"encrypted fixture"
    );
    assert_eq!(serde_json::to_value(service.snapshot()).unwrap(), before);
    assert!(!tmp.path().join("mnemonic.txt").exists());
}

#[test]
fn concurrent_consume_exactly_once() {
    let tmp = tempfile::tempdir().unwrap();
    let (service, client, op_id, console) = pending_replacement(tmp.path());
    let approval = service.replacement_approval(&op_id).unwrap();
    service
        .approve_replacement(
            &op_id,
            &console.confirmation(&pairing::replacement_confirmation_phrase(&approval)),
        )
        .unwrap();

    let mut outcomes = Vec::new();
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let service = Arc::clone(&service);
                let op_id = op_id.clone();
                let client_id = client.client_id.clone();
                scope.spawn(move || {
                    service
                        .consume_replacement_approval(
                            &op_id,
                            &client_id,
                            &current_fingerprint(),
                            &replacement_fingerprint(),
                        )
                        .is_ok()
                })
            })
            .collect();
        for h in handles {
            outcomes.push(h.join().unwrap());
        }
    });

    assert_eq!(
        outcomes.iter().filter(|ok| **ok).count(),
        1,
        "exactly one concurrent consumption may succeed"
    );
    // And the store shows exactly one effect: the approval is gone, once.
    assert!(service
        .reload_from_disk()
        .unwrap()
        .replacement_approvals
        .is_empty());
    assert_no_authority_or_identity_effect(&service, tmp.path());
}

#[test]
fn expired_approval_no_effect() {
    let tmp = tempfile::tempdir().unwrap();
    let (service, client, op_id, console) = pending_replacement(tmp.path());
    let approval = service.replacement_approval(&op_id).unwrap();
    service
        .approve_replacement(
            &op_id,
            &console.confirmation(&pairing::replacement_confirmation_phrase(&approval)),
        )
        .unwrap();

    // Age the durable record past its window. Expiry is enforced at
    // consumption, not only at creation.
    let (aged, _aged_console) = expire_approvals_on_disk(tmp.path());
    let err = aged
        .consume_replacement_approval(
            &op_id,
            &client.client_id,
            &current_fingerprint(),
            &replacement_fingerprint(),
        )
        .unwrap_err();
    assert!(matches!(err, PairingError::Expired), "{err}");
    assert!(!tmp.path().join("mnemonic.txt").exists());

    // An expired elevation request cannot be granted either.
    let op = aged
        .create_elevation_request(&client.client_id, vec![Scope::Spend])
        .unwrap();
    let phrase = pairing::grant_confirmation_phrase(&op);
    let (aged2, console2) = expire_approvals_on_disk(tmp.path());
    let err = aged2.grant_elevation(&op.op_id, &phrase, konsensus_api::spend_budget::GrantTerms::new(1_000_000)).unwrap_err();
    assert!(matches!(err, PairingError::Expired), "{err}");
    assert!(
        aged2.reload_from_disk().unwrap().grants.is_empty(),
        "an expired request must not produce a grant"
    );
    assert_no_authority_or_identity_effect(&aged2, tmp.path());

    // POSITIVE CONTROL: a fresh request, still inside its window, is granted.
    let fresh = aged2
        .create_elevation_request(&client.client_id, vec![Scope::Spend])
        .unwrap();
    aged2
        .grant_elevation(
            &fresh.op_id,
            &console2.confirmation(&pairing::grant_confirmation_phrase(&fresh)),
            konsensus_api::spend_budget::GrantTerms::new(1_000_000),
        )
        .unwrap();
    assert_eq!(aged2.reload_from_disk().unwrap().grants.len(), 1);
}

fn assert_no_authority_or_identity_effect(service: &PairingService, dir: &std::path::Path) {
    let durable = service.reload_from_disk().unwrap();
    assert!(
        durable.grants.is_empty(),
        "a denial must not create a grant"
    );
    assert!(
        !durable.clients.is_empty(),
        "positive fixture must contain a pairing"
    );
    for client in &durable.clients {
        assert_eq!(client.scopes, pairing::default_pairing_scopes());
        assert_eq!(client.identity_fingerprint, current_fingerprint());
    }
    assert!(!dir.join("mnemonic.txt").exists());
    assert!(!dir.join("identity").exists());
}

#[test]
fn replacement_approval_requires_owner_console_entropy() {
    let tmp = tempfile::tempdir().unwrap();
    let (service, client, op_id, console) = pending_replacement(tmp.path());
    let approval = service.replacement_approval(&op_id).unwrap();
    let label = pairing::replacement_confirmation_phrase(&approval);
    let before = serde_json::to_value(service.snapshot()).unwrap();
    assert!(matches!(
        service.approve_replacement(&op_id, &label),
        Err(PairingError::ConfirmationMismatch)
    ));
    assert_eq!(
        serde_json::to_value(service.reload_from_disk().unwrap()).unwrap(),
        before
    );
    assert_no_authority_or_identity_effect(&service, tmp.path());
    let phrase = console.confirmation(&label);
    let other = service
        .create_replacement_request(
            &client.client_id,
            &current_fingerprint(),
            REPLACEMENT_MNEMONIC,
        )
        .unwrap();
    assert!(matches!(
        service.approve_replacement(&other.op_id, &phrase),
        Err(PairingError::ConfirmationMismatch)
    ));
    assert!(
        service
            .approve_replacement(&op_id, &phrase)
            .unwrap()
            .approved
    );
    // A restart cannot recover a nonce from the client-readable durable file.
    let (restarted, _console) = owner_run_service(tmp.path());
    assert!(matches!(
        restarted.approve_replacement(
            &other.op_id,
            &console.confirmation(&pairing::replacement_confirmation_phrase(&other))
        ),
        Err(PairingError::ConfirmationMismatch)
    ));
}

#[test]
fn replacement_refuses_retained_state_before_approval_or_identity_write() {
    for artifact in [
        "nested-ldk",
        "external-ldk",
        "external-store",
        "scb",
        "whitelist",
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let external = tempfile::tempdir().unwrap();
        let (service, _, op_id, console) = pending_replacement(tmp.path());
        let approval = service.replacement_approval(&op_id).unwrap();
        let mut context = ctx(&service, tmp.path());
        let identity_dir = if artifact == "nested-ldk" {
            tmp.path().join("identity")
        } else {
            external.path().join("keys")
        };
        std::fs::create_dir_all(&identity_dir).unwrap();
        context.mnemonic_path = identity_dir.join("mnemonic.txt");
        std::fs::write(&context.mnemonic_path, CURRENT_MNEMONIC).unwrap();
        let store_path = external.path().join("messages.sqlite");
        let backups = external.path().join("backups");
        context.replacement_guard.layout = konsensus_api::bootstrap::DataDirLayout::new(tmp.path())
            .with_configured_paths(
                context.mnemonic_path.clone(),
                Some(store_path.clone()),
                backups.clone(),
            );
        assert!(
            context.replacement_guard.ensure_replaceable().is_ok(),
            "empty positive control"
        );
        let state_file = match artifact {
            "nested-ldk" | "external-ldk" => identity_dir.join("ldk").join("channel-monitor"),
            "external-store" => store_path,
            "scb" => backups.join("scb-latest.aes"),
            _ => backups.join("whitelist-latest.aes"),
        };
        std::fs::create_dir_all(state_file.parent().unwrap()).unwrap();
        std::fs::write(&state_file, b"retained state fixture").unwrap();
        let before = serde_json::to_value(service.reload_from_disk().unwrap()).unwrap();
        let response = control::handle(
            &context,
            ControlRequest::ApproveReplacement {
                op_id,
                confirmation: console
                    .confirmation(&pairing::replacement_confirmation_phrase(&approval)),
                mnemonic: REPLACEMENT_MNEMONIC.into(),
            },
        );
        assert!(
            matches!(response, ControlResponse::Error { .. }),
            "{artifact}: {response:?}"
        );
        assert_eq!(
            std::fs::read_to_string(&context.mnemonic_path).unwrap(),
            CURRENT_MNEMONIC
        );
        assert_eq!(
            std::fs::read(&state_file).unwrap(),
            b"retained state fixture"
        );
        assert_eq!(
            serde_json::to_value(service.reload_from_disk().unwrap()).unwrap(),
            before
        );
    }
}

#[tokio::test]
async fn replacement_refusal_preserves_decryptable_history() {
    use konsensus_storage::Storage;
    let tmp = tempfile::tempdir().unwrap();
    let (service, _, op_id, console) = pending_replacement(tmp.path());
    let approval = service.replacement_approval(&op_id).unwrap();
    let mut context = ctx(&service, tmp.path());
    std::fs::write(&context.mnemonic_path, CURRENT_MNEMONIC).unwrap();
    let path = tmp.path().join("konsensus.db");
    let identity = konsensus_core::NodeIdentity::from_mnemonic(CURRENT_MNEMONIC, "").unwrap();
    let sqlite = konsensus_storage::SqliteStorage::open(path.to_str().unwrap())
        .await
        .unwrap();
    let encrypted = konsensus_storage::EncryptedStorage::new(sqlite, identity.aes_key());
    let envelope = konsensus_core::UkmEnvelopeBuilder::new(
        100,
        *identity.node_id(),
        konsensus_core::types::Recipient::Node(*identity.node_id()),
        b"retained encrypted history".to_vec(),
        konsensus_core::PaymentProof::new([0; 32], [0; 32], 0),
    )
    .build();
    encrypted.store_message(&envelope).await.unwrap();
    context.replacement_guard.uses_identity_derived_keys = true;
    let before = serde_json::to_value(service.reload_from_disk().unwrap()).unwrap();
    let response = control::handle(
        &context,
        ControlRequest::ApproveReplacement {
            op_id,
            confirmation: console
                .confirmation(&pairing::replacement_confirmation_phrase(&approval)),
            mnemonic: REPLACEMENT_MNEMONIC.into(),
        },
    );
    assert!(matches!(response, ControlResponse::Error { .. }));
    assert_eq!(
        std::fs::read_to_string(&context.mnemonic_path).unwrap(),
        CURRENT_MNEMONIC
    );
    assert_eq!(
        serde_json::to_value(service.reload_from_disk().unwrap()).unwrap(),
        before
    );
    assert_eq!(
        encrypted
            .get_message(&envelope.id)
            .await
            .unwrap()
            .unwrap()
            .ciphertext,
        envelope.ciphertext
    );
    // The replacement key demonstrably cannot decrypt the retained record.
    let replacement =
        konsensus_core::NodeIdentity::from_mnemonic(REPLACEMENT_MNEMONIC, "").unwrap();
    let wrong_key = konsensus_storage::EncryptedStorage::new(
        konsensus_storage::SqliteStorage::open(path.to_str().unwrap())
            .await
            .unwrap(),
        replacement.aes_key(),
    );
    assert!(wrong_key.get_message(&envelope.id).await.is_err());
}

/// Finding 1: a late/concurrent bootstrap confirmation must never persist
/// identity authority after the identity is rebound.
#[test]
fn late_bootstrap_confirm_cannot_persist_identity_after_rebind() {
    let tmp = tempfile::tempdir().unwrap();
    let service = PairingService::open(tmp.path(), String::new(), false)
        .unwrap()
        .without_stdout_code();

    let key_a = client_key(11);
    let key_b = client_key(12);
    let pubkey_a = hex::encode(key_a.verifying_key().to_bytes());
    let pubkey_b = hex::encode(key_b.verifying_key().to_bytes());

    // Queue two pairing requests while bootstrap is empty.
    let req_a = service.request_pairing("client-a", &pubkey_a).unwrap();
    let req_b = service.request_pairing("client-b", &pubkey_b).unwrap();

    let challenge_a =
        std::fs::read(service.dir().join(format!("challenge-{}", req_a.pair_id))).unwrap();
    let sig_a = hex::encode(
        key_a
            .sign(&PairingService::proof_message(
                &req_a.pair_id,
                &pubkey_a,
                &challenge_a,
            ))
            .to_bytes(),
    );
    service
        .confirm_pairing(
            &req_a.pair_id,
            &sig_a,
            pairing::bootstrap_pairing_scopes(),
        )
        .unwrap();

    // Commit/rebind: identity exists. Pending B is cleared, but clearing alone
    // is not the gate — confirm with bootstrap scopes must still refuse once
    // a fingerprint is bound (covers the concurrent "already removed from
    // pending" path via the same final-lock check).
    let fingerprint = current_fingerprint();
    service.rebind_to_identity(&fingerprint).unwrap();
    assert!(
        service
            .confirm_pairing(
                &req_b.pair_id,
                "00",
                pairing::bootstrap_pairing_scopes(),
            )
            .is_err(),
        "pending B must not survive rebind"
    );

    service.open_pairing_window(std::time::Duration::from_secs(60));
    let late = service.request_pairing("client-b-late", &pubkey_b).unwrap();
    let late_challenge =
        std::fs::read(service.dir().join(format!("challenge-{}", late.pair_id))).unwrap();
    let late_sig = hex::encode(
        key_b
            .sign(&PairingService::proof_message(
                &late.pair_id,
                &pubkey_b,
                &late_challenge,
            ))
            .to_bytes(),
    );
    let err = service
        .confirm_pairing(
            &late.pair_id,
            &late_sig,
            pairing::bootstrap_pairing_scopes(),
        )
        .unwrap_err();
    assert!(
        matches!(err, PairingError::Closed),
        "expected Closed after rebind, got {err:?}"
    );

    let durable = service.reload_from_disk().unwrap();
    assert!(
        !durable
            .clients
            .iter()
            .any(|c| c.scopes.contains(&Scope::Identity)),
        "identity authority must never persist after rebind: {:?}",
        durable.clients
    );
}

/// Finding 2: a JWT from a deleted pairing must stay rejected after re-pairing
/// the same key, including across a service restart.
#[test]
fn revoked_jwt_stays_rejected_after_repair_of_same_key() {
    let tmp = tempfile::tempdir().unwrap();
    let secret = "test-secret-at-least-32-bytes-long!";
    let key = client_key(21);
    let fingerprint = current_fingerprint();

    let (service, _console) = owner_run_service(tmp.path());
    let client = pair(&service, &key, "phone");
    let challenge = service.issue_token_challenge(&client.client_id).unwrap();
    let sig = hex::encode(key.sign(challenge.as_bytes()).to_bytes());
    let issued = service
        .issue_token("node", secret, &client.client_id, &challenge, &sig)
        .unwrap();
    let claims = konsensus_api::auth::validate_token(&issued.token, secret).unwrap();
    let old_epoch = claims.epc.unwrap();
    assert_eq!(old_epoch, client.epoch);

    service.revoke(&client.client_id).unwrap();
    assert!(service
        .verify_token_binding(&client.client_id, old_epoch, &fingerprint, &claims.scp)
        .is_err());

    // Re-pair the same public key before the old JWT would expire.
    service.open_pairing_window(std::time::Duration::from_secs(60));
    let repaired = pair(&service, &key, "phone-again");
    assert_eq!(repaired.client_id, client.client_id);
    assert_ne!(
        repaired.epoch, old_epoch,
        "re-pair must advance the generation so the revoked JWT cannot bind"
    );
    assert!(
        service
            .verify_token_binding(&client.client_id, old_epoch, &fingerprint, &claims.scp)
            .is_err(),
        "revoked JWT must remain rejected after re-pairing the same key"
    );

    // Across restart: reopen from disk and re-check.
    let restarted = PairingService::open(tmp.path(), fingerprint.clone(), true)
        .unwrap()
        .without_stdout_code();
    assert!(
        restarted
            .verify_token_binding(&client.client_id, old_epoch, &fingerprint, &claims.scp)
            .is_err(),
        "revoked JWT must remain rejected after restart"
    );
    assert_eq!(
        restarted
            .list_clients()
            .iter()
            .find(|c| c.client_id == client.client_id)
            .unwrap()
            .epoch,
        repaired.epoch
    );
}

/// Finding 2 (rotation): a revoked destination JWT must stay rejected after
/// rotation into that key, and after rotation away plus same-key re-pair,
/// including across a service restart that reopens the durable last_epoch map.
#[test]
fn revoked_jwt_stays_rejected_after_rotation_into_key() {
    let tmp = tempfile::tempdir().unwrap();
    let secret = "test-secret-at-least-32-bytes-long!";
    let key_a = client_key(31);
    let key_b = client_key(32);
    let key_c = client_key(33);
    let fingerprint = current_fingerprint();

    let (service, _console) = owner_run_service(tmp.path());

    // Pair B, re-pair to raise its epoch, mint a JWT, then revoke B.
    let b1 = pair(&service, &key_b, "phone-b");
    service.open_pairing_window(std::time::Duration::from_secs(60));
    let b2 = pair(&service, &key_b, "phone-b-again");
    assert!(b2.epoch > b1.epoch);
    let challenge = service.issue_token_challenge(&b2.client_id).unwrap();
    let sig = hex::encode(key_b.sign(challenge.as_bytes()).to_bytes());
    let issued = service
        .issue_token("node", secret, &b2.client_id, &challenge, &sig)
        .unwrap();
    let claims = konsensus_api::auth::validate_token(&issued.token, secret).unwrap();
    let revoked_epoch = claims.epc.unwrap();
    assert_eq!(revoked_epoch, b2.epoch);
    service.revoke(&b2.client_id).unwrap();
    assert!(service
        .verify_token_binding(&b2.client_id, revoked_epoch, &fingerprint, &claims.scp)
        .is_err());

    // Pair A at a lower epoch and rotate A → B's public key. The rotated
    // record must allocate above B's historical epoch so the revoked JWT
    // cannot bind.
    service.open_pairing_window(std::time::Duration::from_secs(60));
    let a = pair(&service, &key_a, "phone-a");
    assert!(a.epoch < revoked_epoch);
    let new_pubkey = hex::encode(key_b.verifying_key().to_bytes());
    let rotate_msg = format!("bitsov-pair-rotate-v1:{}:{new_pubkey}", a.client_id);
    let rotate_sig = hex::encode(key_a.sign(rotate_msg.as_bytes()).to_bytes());
    let rotated_into_b = service
        .rotate_client_key(&a.client_id, &new_pubkey, &rotate_sig)
        .unwrap();
    assert_eq!(rotated_into_b.client_id, b2.client_id);
    assert!(
        rotated_into_b.epoch > revoked_epoch,
        "rotation must allocate above the destination history, got {} vs revoked {}",
        rotated_into_b.epoch,
        revoked_epoch
    );
    assert!(
        service
            .verify_token_binding(&b2.client_id, revoked_epoch, &fingerprint, &claims.scp)
            .is_err(),
        "revoked JWT must stay rejected after rotation into that key"
    );

    // Rotate B → C, then re-pair B. History for B must never have been lowered,
    // so the re-pair cannot recreate the revoked epoch.
    let c_pubkey = hex::encode(key_c.verifying_key().to_bytes());
    let rotate_away = format!(
        "bitsov-pair-rotate-v1:{}:{c_pubkey}",
        rotated_into_b.client_id
    );
    let rotate_away_sig = hex::encode(key_b.sign(rotate_away.as_bytes()).to_bytes());
    let _rotated_to_c = service
        .rotate_client_key(&rotated_into_b.client_id, &c_pubkey, &rotate_away_sig)
        .unwrap();

    service.open_pairing_window(std::time::Duration::from_secs(60));
    let repaired_b = pair(&service, &key_b, "phone-b-repair");
    assert_eq!(repaired_b.client_id, b2.client_id);
    assert!(
        repaired_b.epoch > revoked_epoch,
        "re-pair after rotation away must still advance past the revoked epoch"
    );
    assert!(
        service
            .verify_token_binding(&b2.client_id, revoked_epoch, &fingerprint, &claims.scp)
            .is_err(),
        "revoked JWT must stay rejected after rotation away and same-key re-pair"
    );

    let restarted = PairingService::open(tmp.path(), fingerprint.clone(), true)
        .unwrap()
        .without_stdout_code();
    assert!(
        restarted
            .verify_token_binding(&b2.client_id, revoked_epoch, &fingerprint, &claims.scp)
            .is_err(),
        "revoked JWT must stay rejected after reopening persisted state"
    );
    assert_eq!(
        restarted
            .list_clients()
            .iter()
            .find(|c| c.client_id == b2.client_id)
            .unwrap()
            .epoch,
        repaired_b.epoch
    );
}

// ─── The short owner code (one-step `konsensus grant`) ─────────────

fn front_door_grants(service: &PairingService) -> usize {
    service.reload_from_disk().unwrap().front_door_grants.len()
}

/// Every file under `dir`, as lossy text.
fn all_files_text(dir: &std::path::Path) -> String {
    let mut out = String::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            out.push_str(&all_files_text(&path));
        } else if let Ok(bytes) = std::fs::read(&path) {
            out.push_str(&String::from_utf8_lossy(&bytes));
        }
    }
    out
}

#[test]
fn short_owner_code_grants_spend_and_front_door() {
    let tmp = tempfile::tempdir().unwrap();
    let (service, console) = owner_run_service(tmp.path());
    let a = pair(&service, &client_key(1), "client A");

    let spend = service
        .create_elevation_request(&a.client_id, vec![Scope::Spend])
        .unwrap();
    let code = console.owner_code(&spend.op_id);
    assert_eq!(code.len(), 9, "{code}");
    assert_eq!(&code[4..5], "-");

    // The owner types it as they read it: case and dash do not matter.
    let typed = code.replace('-', " ").to_lowercase();
    let grant = service
        .grant_elevation(&spend.op_id, &typed, konsensus_api::spend_budget::GrantTerms::new(1_000_000))
        .unwrap();
    assert_eq!(grant.client_id, a.client_id);
    assert_eq!(service.reload_from_disk().unwrap().grants.len(), 1);

    let fd = service
        .create_elevation_request(&a.client_id, vec![Scope::FrontDoor])
        .unwrap();
    let code = console.owner_code(&fd.op_id);
    service.grant_front_door(&fd.op_id, &code, 3600).unwrap();
    assert_eq!(front_door_grants(&service), 1);

    // The code approved exactly once: the request is consumed.
    let err = service.grant_front_door(&fd.op_id, &code, 3600).unwrap_err();
    assert!(matches!(err, PairingError::UnknownOperation), "{err}");
}

#[test]
fn a_code_approves_only_its_own_request() {
    let tmp = tempfile::tempdir().unwrap();
    let (service, console) = owner_run_service(tmp.path());
    let a = pair(&service, &client_key(1), "client A");
    let first = service
        .create_elevation_request(&a.client_id, vec![Scope::Spend])
        .unwrap();
    let second = service
        .create_elevation_request(&a.client_id, vec![Scope::Spend])
        .unwrap();
    let first_code = console.owner_code(&first.op_id);
    assert_ne!(first_code, console.owner_code(&second.op_id));

    let err = service
        .grant_elevation(&second.op_id, &first_code, konsensus_api::spend_budget::GrantTerms::new(1_000))
        .unwrap_err();
    assert!(matches!(err, PairingError::WrongOwnerCode(2)), "{err}");
    assert!(service.reload_from_disk().unwrap().grants.is_empty());
}

#[test]
fn wrong_codes_cancel_the_request_without_effect() {
    let tmp = tempfile::tempdir().unwrap();
    let (service, console) = owner_run_service(tmp.path());
    let a = pair(&service, &client_key(1), "client A");
    let op = service
        .create_elevation_request(&a.client_id, vec![Scope::Spend])
        .unwrap();
    let code = console.owner_code(&op.op_id);
    let terms = || konsensus_api::spend_budget::GrantTerms::new(1_000_000);

    for left in [2u8, 1] {
        let err = service.grant_elevation(&op.op_id, "AAAA-AAAA", terms()).unwrap_err();
        assert!(matches!(err, PairingError::WrongOwnerCode(l) if l == left), "{err}");
        assert_eq!(service.elevation_status(&op.op_id), pairing::ElevationStatus::Pending);
    }
    let err = service.grant_elevation(&op.op_id, "AAAA-AAAA", terms()).unwrap_err();
    assert!(matches!(err, PairingError::ConfirmationLost), "{err}");

    // Cancelled: not even the right code or the full line approves it now.
    let phrase = console.confirmation(&pairing::grant_confirmation_phrase(&op));
    for right in [code.as_str(), phrase.as_str()] {
        let err = service.grant_elevation(&op.op_id, right, terms()).unwrap_err();
        assert!(matches!(err, PairingError::ConfirmationLost), "{err}");
    }
    assert!(service.reload_from_disk().unwrap().grants.is_empty());
    assert_eq!(service.elevation_status(&op.op_id), pairing::ElevationStatus::Lost);

    // The owner saw each attempt on their own terminal.
    let text = console.text();
    assert_eq!(text.matches("WRONG approval code").count(), 3, "{text}");
    assert!(text.contains("That request is cancelled"), "{text}");
}

#[test]
fn run_wide_cap_turns_short_codes_off_but_not_the_full_line() {
    let tmp = tempfile::tempdir().unwrap();
    let (service, console) = owner_run_service(tmp.path());
    let a = pair(&service, &client_key(1), "client A");
    let terms = || konsensus_api::spend_budget::GrantTerms::new(1_000);

    // Spend the run's wrong-code allowance across requests the attacker makes.
    let mut spent = 0;
    while spent < pairing::OWNER_CODE_FAILURES_PER_RUN {
        let op = service
            .create_elevation_request(&a.client_id, vec![Scope::Spend])
            .unwrap();
        for _ in 0..pairing::OWNER_CODE_ATTEMPTS {
            if spent == pairing::OWNER_CODE_FAILURES_PER_RUN {
                break;
            }
            let _ = service.grant_elevation(&op.op_id, "AAAA-AAAA", terms());
            spent += 1;
        }
    }
    assert!(console.text().contains("short codes are off until the node restarts"));

    let op = service
        .create_elevation_request(&a.client_id, vec![Scope::Spend])
        .unwrap();
    let code = console.owner_code(&op.op_id);
    let err = service.grant_elevation(&op.op_id, &code, terms()).unwrap_err();
    assert!(matches!(err, PairingError::ConfirmationMismatch), "{err}");
    assert!(service.reload_from_disk().unwrap().grants.is_empty());

    // POSITIVE CONTROL: the full console line still approves.
    let phrase = console.confirmation(&pairing::grant_confirmation_phrase(&op));
    service.grant_elevation(&op.op_id, &phrase, terms()).unwrap();
    assert_eq!(service.reload_from_disk().unwrap().grants.len(), 1);
}

#[test]
fn a_request_from_before_a_restart_is_lost_not_pending() {
    let tmp = tempfile::tempdir().unwrap();
    let (service, console) = owner_run_service(tmp.path());
    let a = pair(&service, &client_key(1), "client A");
    let op = service
        .create_elevation_request(&a.client_id, vec![Scope::Spend])
        .unwrap();
    let code = console.owner_code(&op.op_id);
    let phrase = console.confirmation(&pairing::grant_confirmation_phrase(&op));
    assert_eq!(service.elevation_status(&op.op_id), pairing::ElevationStatus::Pending);
    drop(service);

    // Restart: the request is still on file, its codes are not.
    let (service, _) = owner_run_service(tmp.path());
    assert_eq!(service.reload_from_disk().unwrap().pending_elevations.len(), 1);
    assert_eq!(service.elevation_status(&op.op_id), pairing::ElevationStatus::Lost);
    assert_eq!(
        serde_json::to_value(pairing::ElevationStatus::Lost).unwrap(),
        serde_json::json!("lost")
    );
    for old in [code.as_str(), phrase.as_str()] {
        let err = service
            .grant_elevation(&op.op_id, old, konsensus_api::spend_budget::GrantTerms::new(1_000))
            .unwrap_err();
        assert!(matches!(err, PairingError::ConfirmationLost), "{err}");
    }
    assert!(service.reload_from_disk().unwrap().grants.is_empty());

    // The owner CLI is told before it asks for terms or a code.
    let ctx = ctx(&service, tmp.path());
    match control::handle(&ctx, ControlRequest::Describe { op_id: op.op_id.clone() }) {
        ControlResponse::Error { message } => assert!(message.contains("Ask again"), "{message}"),
        other => panic!("a lost request must not be described as approvable: {other:?}"),
    }
    match control::handle(&ctx, ControlRequest::Status) {
        ControlResponse::Status { pending_elevations, .. } => {
            assert!(pending_elevations.iter().all(|e| e.lost), "{pending_elevations:?}")
        }
        other => panic!("{other:?}"),
    }

    // POSITIVE CONTROL: asking again gives a request the owner can approve.
    drop((ctx, service));
    let (service, console) = owner_run_service(tmp.path());
    let again = service
        .create_elevation_request(&a.client_id, vec![Scope::Spend])
        .unwrap();
    assert_eq!(service.elevation_status(&again.op_id), pairing::ElevationStatus::Pending);
    service
        .grant_elevation(&again.op_id, &console.owner_code(&again.op_id), konsensus_api::spend_budget::GrantTerms::new(1_000))
        .unwrap();
    assert_eq!(service.elevation_status(&again.op_id), pairing::ElevationStatus::Granted);
}

#[test]
fn the_owner_code_reaches_only_the_owner_terminal() {
    let tmp = tempfile::tempdir().unwrap();
    let (service, console) = owner_run_service(tmp.path());
    let a = pair(&service, &client_key(1), "client A");
    let op = service
        .create_elevation_request(&a.client_id, vec![Scope::Spend])
        .unwrap();
    let code = console.owner_code(&op.op_id);
    let bare = code.replace('-', "");

    let ctx = ctx(&service, tmp.path());
    let replies = [
        control::handle(&ctx, ControlRequest::Status),
        control::handle(&ctx, ControlRequest::Describe { op_id: op.op_id.clone() }),
    ];
    for reply in &replies {
        let json = serde_json::to_string(reply).unwrap();
        assert!(!json.contains(&code) && !json.contains(&bare), "{json}");
    }
    let on_disk = all_files_text(tmp.path());
    assert!(!on_disk.contains(&code) && !on_disk.contains(&bare));
}

#[test]
fn owner_command_names_the_absolute_config_quoted_for_a_shell() {
    let tmp = tempfile::tempdir().unwrap();
    let console = OwnerConsole::default();
    let service = PairingService::open(tmp.path(), current_fingerprint(), true)
        .unwrap()
        .with_owner_console(Box::new(console.clone()))
        .without_stdout_code()
        .with_owner_config("/Users/o'neil/My Node/konsensus.toml".into());
    assert_eq!(
        service.owner_grant_command("ab12"),
        r"konsensus grant --op ab12 --config '/Users/o'\''neil/My Node/konsensus.toml'"
    );
    let plain = PairingService::open(tmp.path(), current_fingerprint(), true)
        .unwrap()
        .with_owner_config("/srv/bitsov/konsensus.toml".into());
    assert_eq!(
        plain.owner_grant_command("ab12"),
        "konsensus grant --op ab12 --config /srv/bitsov/konsensus.toml"
    );
    // Never a path that could rewrite what the owner sees.
    let hostile = PairingService::open(tmp.path(), current_fingerprint(), true)
        .unwrap()
        .with_owner_config("/tmp/a\u{202E}lmot.toml".into());
    assert_eq!(hostile.owner_grant_command("ab12"), "konsensus grant --op ab12");

    // The owner terminal prints the same command next to the code.
    let a = pair(&service, &client_key(1), "client A");
    let op = service
        .create_elevation_request(&a.client_id, vec![Scope::Spend])
        .unwrap();
    assert!(console
        .text()
        .contains(&format!("To approve, run: {}", service.owner_grant_command(&op.op_id))));
}

#[test]
fn replacement_still_requires_the_full_console_line() {
    let tmp = tempfile::tempdir().unwrap();
    let (service, console) = owner_run_service(tmp.path());
    let a = pair(&service, &client_key(1), "client A");
    let approval = service
        .create_replacement_request(&a.client_id, &current_fingerprint(), REPLACEMENT_MNEMONIC)
        .unwrap();
    // No short code is ever printed for an identity replacement.
    assert!(!console.text().contains("type this code when it asks"));
    let err = service
        .approve_replacement(&approval.op_id, "AAAA-AAAA")
        .unwrap_err();
    assert!(matches!(err, PairingError::ConfirmationMismatch), "{err}");
}
