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
    let grant = service.grant_elevation(&op.op_id, &phrase).unwrap();
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

    let err = sidecar.grant_elevation(&op.op_id, &phrase).unwrap_err();
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
    let err = aged2.grant_elevation(&op.op_id, &phrase).unwrap_err();
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
