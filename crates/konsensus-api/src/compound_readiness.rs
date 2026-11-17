//! Read-only, versioned observations for a named contact journey.
//!
//! This evaluator accepts observations only; it cannot enroll, reserve, send,
//! or authorize. Consumers supply the binding from their authenticated transport
//! and compare their current context again before publishing an outstanding read.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub const MAX_ENVELOPE_BYTES: usize = 32_768;
pub const GROUPS: &[&str] = &[
    "owner_setup",
    "authority_consent",
    "receiving_reply",
    "aggregate_history",
    "aggregate_enforcement",
    "exact_hold",
    "durable_compound",
    "introduction_sequencing",
    "callee_signals",
    "lifecycle_recovery",
    "platform_connection",
];
const DECISIONS: &[&str] = &[
    "profile_selection",
    "aggregate_policy",
    "exact_hold_consent",
    "callee_terms",
    "custody_setup",
    "approval_intent",
    "platform_scope",
];
const CHECKS: &[&str] = &[
    "owner_route",
    "custody",
    "device_key",
    "device_approvals",
    "enrollment",
    "independent_approval",
    "peer_trust",
    "recipient_admission",
    "reply_authority",
    "reverse_admission",
    "sender_receiving",
    "chain",
    "payment",
    "liquidity",
    "exact_hold_consent",
    "terms_current",
    "microphone",
    "callee_authority",
    "live_ring",
    "stage_authority",
];
const STAGES: &[&str] = &["setup", "introduction", "reply", "call", "answer"];

macro_rules! vocabulary {
    ($name:ident { $($variant:ident),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name { $($variant),+ }
    };
}
vocabulary!(Stage {
    Setup,
    Introduction,
    Reply,
    Call,
    Answer
});

impl Stage {
    fn label(self) -> &'static str {
        match self {
            Self::Setup => "setup",
            Self::Introduction => "introduction",
            Self::Reply => "reply",
            Self::Call => "call",
            Self::Answer => "answer",
        }
    }
}

vocabulary!(Support {
    Supported,
    Unsupported,
    Unknown
});
vocabulary!(ReadinessState {
    Ready,
    NeedsOwner,
    Pending,
    Refused,
    Unknown
});
vocabulary!(Role {
    Caller,
    Callee,
    Owner,
    Reader
});
vocabulary!(OperationState {
    Active,
    Cancelled,
    Closed,
    Unknown
});
vocabulary!(History {
    Complete,
    Partial,
    Unknown
});
vocabulary!(OutcomeState {
    NotAttempted,
    Confirmed,
    Pending,
    Refused,
    Unknown
});
vocabulary!(Reason {
    Satisfied,
    InvalidEnvelope,
    UnsupportedSchema,
    UnknownRequiredExtension,
    UnsupportedProfile,
    MissingDependency,
    OwnerDecisionRequired,
    BindingChanged,
    NetworkUnverified,
    FreshnessUnknown,
    PrerequisiteUnknown,
    OwnerRouteUnavailable,
    CustodyUnverified,
    SettingOff,
    Revoked,
    IndependentOwnerRequired,
    ConsentRequired,
    AdmissionPending,
    AdmissionRefused,
    ReplyAuthorityMissing,
    PeerUnverified,
    ComponentUnavailable,
    ReconciliationRequired,
    IntroductionUnconfirmed,
    SeparateConfirmationRequired,
    TermsChanged,
    Expired,
    TerminalOperation,
    StageAlreadyResolved,
    ActorMismatch,
});
vocabulary!(NextAction {
    None,
    CheckCompatibility,
    Reconnect,
    Refresh,
    RequestOwner,
    Reconcile,
    ReviewTerms,
    Wait
});

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Schema {
    pub name: String,
    pub major: u16,
    pub minor: u16,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub name: String,
    pub revision: u16,
    pub finalized: bool,
    #[serde(deserialize_with = "unique_map")]
    pub manifest: BTreeMap<String, u16>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeBinding {
    pub node_id: String,
    pub build: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionBinding {
    pub generation: u64,
    pub request_id: String,
    pub client_context: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Context {
    pub requested_stage: Stage,
    pub operation_id: Option<String>,
    pub role: Role,
    pub recipient: Option<String>,
    pub policy_revision: String,
    pub enrollment_epoch: u64,
    pub terms_revision: Option<String>,
    pub operation: OperationState,
    pub warm: bool,
    pub warm_provenance: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capability {
    pub revision: u16,
    pub support: Support,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub valid_for_ms: Option<u64>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Prerequisite {
    pub state: ReadinessState,
    pub reason: Reason,
    pub expires_at_ms: Option<u64>,
    pub parent_expires_at_ms: Option<u64>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Accounting {
    pub history: History,
    pub unresolved_obligations: bool,
    pub policy_revision: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Outcome {
    pub state: OutcomeState,
    pub reference: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub schema: Schema,
    pub required_extensions: Vec<String>,
    pub profile: Profile,
    pub node_binding: NodeBinding,
    pub connection_binding: ConnectionBinding,
    pub network: Option<String>,
    #[serde(deserialize_with = "unique_map")]
    pub capabilities: BTreeMap<String, Capability>,
    #[serde(deserialize_with = "unique_map")]
    pub decisions: BTreeMap<String, bool>,
    pub observation: Observation,
    pub context: Context,
    #[serde(deserialize_with = "unique_map")]
    pub prerequisites: BTreeMap<String, Prerequisite>,
    pub authority_refs: Vec<String>,
    pub accounting: Accounting,
    #[serde(deserialize_with = "unique_map")]
    pub stage_result_refs: BTreeMap<String, Outcome>,
    /// Only this explicitly non-authoritative namespace accepts additive fields.
    #[serde(deserialize_with = "unique_map")]
    pub optional_diagnostics: BTreeMap<String, serde_json::Value>,
}

/// Receipt-local time and current binding, supplied by the authenticated caller.
/// No product release string, wall-clock timestamp or response claim proves trust.
#[derive(Clone, Debug)]
pub struct ReadContext {
    pub authenticated_node_id: String,
    pub connection_binding: ConnectionBinding,
    pub context: Context,
    pub receipt_age_ms: Option<u64>,
    pub now_ms: Option<u64>,
    pub clock_valid: bool,
}
#[derive(Clone, Debug, Serialize)]
pub struct Blocker {
    pub stage: Option<&'static str>,
    pub reason: Reason,
    pub dependency: Option<&'static str>,
    pub next_action: NextAction,
}
#[derive(Clone, Debug, Serialize)]
pub struct StageReadiness {
    pub state: ReadinessState,
    pub can_prepare: bool,
    pub can_request_approval: bool,
    pub can_attempt_stage: bool,
}
#[derive(Clone, Debug, Serialize)]
pub struct Readiness {
    pub implemented: bool,
    pub authorizes_dispatch: bool,
    pub revalidation_required: bool,
    pub stages: BTreeMap<&'static str, StageReadiness>,
    pub blockers: Vec<Blocker>,
    pub context: Option<Context>,
    pub accounting: Option<Accounting>,
    pub stage_result_refs: BTreeMap<String, Outcome>,
}

fn blocker(
    stage: Option<&'static str>,
    reason: Reason,
    dependency: Option<&'static str>,
) -> Blocker {
    let next_action = match reason {
        Reason::Satisfied => NextAction::None,
        Reason::BindingChanged | Reason::NetworkUnverified => NextAction::Reconnect,
        Reason::FreshnessUnknown | Reason::Expired => NextAction::Refresh,
        Reason::OwnerDecisionRequired
        | Reason::SettingOff
        | Reason::ConsentRequired
        | Reason::OwnerRouteUnavailable
        | Reason::IndependentOwnerRequired
        | Reason::ReplyAuthorityMissing
        | Reason::CustodyUnverified => NextAction::RequestOwner,
        Reason::ReconciliationRequired
        | Reason::IntroductionUnconfirmed
        | Reason::TerminalOperation
        | Reason::StageAlreadyResolved => NextAction::Reconcile,
        Reason::SeparateConfirmationRequired | Reason::TermsChanged => NextAction::ReviewTerms,
        Reason::AdmissionPending => NextAction::Wait,
        _ => NextAction::CheckCompatibility,
    };
    Blocker {
        stage,
        reason,
        dependency,
        next_action,
    }
}
fn unavailable(reason: Reason) -> Readiness {
    Readiness {
        implemented: false,
        authorizes_dispatch: false,
        revalidation_required: true,
        stages: STAGES
            .iter()
            .map(|&s| {
                (
                    s,
                    StageReadiness {
                        state: ReadinessState::Unknown,
                        can_prepare: false,
                        can_request_approval: false,
                        can_attempt_stage: false,
                    },
                )
            })
            .collect(),
        blockers: vec![blocker(None, reason, None)],
        context: None,
        accounting: None,
        stage_result_refs: BTreeMap::new(),
    }
}

/// Bounded decoding; missing or unknown mandatory semantics always refuse.
/// Readiness is never consumed by an authority or dispatch boundary.
pub fn evaluate(bytes: &[u8], current: &ReadContext) -> Readiness {
    if bytes.len() > MAX_ENVELOPE_BYTES || !named_object_encoding(bytes) {
        return unavailable(Reason::InvalidEnvelope);
    }
    let Ok(envelope) = serde_json::from_slice::<Envelope>(bytes) else {
        return unavailable(Reason::InvalidEnvelope);
    };
    if !well_formed(&envelope) {
        return unavailable(Reason::InvalidEnvelope);
    }
    if envelope.node_binding.node_id != current.authenticated_node_id
        || envelope.connection_binding != current.connection_binding
        || envelope.context != current.context
    {
        return unavailable(Reason::BindingChanged);
    }
    let mut result = unavailable(Reason::InvalidEnvelope);
    result.blockers.clear();
    result.context = Some(envelope.context.clone());
    result.accounting = Some(envelope.accounting.clone());
    result.stage_result_refs = envelope.stage_result_refs.clone();
    let schema_ok = envelope.schema.name == "compound_readiness" && envelope.schema.major == 1;
    let profile_ok = envelope.profile.name == "named_contact_compound"
        && envelope.profile.revision == 1
        && envelope.profile.finalized
        && envelope.profile.manifest.len() == GROUPS.len()
        && GROUPS
            .iter()
            .all(|g| envelope.profile.manifest.get(*g) == Some(&1));
    let missing: Vec<_> = GROUPS
        .iter()
        .copied()
        .filter(|g| {
            !envelope
                .capabilities
                .get(*g)
                .is_some_and(|c| c.revision == 1 && c.support == Support::Supported)
        })
        .collect();
    result.implemented =
        schema_ok && profile_ok && envelope.required_extensions.is_empty() && missing.is_empty();
    let mut common = Vec::new();
    if !schema_ok {
        common.push(Reason::UnsupportedSchema);
    }
    if !profile_ok {
        common.push(Reason::UnsupportedProfile);
    }
    if !envelope.required_extensions.is_empty() {
        common.push(Reason::UnknownRequiredExtension);
    }
    if envelope.network.as_deref() != Some("signet") {
        common.push(Reason::NetworkUnverified);
    }
    let fresh = current.clock_valid
        && current.now_ms.is_some()
        && current
            .receipt_age_ms
            .zip(envelope.observation.valid_for_ms)
            .is_some_and(|(age, validity)| age < validity);
    if !fresh {
        common.push(Reason::FreshnessUnknown);
    }
    for &reason in &common {
        result.blockers.push(blocker(None, reason, None));
    }
    for &group in &missing {
        result
            .blockers
            .push(blocker(None, Reason::MissingDependency, Some(group)));
    }
    for &decision in DECISIONS {
        if envelope.decisions.get(decision) != Some(&true) {
            result
                .blockers
                .push(blocker(None, Reason::OwnerDecisionRequired, Some(decision)));
        }
    }
    for &stage in STAGES {
        let mut failures = Vec::new();
        for &reason in &common {
            failures.push((ReadinessState::Unknown, blocker(Some(stage), reason, None)));
        }
        for &group in &missing {
            if stage != "setup" || ["owner_setup", "platform_connection"].contains(&group) {
                failures.push((
                    ReadinessState::Unknown,
                    blocker(Some(stage), Reason::MissingDependency, Some(group)),
                ));
            }
        }
        for &decision in DECISIONS {
            if (stage != "setup"
                || ["custody_setup", "approval_intent", "platform_scope"].contains(&decision))
                && envelope.decisions.get(decision) != Some(&true)
            {
                failures.push((
                    ReadinessState::NeedsOwner,
                    blocker(Some(stage), Reason::OwnerDecisionRequired, Some(decision)),
                ));
            }
        }
        let role_ok = match stage {
            "introduction" | "call" => envelope.context.role == Role::Caller,
            "reply" | "answer" => envelope.context.role == Role::Callee,
            _ => true,
        };
        if !role_ok {
            failures.push((
                ReadinessState::Refused,
                blocker(Some(stage), Reason::ActorMismatch, None),
            ));
        }
        for &check in stage_checks(stage) {
            match envelope.prerequisites.get(check) {
                Some(p) => {
                    if p.state == ReadinessState::Ready
                        && ["enrollment", "live_ring", "callee_authority"].contains(&check)
                        && p.expires_at_ms.is_none()
                    {
                        failures.push((
                            ReadinessState::Unknown,
                            blocker(Some(stage), Reason::FreshnessUnknown, Some(check)),
                        ));
                        continue;
                    }
                    if let Some(now) = current.now_ms {
                        if p.expires_at_ms
                            .into_iter()
                            .chain(p.parent_expires_at_ms)
                            .any(|expiry| now >= expiry)
                        {
                            failures.push((
                                ReadinessState::Refused,
                                blocker(Some(stage), Reason::Expired, Some(check)),
                            ));
                            continue;
                        }
                    }
                    if p.state != ReadinessState::Ready {
                        failures.push((p.state, blocker(Some(stage), p.reason, Some(check))));
                    }
                }
                None => failures.push((
                    ReadinessState::Unknown,
                    blocker(Some(stage), Reason::PrerequisiteUnknown, Some(check)),
                )),
            }
        }
        if stage != "setup" {
            if envelope
                .context
                .recipient
                .as_deref()
                .is_none_or(str::is_empty)
            {
                failures.push((
                    ReadinessState::Unknown,
                    blocker(Some(stage), Reason::PrerequisiteUnknown, None),
                ));
            }
            if envelope
                .context
                .terms_revision
                .as_deref()
                .is_none_or(str::is_empty)
            {
                failures.push((
                    ReadinessState::Unknown,
                    blocker(
                        Some(stage),
                        Reason::PrerequisiteUnknown,
                        Some("terms_current"),
                    ),
                ));
            }
            match envelope.context.operation {
                OperationState::Cancelled | OperationState::Closed => failures.push((
                    ReadinessState::Refused,
                    blocker(Some(stage), Reason::TerminalOperation, None),
                )),
                OperationState::Unknown => failures.push((
                    ReadinessState::Unknown,
                    blocker(Some(stage), Reason::PrerequisiteUnknown, None),
                )),
                OperationState::Active => {}
            }
            if envelope.accounting.history != History::Complete
                || envelope.accounting.unresolved_obligations
                || envelope.context.policy_revision.is_empty()
                || envelope.accounting.policy_revision.as_ref()
                    != Some(&envelope.context.policy_revision)
            {
                failures.push((
                    ReadinessState::Unknown,
                    blocker(Some(stage), Reason::ReconciliationRequired, None),
                ));
            }
        }
        if stage == "call"
            && !envelope
                .stage_result_refs
                .get("introduction")
                .is_some_and(|r| r.state == OutcomeState::Confirmed && r.reference.is_some())
        {
            failures.push((
                ReadinessState::Pending,
                blocker(Some(stage), Reason::IntroductionUnconfirmed, None),
            ));
        }
        if ["introduction", "reply"].contains(&stage) {
            if let Some(outcome) = envelope.stage_result_refs.get(stage) {
                let failure = match outcome.state {
                    OutcomeState::NotAttempted => None,
                    OutcomeState::Pending => {
                        Some((ReadinessState::Pending, Reason::ReconciliationRequired))
                    }
                    OutcomeState::Unknown => {
                        Some((ReadinessState::Unknown, Reason::ReconciliationRequired))
                    }
                    OutcomeState::Confirmed | OutcomeState::Refused => {
                        Some((ReadinessState::Refused, Reason::StageAlreadyResolved))
                    }
                };
                if let Some((state, reason)) = failure {
                    failures.push((state, blocker(Some(stage), reason, None)));
                }
            }
        }
        let can_prepare = failures.is_empty();
        let authority = envelope.prerequisites.get("stage_authority");
        let can_attempt_stage = stage != "setup"
            && can_prepare
            && envelope.context.requested_stage.label() == stage
            && envelope.context.operation_id.is_some()
            && !envelope.authority_refs.is_empty()
            && envelope
                .context
                .terms_revision
                .as_deref()
                .is_some_and(|s| !s.is_empty())
            && authority.is_some_and(|p| {
                p.state == ReadinessState::Ready
                    && p.expires_at_ms
                        .zip(current.now_ms)
                        .is_some_and(|(expiry, now)| now < expiry)
                    && p.parent_expires_at_ms
                        .zip(current.now_ms)
                        .is_none_or(|(expiry, now)| now < expiry)
            });
        if stage != "setup" && can_prepare && !can_attempt_stage {
            let (state, reason) = authority
                .filter(|p| p.state != ReadinessState::Ready)
                .map(|p| (p.state, p.reason))
                .unwrap_or((ReadinessState::NeedsOwner, Reason::ConsentRequired));
            failures.push((state, blocker(Some(stage), reason, Some("stage_authority"))));
        }
        let state = [
            ReadinessState::Refused,
            ReadinessState::Unknown,
            ReadinessState::Pending,
            ReadinessState::NeedsOwner,
        ]
        .into_iter()
        .find(|s| failures.iter().any(|(state, _)| s == state))
        .unwrap_or(ReadinessState::Ready);
        result.stages.insert(
            stage,
            StageReadiness {
                state,
                can_prepare,
                can_request_approval: can_prepare
                    && envelope.context.requested_stage.label() == stage
                    && (stage == "setup" || envelope.context.operation_id.is_some()),
                can_attempt_stage,
            },
        );
        result.blockers.extend(failures.into_iter().map(|(_, b)| b));
    }
    result
}

fn well_formed(e: &Envelope) -> bool {
    let bounded = |s: &str| !s.is_empty() && s.len() <= 128;
    bounded(&e.node_binding.node_id)
        && bounded(&e.connection_binding.client_context)
        && valid_request_id(&e.connection_binding.request_id)
        && e.capabilities.keys().all(|k| GROUPS.contains(&k.as_str()))
        && e.decisions.keys().all(|k| DECISIONS.contains(&k.as_str()))
        && e.prerequisites.iter().all(|(k, p)| {
            CHECKS.contains(&k.as_str())
                && ((p.state == ReadinessState::Ready) == (p.reason == Reason::Satisfied))
        })
        && e.stage_result_refs
            .keys()
            .all(|k| ["introduction", "reply", "receiving"].contains(&k.as_str()))
        && ["introduction", "reply", "receiving"]
            .iter()
            .all(|k| e.stage_result_refs.contains_key(*k))
        && e.stage_result_refs.values().all(|r| {
            r.reference.as_deref().is_none_or(bounded)
                && (r.state != OutcomeState::Confirmed || r.reference.is_some())
                && (r.state != OutcomeState::NotAttempted || r.reference.is_none())
        })
        && e.authority_refs.iter().all(|r| bounded(r))
        && e.context.operation_id.as_deref().is_none_or(bounded)
        && (!e.context.warm || e.context.warm_provenance.as_deref().is_some_and(bounded))
}

fn stage_checks(stage: &str) -> &'static [&'static str] {
    match stage {
        "setup" => &["owner_route", "custody", "device_key"],
        "introduction" => &[
            "owner_route",
            "custody",
            "device_key",
            "device_approvals",
            "enrollment",
            "independent_approval",
            "peer_trust",
            "recipient_admission",
            "terms_current",
            "chain",
            "payment",
            "liquidity",
        ],
        "reply" => &[
            "owner_route",
            "custody",
            "device_key",
            "device_approvals",
            "enrollment",
            "independent_approval",
            "peer_trust",
            "reply_authority",
            "reverse_admission",
            "sender_receiving",
            "terms_current",
            "chain",
            "payment",
            "liquidity",
        ],
        "call" => &[
            "owner_route",
            "custody",
            "device_key",
            "device_approvals",
            "enrollment",
            "independent_approval",
            "peer_trust",
            "recipient_admission",
            "chain",
            "payment",
            "liquidity",
            "exact_hold_consent",
            "terms_current",
            "microphone",
        ],
        "answer" => &[
            "owner_route",
            "custody",
            "device_key",
            "device_approvals",
            "enrollment",
            "independent_approval",
            "peer_trust",
            "chain",
            "payment",
            "liquidity",
            "callee_authority",
            "live_ring",
            "terms_current",
            "microphone",
        ],
        _ => &[],
    }
}

pub fn valid_request_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
}

#[derive(Serialize)]
pub struct Discovery {
    pub envelope: Envelope,
    pub readiness: Readiness,
}

/// Facts available on this authenticated status read, without new storage reads.
pub struct RuntimeInputs {
    pub node_id: String,
    pub network: Option<String>,
    pub connection: ConnectionBinding,
    pub role: Role,
    pub enrollment_epoch: u64,
    pub device_approvals: Option<bool>,
    pub chain_ready: bool,
    pub payment_ready: bool,
}

pub fn runtime_discovery(input: RuntimeInputs) -> Discovery {
    let mut prerequisites: BTreeMap<_, _> = CHECKS
        .iter()
        .map(|&check| {
            (
                check.into(),
                Prerequisite {
                    state: ReadinessState::Unknown,
                    reason: Reason::PrerequisiteUnknown,
                    expires_at_ms: None,
                    parent_expires_at_ms: None,
                },
            )
        })
        .collect();
    for (check, ready) in [
        ("chain", Some(input.chain_ready)),
        ("payment", Some(input.payment_ready)),
        ("device_approvals", input.device_approvals),
    ] {
        if let Some(ready) = ready {
            prerequisites.insert(
                check.into(),
                Prerequisite {
                    state: if ready {
                        ReadinessState::Ready
                    } else {
                        ReadinessState::NeedsOwner
                    },
                    reason: if ready {
                        Reason::Satisfied
                    } else if check == "device_approvals" {
                        Reason::SettingOff
                    } else {
                        Reason::ComponentUnavailable
                    },
                    expires_at_ms: None,
                    parent_expires_at_ms: None,
                },
            );
        }
    }
    let envelope = Envelope {
        schema: Schema {
            name: "compound_readiness".into(),
            major: 1,
            minor: 0,
        },
        required_extensions: vec![],
        profile: Profile {
            name: "named_contact_compound".into(),
            revision: 1,
            finalized: false,
            manifest: GROUPS.iter().map(|&g| (g.into(), 1)).collect(),
        },
        node_binding: NodeBinding {
            node_id: input.node_id.clone(),
            build: env!("CARGO_PKG_VERSION").into(),
        },
        connection_binding: input.connection,
        network: input.network,
        capabilities: GROUPS
            .iter()
            .map(|&g| {
                (
                    g.into(),
                    Capability {
                        revision: 1,
                        support: Support::Unsupported,
                    },
                )
            })
            .collect(),
        decisions: DECISIONS.iter().map(|&d| (d.into(), false)).collect(),
        observation: Observation { valid_for_ms: None },
        context: Context {
            requested_stage: Stage::Setup,
            operation_id: None,
            role: input.role,
            recipient: None,
            policy_revision: String::new(),
            enrollment_epoch: input.enrollment_epoch,
            terms_revision: None,
            operation: OperationState::Unknown,
            warm: false,
            warm_provenance: None,
        },
        prerequisites,
        authority_refs: vec![],
        accounting: Accounting {
            history: History::Unknown,
            unresolved_obligations: true,
            policy_revision: None,
        },
        stage_result_refs: ["introduction", "reply", "receiving"]
            .iter()
            .map(|&s| {
                (
                    s.into(),
                    Outcome {
                        state: OutcomeState::Unknown,
                        reference: None,
                    },
                )
            })
            .collect(),
        optional_diagnostics: BTreeMap::new(),
    };
    let current = ReadContext {
        authenticated_node_id: input.node_id,
        connection_binding: envelope.connection_binding.clone(),
        context: envelope.context.clone(),
        receipt_age_ms: Some(0),
        now_ms: None,
        clock_valid: false,
    };
    let readiness = match serde_json::to_vec(&envelope) {
        Ok(bytes) => evaluate(&bytes, &current),
        Err(_) => unavailable(Reason::InvalidEnvelope),
    };
    Discovery {
        envelope,
        readiness,
    }
}

fn unique_map<'de, D, V>(deserializer: D) -> Result<BTreeMap<String, V>, D::Error>
where
    D: serde::Deserializer<'de>,
    V: Deserialize<'de>,
{
    struct Unique<V>(std::marker::PhantomData<V>);
    impl<'de, V: Deserialize<'de>> serde::de::Visitor<'de> for Unique<V> {
        type Value = BTreeMap<String, V>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("an object with unique keys")
        }
        fn visit_map<M: serde::de::MapAccess<'de>>(
            self,
            mut map: M,
        ) -> Result<Self::Value, M::Error> {
            let mut entries = BTreeMap::new();
            while let Some((key, value)) = map.next_entry::<String, V>()? {
                if entries.insert(key, value).is_some() {
                    return Err(serde::de::Error::custom("duplicate object key"));
                }
            }
            Ok(entries)
        }
    }
    deserializer.deserialize_map(Unique(std::marker::PhantomData))
}

fn named_object_encoding(bytes: &[u8]) -> bool {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return false;
    };
    let Some(fields) = value.as_object() else {
        return false;
    };
    [
        "schema",
        "profile",
        "node_binding",
        "connection_binding",
        "observation",
        "context",
        "accounting",
    ]
    .iter()
    .all(|key| fields.get(*key).is_some_and(serde_json::Value::is_object))
        && ["capabilities", "prerequisites", "stage_result_refs"]
            .iter()
            .all(|key| {
                fields
                    .get(*key)
                    .and_then(serde_json::Value::as_object)
                    .is_some_and(|entries| entries.values().all(serde_json::Value::is_object))
            })
}
