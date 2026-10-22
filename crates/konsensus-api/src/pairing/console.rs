//! Owner-console enrollment controls. Preview and commit share the pairing lock.
use super::{device, Inner, PairingError, PairingService};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashSet, VecDeque};

/// Exact operator choices; bound into the confirmation digest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RevokeOptions {
    pub root: String,
    pub cascade: bool,
    pub with_pairing: bool,
    pub keep: Vec<String>,
    pub allow_zero_owner: bool,
}

/// Public provenance entry; never carries a signature or key material.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevokeKey {
    pub key_id: String,
    pub client_id: String,
    pub name: String,
    pub enrolled_by: String,
}

/// Reviewable effect, recomputed on confirmation to detect concurrent changes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevokePlan {
    pub keys: Vec<RevokeKey>,
    pub descendants: Vec<RevokeKey>,
    pub pairings: Vec<String>,
    pub owner_device_count: usize,
    pub confirmation: String,
}

/// Public-only console status for v2 enrollment.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnrollmentStatus {
    pub provisional: Vec<ProvisionalSummary>,
    pub words: std::collections::BTreeMap<String, String>,
}

/// Provisional deadline, with no ticket commitment or code.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProvisionalSummary {
    pub client_id: String,
    pub expires_at: i64,
}

fn provenance_parent(value: &str) -> Option<&str> {
    value
        .strip_prefix("second_device:")
        .or_else(|| value.strip_prefix("device:"))
}

/// Audit legacy/untrusted records with the device and node display-name
/// exclusions and their 64-character limit. Keep raw names in the plan so
/// confirmation still detects any change to the stored record.
fn audit_device_name(name: &str) -> String {
    let visible: String = name
        .chars()
        .filter(|c| {
            !c.is_control()
                && !super::invisible_format(*c)
                // NodeDisplayConfig also excludes deprecated formatting,
                // interlinear annotation controls, and invisible Unicode tags.
                && !matches!(c, '\u{206A}'..='\u{206F}' | '\u{FFF9}'..='\u{FFFB}' | '\u{E0020}'..='\u{E007F}')
        })
        .collect();
    let name: String = visible.trim().chars().take(64).collect();
    if name.is_empty() {
        "unnamed device".into()
    } else {
        name
    }
}

impl PairingService {
    fn require_console_enrollment(&self) -> Result<(), PairingError> {
        if !self.owner_control_enabled || !self.second_device_enrollment {
            return Err(PairingError::OwnerChannelUnavailable);
        }
        Ok(())
    }

    /// Gate a console ticket against the running process, not stale disk config.
    pub fn console_second_ticket_ready(&self) -> Result<(), PairingError> {
        self.second_device_available()?;
        if self.owner_device_count() == 0 {
            return Err(PairingError::NotGrantable("no_owner_device".into()));
        }
        Ok(())
    }

    /// Only confirmed, live v2 operations expose words on the owner console.
    pub fn console_enrollment_status(&self) -> EnrollmentStatus {
        if !self.second_device_enrollment {
            return EnrollmentStatus::default();
        }
        let inner = self.lock();
        let mut provisional: Vec<_> = inner
            .second_device
            .provisional
            .iter()
            .map(|(id, p)| ProvisionalSummary {
                client_id: id.clone(),
                expires_at: p.expires_at,
            })
            .collect();
        provisional.sort_by(|a, b| a.client_id.cmp(&b.client_id));
        let words = inner
            .file
            .pending_device_keys
            .iter()
            .filter(|p| {
                p.sas_version == Some(2)
                    && p.expires_at > chrono::Utc::now().timestamp()
                    && p.require_sas_confirmed().is_ok()
                    && self.provisional_locked(&inner, &p.client_id).is_ok()
            })
            .filter_map(|p| {
                p.sas
                    .as_ref()
                    .map(|s| (p.op_id.clone(), crate::sas::words(&s.digest).join(" ")))
            })
            .collect();
        EnrollmentStatus { provisional, words }
    }

    /// Owner rejection cancels the pairing immediately, without a mismatch charge.
    pub fn console_cancel_second_device(&self, op_id: &str) -> Result<(), PairingError> {
        self.require_console_enrollment()?;
        let mut inner = self.lock();
        let op = inner
            .file
            .pending_device_keys
            .iter()
            .find(|p| p.op_id == op_id && p.sas_version == Some(2))
            .cloned()
            .ok_or(PairingError::UnknownOperation)?;
        if !inner.second_device.provisional.contains_key(&op.client_id) {
            return Err(PairingError::UnknownOperation);
        }
        let file = inner.file.clone();
        let state = inner.second_device.clone();
        let cancelled = inner.cancelled_ops.clone();
        Self::remove_provisional_locked(&mut inner, &op.client_id);
        if let Err(e) = self.persist(&mut inner.file) {
            inner.file = file;
            inner.second_device = state;
            inner.cancelled_ops = cancelled;
            return Err(e);
        }
        Self::commit_enrollment_cleanup(&mut inner);
        self.notify_authority_change();
        self.enrollment_event(
            "pair.second_device_rejected",
            &op.client_id,
            serde_json::json!({"by":"console"}),
        );
        Ok(())
    }

    /// Reset both versions' counters on the owner control socket.
    pub fn console_reset_sas(&self) -> Result<(), PairingError> {
        self.require_console_enrollment()?;
        self.reset_sas_failures();
        Ok(())
    }

    fn console_owner_count(
        &self,
        inner: &Inner,
        removed: &HashSet<String>,
        clients: &BTreeSet<String>,
    ) -> usize {
        inner
            .file
            .device_keys
            .iter()
            .filter(|k| {
                !removed.contains(&k.key_id)
                    && !clients.contains(&k.client_id)
                    && device::parse_public_key(&k.public_key)
                        .is_ok_and(|raw| device::key_id_for(&raw) == k.key_id)
                    && self
                        .intent_key(inner, &k.client_id, k.epoch, &k.key_id)
                        .is_ok()
            })
            .map(|k| &k.key_id)
            .collect::<HashSet<_>>()
            .len()
    }

    /// Breadth-first, cycle-safe provenance walk, including a missing/revoked root.
    /// Confirmation binds options, affected keys, pairings and remaining owner count.
    pub fn console_revoke_devices(
        &self,
        options: &RevokeOptions,
        confirmation: Option<&str>,
    ) -> Result<RevokePlan, PairingError> {
        self.require_console_enrollment()?;
        if options.root.is_empty() || (!options.cascade && !options.keep.is_empty()) {
            return Err(PairingError::NotGrantable(
                "invalid revocation options".into(),
            ));
        }
        let mut inner = self.lock();
        let mut queue = VecDeque::from([options.root.clone()]);
        let mut visited = HashSet::new();
        let mut chain = Vec::new();
        while let Some(id) = queue.pop_front() {
            if !visited.insert(id.clone()) {
                continue;
            }
            if let Some(key) = inner.file.device_keys.iter().find(|k| k.key_id == id) {
                // Removing this pairing also removes independently enrolled sibling
                // keys. Walk their approvals too, to a fixpoint, before previewing.
                if options.cascade && !options.keep.contains(&id) {
                    queue.extend(
                        inner
                            .file
                            .device_keys
                            .iter()
                            .filter(|sibling| sibling.client_id == key.client_id)
                            .map(|sibling| sibling.key_id.clone()),
                    );
                }
                chain.push(RevokeKey {
                    key_id: id.clone(),
                    client_id: key.client_id.clone(),
                    name: key.name.clone(),
                    enrolled_by: key.enrolled_by.clone(),
                });
            }
            for key in &inner.file.device_keys {
                if provenance_parent(&key.enrolled_by) == Some(id.as_str()) {
                    queue.push_back(key.key_id.clone());
                }
            }
        }
        let descendants = chain
            .iter()
            .filter(|k| k.key_id != options.root)
            .cloned()
            .collect();
        let mut keys: Vec<_> = chain
            .into_iter()
            .filter(|k| {
                (options.cascade || k.key_id == options.root) && !options.keep.contains(&k.key_id)
            })
            .collect();
        if keys.is_empty() {
            return Err(PairingError::UnknownOperation);
        }
        let pairings: BTreeSet<_> = if options.with_pairing || options.cascade {
            keys.iter().map(|k| k.client_id.clone()).collect()
        } else {
            BTreeSet::new()
        };
        // Pairing removal necessarily retires all of its keys. Never silently remove a kept key.
        for key in inner
            .file
            .device_keys
            .iter()
            .filter(|k| pairings.contains(&k.client_id))
        {
            if options.keep.contains(&key.key_id) {
                return Err(PairingError::NotGrantable(
                    "a kept key shares a pairing being revoked; keep every key on that pairing"
                        .into(),
                ));
            }
            if !keys.iter().any(|k| k.key_id == key.key_id) {
                keys.push(RevokeKey {
                    key_id: key.key_id.clone(),
                    client_id: key.client_id.clone(),
                    name: key.name.clone(),
                    enrolled_by: key.enrolled_by.clone(),
                });
            }
        }
        let removed: HashSet<_> = keys.iter().map(|k| k.key_id.clone()).collect();
        let mut plan = RevokePlan {
            keys,
            descendants,
            pairings: pairings.iter().cloned().collect(),
            owner_device_count: self.console_owner_count(&inner, &removed, &pairings),
            confirmation: String::new(),
        };
        let bytes = serde_json::to_vec(&(options, &plan)).expect("serializable revocation plan");
        plan.confirmation = blake3::hash(&bytes).to_hex().to_string();
        if let Some(confirmation) = confirmation {
            if confirmation != plan.confirmation {
                return Err(PairingError::NotGrantable(
                    "revocation changed; review a fresh preview".into(),
                ));
            }
            if plan.owner_device_count == 0 && !options.allow_zero_owner {
                return Err(PairingError::NotGrantable(
                    "zero owner devices; use --allow-zero-owner for console-only recovery".into(),
                ));
            }
            let before = inner.file.clone();
            for client in &pairings {
                if let Some(c) = inner
                    .file
                    .clients
                    .iter()
                    .find(|c| &c.client_id == client)
                    .cloned()
                {
                    let last = inner.file.last_epoch.entry(client.clone()).or_default();
                    *last = (*last).max(c.epoch);
                }
                inner.file.revoke_grants(Some(client));
            }
            for key in &plan.keys {
                Self::end_relation_grants(&mut inner, &key.client_id);
            }
            inner
                .file
                .clients
                .retain(|c| !pairings.contains(&c.client_id));
            inner
                .file
                .device_keys
                .retain(|k| !removed.contains(&k.key_id));
            inner
                .file
                .registered_ops
                .retain(|_, k| !removed.contains(k));
            inner
                .file
                .pending_device_keys
                .retain(|p| !pairings.contains(&p.client_id));
            inner
                .file
                .pending_elevations
                .retain(|p| !pairings.contains(&p.client_id));
            inner
                .file
                .replacement_approvals
                .retain(|p| !pairings.contains(&p.client_id));
            if let Err(e) = self.persist(&mut inner.file) {
                inner.file = before;
                return Err(e);
            }
            for client in &pairings {
                inner.second_device.provisional.remove(client);
            }
            inner
                .token_challenges
                .retain(|_, (client, _)| !pairings.contains(client));
            self.notify_authority_change();
            let mut audit_keys = plan.keys.clone();
            for key in &mut audit_keys {
                key.name = audit_device_name(&key.name);
            }
            self.enrollment_event(
                "pair.device_revoked",
                &options.root,
                serde_json::json!({"keys":audit_keys,"owner_device_count":plan.owner_device_count}),
            );
        }
        Ok(plan)
    }
}
