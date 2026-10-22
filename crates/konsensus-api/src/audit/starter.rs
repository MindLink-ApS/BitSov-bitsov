//! Starter activity uses the existing owner audit journal, including attribution
//! recovery. No approval kind or database schema is involved.
use super::{AuditEntry, AuditLog};
use konsensus_storage::starter_request::StarterRequest;
use std::collections::{HashMap, HashSet};
use std::io::Write;

#[derive(Default)]
pub(super) struct StarterActivity {
    actors: HashMap<String, String>,
    outcomes: HashSet<(String, String)>,
}
impl StarterActivity {
    pub(super) fn recover(&mut self, entry: &serde_json::Value) {
        let (Some(event), Some(id), Some(actor)) = (
            entry["event"].as_str(),
            entry["detail"]["request_id"].as_str(),
            entry["detail"]["paired_device_id"].as_str(),
        ) else {
            return;
        };
        match event {
            "starter.requested" => {
                self.outcomes.retain(|(request_id, _)| request_id != id);
                self.actors.entry(id.into()).or_insert_with(|| actor.into());
            }
            "starter.ready" | "starter.refused" => {
                self.outcomes.insert((id.into(), event.into()));
            }
            _ => {}
        }
    }
}
impl AuditLog {
    // Unlike best-effort general audit events, starter attribution must be
    // durable before dispatch. The caller holds starter_activity across this
    // write, so concurrent replays cannot replace the initiating device.
    fn starter_record(
        &self,
        event: &str,
        actor: &str,
        detail: serde_json::Value,
    ) -> std::io::Result<()> {
        let entry = AuditEntry {
            seq: self.seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            timestamp: chrono::Utc::now().to_rfc3339(),
            event,
            actor,
            detail: Some(detail),
        };
        let json = serde_json::to_string(&entry)?;
        let mut writer = self.writer.lock().unwrap_or_else(|e| e.into_inner());
        writeln!(writer, "{json}")?;
        writer.flush()?;
        writer.get_ref().sync_data()
    }

    /// Record the first paired request intent before creating its operation.
    /// An idempotent replay retains the first requesting device.
    pub fn starter_requested(&self, id: &str, client_id: &str) -> std::io::Result<()> {
        let mut activity = self
            .starter_activity
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if activity.actors.contains_key(id) {
            return Ok(());
        }
        self.starter_record("starter.requested", client_id, serde_json::json!({
            "request_id":id, "root_request_id":id, "paired_device_id":client_id, "state":"requested"
        }))?;
        activity.actors.insert(id.into(), client_id.into());
        Ok(())
    }

    /// Intents without a journaled terminal result, including a crash between
    /// committing the terminal row and appending its event.
    pub fn starter_pending(&self) -> Vec<String> {
        let activity = self
            .starter_activity
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        activity
            .actors
            .keys()
            .filter(|id| {
                !activity
                    .outcomes
                    .contains(&(id.to_string(), "starter.ready".into()))
                    && !activity
                        .outcomes
                        .contains(&(id.to_string(), "starter.refused".into()))
            })
            .cloned()
            .collect()
    }

    /// Record persisted worker progress. Retries/adoptions inherit the root's
    /// device; pre-upgrade operations explicitly have unknown attribution.
    pub fn starter_progress(&self, row: &StarterRequest) -> std::io::Result<()> {
        let mut activity = self
            .starter_activity
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let actor = activity
            .actors
            .get(row.root_id())
            .cloned()
            .unwrap_or_else(|| "unknown".into());
        let detail = serde_json::json!({
            "request_id":row.request_id, "root_request_id":row.root_id(),
            "paired_device_id":actor, "state":row.state, "reason":row.reason
        });
        let revived = !row.terminal()
            && activity
                .outcomes
                .iter()
                .any(|(id, _)| id == &row.request_id);
        if !activity.actors.contains_key(&row.request_id) || revived {
            let mut requested = detail.clone();
            requested["state"] = serde_json::json!("requested");
            requested["reason"] = serde_json::Value::Null;
            self.starter_record("starter.requested", &actor, requested)?;
            activity.outcomes.retain(|(id, _)| id != &row.request_id);
            activity
                .actors
                .insert(row.request_id.clone(), actor.clone());
        }
        if row.terminal() {
            let event = format!("starter.{}", row.state);
            let key = (row.request_id.clone(), event.clone());
            if !activity.outcomes.contains(&key) {
                self.starter_record(&event, &actor, detail)?;
                activity.outcomes.insert(key);
            }
        }
        Ok(())
    }
}
