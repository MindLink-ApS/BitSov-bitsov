//! Starter activity uses the existing owner audit journal, including attribution
//! recovery. No approval kind or database schema is involved.
use super::{AuditEntry, AuditLog};
use konsensus_storage::starter_request::StarterRequest;
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::sync::Arc;

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
                // Replays emit no new intent. A new requested event may reuse
                // an orphan UUID after pruning, with a new initiating device.
                self.actors.insert(id.into(), actor.into());
            }
            "starter.request_conflict" => {
                self.actors.remove(id);
                self.outcomes.retain(|(request_id, _)| request_id != id);
            }
            "starter.ready" | "starter.refused" => {
                self.outcomes.insert((id.into(), event.into()));
            }
            _ => {}
        }
    }
}
impl AuditLog {
    /// Load attribution off the runtime and discard orphan intents before use.
    pub async fn open_with_starter_storage(
        path: impl AsRef<std::path::Path>,
        storage: Arc<dyn konsensus_storage::Storage>,
    ) -> std::io::Result<Arc<Self>> {
        let path = path.as_ref().to_owned();
        let log = Arc::new(
            tokio::task::spawn_blocking(move || Self::open(path))
                .await
                .map_err(std::io::Error::other)??,
        );
        log.starter_reconcile(storage).await?;
        Ok(log)
    }

    /// Serialize the complete intent/row transition and orphan pruning.
    pub async fn starter_admitted<T, F, Fut>(self: &Arc<Self>, operation: F) -> std::io::Result<T>
    where
        T: Send + 'static,
        F: FnOnce(Arc<Self>) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = T> + Send + 'static,
    {
        let log = Arc::clone(self);
        // Dropping an HTTP/worker future must not release admission while its
        // blocking audit job or database commit can still complete later.
        tokio::spawn(async move {
            let _admission = log.starter_admission.lock().await;
            operation(Arc::clone(&log)).await
        })
        .await
        .map_err(std::io::Error::other)
    }

    // All std mutexes are acquired inside the blocking job, never carried
    // across spawn_blocking or its await. Completion includes flush + fsync.
    async fn starter_blocking<T: Send + 'static>(
        self: &Arc<Self>,
        write: impl FnOnce(&Self) -> std::io::Result<T> + Send + 'static,
    ) -> std::io::Result<T> {
        let log = Arc::clone(self);
        tokio::task::spawn_blocking(move || write(&log))
            .await
            .map_err(std::io::Error::other)?
    }

    pub async fn starter_requested_async(
        self: &Arc<Self>,
        id: &str,
        client_id: &str,
    ) -> std::io::Result<()> {
        let (id, client_id) = (id.to_owned(), client_id.to_owned());
        self.starter_blocking(move |log| log.starter_requested(&id, &client_id))
            .await
    }

    pub async fn starter_progress_async(
        self: &Arc<Self>,
        row: &StarterRequest,
    ) -> std::io::Result<()> {
        let row = row.clone();
        self.starter_blocking(move |log| log.starter_progress(&row))
            .await
    }

    /// Conflicts are durable events, but never pending request intents.
    pub async fn starter_conflict(
        self: &Arc<Self>,
        id: &str,
        client_id: &str,
    ) -> std::io::Result<()> {
        let (id, client_id) = (id.to_owned(), client_id.to_owned());
        self.starter_blocking(move |log| {
            let mut activity = log.starter_activity.lock().unwrap_or_else(|e| e.into_inner());
            let result = log.starter_record("starter.request_conflict", &client_id, serde_json::json!({
                "request_id": id, "paired_device_id": client_id, "reason": "starter_already_requested"
            }));
            // Also discard an intent if storage's final transaction lost a race
            // with another process after the local admission check.
            activity.actors.remove(&id);
            activity.outcomes.retain(|(request_id, _)| request_id != &id);
            result
        }).await
    }

    /// Repair committed outcomes and forget old intents with no durable row.
    /// Run at startup before serving requests, and on every worker sweep.
    pub async fn starter_reconcile(
        self: &Arc<Self>,
        storage: Arc<dyn konsensus_storage::Storage>,
    ) -> std::io::Result<()> {
        self.starter_admitted(move |log| async move {
            for id in log
                .starter_blocking(|log| Ok(log.starter_pending()))
                .await?
            {
                if let Some(row) = storage
                    .starter_request_get(&id)
                    .await
                    .map_err(std::io::Error::other)?
                {
                    log.starter_progress_async(&row).await?;
                } else {
                    log.starter_blocking(move |log| {
                        let mut activity = log
                            .starter_activity
                            .lock()
                            .unwrap_or_else(|e| e.into_inner());
                        activity.actors.remove(&id);
                        activity
                            .outcomes
                            .retain(|(request_id, _)| request_id != &id);
                        Ok(())
                    })
                    .await?;
                }
            }
            Ok(())
        })
        .await?
    }

    // Unlike best-effort general audit events, starter attribution must be
    // durable before dispatch. The caller holds starter_activity across this
    // write, so concurrent replays cannot replace the initiating device.
    fn starter_record(
        &self,
        event: &str,
        actor: &str,
        detail: serde_json::Value,
    ) -> std::io::Result<()> {
        let mut writer = self.writer.lock().unwrap_or_else(|e| e.into_inner());
        let sync_file = writer.try_clone()?;
        let entry = AuditEntry {
            seq: self.seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            timestamp: chrono::Utc::now().to_rfc3339(),
            event,
            actor,
            detail: Some(detail),
        };
        let json = serde_json::to_string(&entry)?;
        writeln!(writer, "{json}")?;
        writer.flush()?;
        // General audit events can be emitted from a Tokio worker. Release
        // their writer lock before the slow sync, but still await durability
        // before allowing the request row to be committed.
        drop(writer);
        sync_file.sync_data()
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
