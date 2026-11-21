//! Operator-only enrollment tickets. Never called from an HTTP handler.
use std::{fs::File, path::Path, time::Duration};

use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use konsensus_api::{
    pairing::{allowance, fsync_dir_strict, load_box_transport_key, restrict_dir, write_protected},
    remote_access::{PairLink, PAIR_LINK_VERSION},
};
use rand::Rng;

use crate::{config::NodeConfig, owner_cmd::data_dir_of};

pub fn parse_ttl(value: &str) -> Result<Duration, String> {
    let (digits, multiplier) = match value.as_bytes().last() {
        Some(b's') => (&value[..value.len() - 1], 1u64),
        Some(b'm') => (&value[..value.len() - 1], 60),
        Some(b'h') => (&value[..value.len() - 1], 3600),
        Some(b'd') => (&value[..value.len() - 1], 86400),
        _ => return Err("TTL needs a unit: s, m, h or d".into()),
    };
    digits
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(multiplier))
        .filter(|n| (1..=365 * 86400).contains(n))
        .map(Duration::from_secs)
        .ok_or_else(|| "TTL must be between 1 second and 365 days".into())
}

/// The same advisory lock serializes CLI publication, daemon consumption and
/// locked-mode transitions. Closing the descriptor releases it, even on panic.
/// The lock inode is never renamed or removed.
pub fn lock_ticket(dir: &Path) -> Result<File> {
    std::fs::create_dir_all(dir)?;
    restrict_dir(dir)?;
    #[cfg(unix)]
    {
        use std::os::{fd::AsRawFd, unix::fs::OpenOptionsExt};
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(dir.join("remote-access.lock"))?;
        loop {
            // SAFETY: the descriptor is owned by file and remains open for this call.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
                return Ok(file);
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(error.into());
            }
        }
    }
    #[cfg(not(unix))]
    anyhow::bail!("enrollment tickets require Unix file locking")
}

pub fn new_code() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn set_locked(dir: &Path, locked: bool) -> Result<()> {
    let _guard = lock_ticket(dir)?;
    let path = dir.join("remote-access-locked");
    if locked {
        write_protected(&path, b"locked\n")?;
    } else {
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    fsync_dir_strict(dir)?;
    Ok(())
}

/// Owner terms for a standing allowance on the pairing a ticket creates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllowanceArgs {
    pub daily_sats: u64,
    pub per_call_sats: Option<u64>,
    pub days: Option<u32>,
}

impl AllowanceArgs {
    fn terms(&self, now: i64) -> Result<allowance::AllowanceTerms> {
        let per_call = self
            .per_call_sats
            .unwrap_or_else(|| allowance::DEFAULT_PER_CALL_SATS.min(self.daily_sats));
        allowance::AllowanceTerms::from_sats(
            self.daily_sats,
            per_call,
            self.days.unwrap_or(allowance::DEFAULT_DAYS),
            now,
        )
        .map_err(anyhow::Error::msg)
    }
}

/// A ticket without an allowance (tests; the command passes its flags).
#[cfg(test)]
pub fn cmd_pair_ticket(
    config_path: &Path,
    qr: bool,
    ttl: Duration,
    legacy: bool,
    second_device: bool,
) -> Result<()> {
    cmd_pair_ticket_with_allowance(config_path, qr, ttl, legacy, second_device, None)
}

pub fn cmd_pair_ticket_with_allowance(
    config_path: &Path,
    qr: bool,
    ttl: Duration,
    legacy: bool,
    second_device: bool,
    allowance_args: Option<AllowanceArgs>,
) -> Result<()> {
    let config = NodeConfig::load_before_identity_validation(config_path)?;
    config.node.validate()?;
    let allowance_terms = match allowance_args {
        None => None,
        Some(args) => {
            anyhow::ensure!(
                config.pairing.standing_allowance_v1,
                "standing allowances are off; set [pairing] standing_allowance_v1 = true first"
            );
            anyhow::ensure!(
                !second_device && !legacy,
                "an allowance attaches only to a regular pairing ticket"
            );
            anyhow::ensure!(
                ttl.as_secs() <= allowance::MAX_TICKET_TTL_SECS,
                "a ticket carrying an allowance lasts at most 1h"
            );
            Some(args.terms(chrono::Utc::now().timestamp())?)
        }
    };
    if second_device {
        anyhow::ensure!(
            config.pairing.second_device_enrollment,
            "second-device enrollment is disabled"
        );
        anyhow::ensure!(
            !legacy && ttl.as_secs() <= 1800,
            "second-device tickets require v2 and a TTL of at most 30 minutes"
        );
    }
    anyhow::ensure!(
        config.remote_access.listen_addr.is_some(),
        "remote access is disabled"
    );
    let listen_addr = config.remote_access.listen_addr.unwrap();
    let endpoints = if listen_addr.port() == 0 {
        // The daemon's signed descriptor below contains the actual bound port.
        // A pre-bootstrap CLI can only use an explicit externally dialable hint.
        config
            .remote_access
            .advertised_endpoint
            .iter()
            .cloned()
            .collect()
    } else {
        crate::endpoints::discover(&config.remote_access, listen_addr)?
    };
    let data = data_dir_of(config_path);
    let dir = data.join("pairing");
    let _guard = lock_ticket(&dir)?;
    anyhow::ensure!(
        !dir.join("remote-access-locked").try_exists()?,
        "pairing is refused while locked; unlock the node first"
    );
    let secret = load_box_transport_key(&dir)?;
    let public = hex::encode(
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*secret)).as_bytes(),
    );
    let mut link = PairLink {
        v: PAIR_LINK_VERSION,
        endpoint: endpoints.first().cloned().unwrap_or_default(),
        endpoints,
        endpoints_signature: None,
        node_id: String::new(),
        transport_pubkey: String::new(),
        transport_signature: String::new(),
        box_transport_pubkey: public,
        box_transport_signature: None,
        code: if second_device {
            format!("second_{}", new_code())
        } else {
            new_code()
        },
        expires_at: chrono::Utc::now().timestamp() + ttl.as_secs() as i64,
        hosted_by: config.node.hosted_by.clone(),
    };
    let metadata = data.join("identity/identity.json");
    if metadata.try_exists()? {
        let document: serde_json::Value = serde_json::from_slice(&std::fs::read(metadata)?)
            .context("invalid public identity metadata")?;
        let field = |name| {
            document
                .get(name)
                .and_then(|v| v.as_str())
                .context("start the node unlocked once to refresh public transport proofs")
        };
        link.node_id = field("node_id")?.into();
        anyhow::ensure!(
            field("box_transport_pubkey")? == link.box_transport_pubkey,
            "box key changed; start unlocked to refresh public transport proofs"
        );
        link.box_transport_signature = Some(field("box_transport_signature")?.into());
        link.transport_pubkey = field("transport_pubkey")?.into();
        link.transport_signature = field("transport_signature")?.into();
        let node: [u8; 32] = hex::decode(&link.node_id)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid public node identity"))?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(&node)?;
        for (message, signature) in [
            (
                konsensus_api::remote_access::box_transport_proof_message(
                    &link.node_id,
                    &link.box_transport_pubkey,
                ),
                link.box_transport_signature.as_deref().unwrap(),
            ),
            (
                konsensus_api::remote_access::transport_proof_message(
                    &link.node_id,
                    &link.transport_pubkey,
                ),
                link.transport_signature.as_str(),
            ),
        ] {
            let signature =
                ed25519_dalek::Signature::from_slice(&URL_SAFE_NO_PAD.decode(signature)?)?;
            key.verify_strict(message.as_bytes(), &signature)
                .context("invalid public transport proof")?;
        }
        let signed_endpoints: Vec<String> = serde_json::from_value(
            document
                .get("endpoints")
                .cloned()
                .context("start unlocked once to sign remote-access endpoints")?,
        )?;
        if listen_addr.port() == 0 {
            if let Some(configured) = &config.remote_access.advertised_endpoint {
                anyhow::ensure!(signed_endpoints.first() == Some(configured),
                    "configured endpoint changed; restart unlocked to refresh the signed descriptor");
            }
            link.endpoint = signed_endpoints
                .first()
                .cloned()
                .context("empty signed endpoints")?;
            link.endpoints = signed_endpoints;
        } else {
            anyhow::ensure!(signed_endpoints == link.endpoints,
                "remote-access endpoints changed; restart unlocked to refresh the signed descriptor");
        }
        link.endpoints_signature = Some(field("endpoints_signature")?.into());
    } else {
        anyhow::ensure!(
            !config.identity.mnemonic_file.try_exists()?
                && !data.join("NODE_INITIALIZED").try_exists()?,
            "start the node unlocked once before issuing an identity ticket"
        );
    }
    link.validate_descriptor().map_err(anyhow::Error::msg)?;
    let uri = if legacy {
        link.to_legacy_uri()?
    } else {
        link.to_uri()?
    };
    // Render before publication: oversized payloads must not replace a good ticket.
    let rendered = if qr { Some(render_qr(&uri)?) } else { None };
    // The published ticket and the terms bound to it change together: the
    // terms are staged first, the ticket is replaced, and only then are the
    // terms published (or, for a ticket without --allow, removed). The node
    // reads both under the same lock this command holds. If replacing the
    // ticket fails, the previous ticket and its terms stay as they were; if
    // publishing the terms fails, the previous ticket is put back.
    let staged = match &allowance_terms {
        Some(terms) => Some(allowance::stage_ticket_allowance(&dir, &link.code, terms)?),
        None => None,
    };
    let link_path = dir.join("remote-access-link");
    let previous_terms = match std::fs::read(allowance::ticket_allowance_path(&dir)) {
        Ok(bytes) => Some(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            if let Some(staged) = &staged {
                let _ = std::fs::remove_file(staged);
            }
            return Err(e.into());
        }
    };
    let previous_link = match std::fs::read(&link_path) {
        Ok(bytes) => Some(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            if let Some(staged) = &staged {
                let _ = std::fs::remove_file(staged);
            }
            return Err(e.into());
        }
    };
    let replace_link = |bytes: &[u8], fail: bool| -> Result<()> {
        let temporary = dir.join(format!(".remote-access-{}.tmp", uuid::Uuid::new_v4()));
        let result = (|| -> Result<()> {
            write_protected(&temporary, bytes)?;
            if fail {
                anyhow::bail!("ticket replace failed (test)");
            }
            std::fs::rename(&temporary, &link_path)?;
            #[cfg(test)]
            if FAIL_AFTER_LINK_RENAME.with(|fail| fail.replace(false)) {
                anyhow::bail!("ticket sync failed (test)");
            }
            fsync_dir_strict(&dir)?;
            Ok(())
        })();
        let _ = std::fs::remove_file(temporary);
        result
    };
    #[cfg(test)]
    let fail_link = FAIL_LINK_REPLACE.with(|fail| fail.get());
    #[cfg(not(test))]
    let fail_link = false;
    if let Err(error) = replace_link(uri.as_bytes(), fail_link) {
        if let Some(staged) = &staged {
            let _ = std::fs::remove_file(staged);
        }
        // A failure after the rename (syncing the directory) leaves the new
        // ticket published next to the previous terms: put the previous
        // ticket back. The terms were not touched yet.
        let renamed = std::fs::read(&link_path).is_ok_and(|bytes| bytes == uri.as_bytes());
        if !renamed {
            return Err(error);
        }
        let restored = match &previous_link {
            Some(bytes) => replace_link(bytes, false),
            None => std::fs::remove_file(&link_path)
                .map_err(anyhow::Error::from)
                .and_then(|()| fsync_dir_strict(&dir).map_err(anyhow::Error::from)),
        };
        return Err(error.context(match restored {
            Ok(()) => "could not publish the ticket; the previous ticket is back in place".to_string(),
            Err(e) => format!(
                "could not publish the ticket, nor put the previous one back ({e}); \
                 the new ticket may be published without its terms: run pair-ticket again"
            ),
        }));
    }
    match &staged {
        Some(staged) => {
            #[cfg(test)]
            let fail_terms = FAIL_TERMS_PUBLISH.with(|fail| fail.get());
            #[cfg(not(test))]
            let fail_terms = false;
            let published = if fail_terms {
                let _ = std::fs::remove_file(staged);
                Err(std::io::Error::other("terms publish failed (test)"))
            } else {
                allowance::commit_ticket_allowance(&dir, staged)
            };
            #[cfg(test)]
            let published = published.and_then(|()| {
                if FAIL_AFTER_TERMS_RENAME.with(|fail| fail.get()) {
                    Err(std::io::Error::other("terms sync failed (test)"))
                } else {
                    Ok(())
                }
            });
            if let Err(error) = published {
                // The new terms may already be in place (a failure after
                // their rename): put back the previous terms and the previous
                // ticket together.
                let terms_restored = allowance::restore_ticket_allowance(&dir, previous_terms.as_deref())
                    .map_err(anyhow::Error::from);
                let link_restored = match &previous_link {
                    Some(bytes) => replace_link(bytes, false),
                    None => std::fs::remove_file(&link_path)
                        .map_err(anyhow::Error::from)
                        .and_then(|()| fsync_dir_strict(&dir).map_err(anyhow::Error::from)),
                };
                let restored = terms_restored.and(link_restored);
                return Err(anyhow::Error::from(error).context(match restored {
                    Ok(()) => "could not publish the allowance; the previous ticket is back in place".to_string(),
                    Err(e) => format!("could not publish the allowance, nor put the previous ticket back ({e}); run pair-ticket again"),
                }));
            }
        }
        None => {
            // Terms left from an earlier ticket are bound to that ticket's
            // code and never match this one; removing them is tidying.
            if let Err(error) = allowance::remove_ticket_allowance(&dir) {
                eprintln!("note: could not remove the terms of an earlier ticket ({error}); they do not apply to this one");
            }
        }
    }
    // Only this explicit operator command prints the secret link.
    println!("{uri}");
    if let Some(rendered) = rendered {
        println!("{rendered}");
    }
    if let Some(terms) = &allowance_terms {
        println!(
            "Allowance on this pairing: up to {} sats in any 24 hours, {} sats per call, until {}. Revoke the pairing to end it.",
            terms.daily_msat / 1000,
            terms.per_call_max_msat / 1000,
            chrono::DateTime::from_timestamp(terms.until, 0).map(|t| t.to_rfc3339()).unwrap_or_default()
        );
    }
    if second_device {
        println!("Open Add a device on your other device now, so it can approve");
        println!("Older apps cannot complete this second-device QR; update the app first.");
    }
    Ok(())
}

#[cfg(test)]
thread_local! {
    /// Test-only: make replacing the published ticket fail.
    static FAIL_LINK_REPLACE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Test-only: make publishing the staged terms fail.
    static FAIL_TERMS_PUBLISH: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Test-only: fail once, right after a ticket was renamed into place.
    static FAIL_AFTER_LINK_RENAME: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Test-only: fail after the staged terms were renamed into place.
    static FAIL_AFTER_TERMS_RENAME: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn render_qr(uri: &str) -> Result<String> {
    use qrcode::render::unicode::Dense1x2;
    let code = qrcode::QrCode::new(uri.as_bytes()).context("ticket is too large for a QR code")?;
    // White background/black modules on the usual dark terminal, with quiet zone.
    Ok(code
        .render::<Dense1x2>()
        .dark_color(Dense1x2::Light)
        .light_color(Dense1x2::Dark)
        .quiet_zone(true)
        .build())
}

#[cfg(test)]
mod second_device_tests {
    use super::*;

    #[test]
    fn second_device_ticket_refusals_do_not_publish() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("konsensus.toml");
        let mut config = NodeConfig::default_for_tier(
            crate::config::NodeTier::Light,
            dir.path().join("mnemonic.enc"),
            dir.path(),
        );
        config.save(&path).unwrap();
        assert!(
            cmd_pair_ticket(&path, false, Duration::from_secs(600), false, true)
                .unwrap_err()
                .to_string()
                .contains("disabled")
        );
        config.pairing.second_device_enrollment = true;
        config.save(&path).unwrap();
        for (ttl, legacy) in [(1801, false), (600, true)] {
            assert!(
                cmd_pair_ticket(&path, false, Duration::from_secs(ttl), legacy, true)
                    .unwrap_err()
                    .to_string()
                    .contains("30 minutes")
            );
        }
        assert!(!dir.path().join("pairing/remote-access-link").exists());
    }
}

#[cfg(test)]
mod allowance_publish_tests {
    use super::*;

    fn node(dir: &Path) -> std::path::PathBuf {
        let path = dir.join("konsensus.toml");
        let mut config = NodeConfig::default_for_tier(crate::config::NodeTier::Light, dir.join("absent.enc"), dir);
        config.remote_access = crate::config::RemoteAccessConfig {
            listen_addr: Some("127.0.0.1:0".parse().unwrap()),
            advertised_endpoint: Some("node.example:9737".into()),
            ..Default::default()
        };
        config.pairing.standing_allowance_v1 = true;
        config.save(&path).unwrap();
        path
    }

    fn published(dir: &Path) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
        let read = |name: &str| std::fs::read(dir.join("pairing").join(name)).ok();
        (read("remote-access-link"), read("remote-access-allowance"))
    }

    fn ticket(path: &Path, allow: bool) -> Result<()> {
        let args = allow.then_some(AllowanceArgs { daily_sats: 2_500, per_call_sats: None, days: None });
        cmd_pair_ticket_with_allowance(path, false, Duration::from_secs(600), false, false, args)
    }

    /// A ticket that cannot be published leaves the published ticket and the
    /// terms bound to it exactly as they were, with or without --allow.
    #[test]
    fn a_failed_publish_keeps_the_previous_ticket_and_its_terms() {
        for (previous_allow, next_allow) in [(true, false), (true, true), (false, true), (false, false)] {
            let dir = tempfile::tempdir().unwrap();
            let path = node(dir.path());
            ticket(&path, previous_allow).unwrap();
            let before = published(dir.path());
            assert!(before.0.is_some());
            assert_eq!(before.1.is_some(), previous_allow);
            FAIL_LINK_REPLACE.with(|fail| fail.set(true));
            let result = ticket(&path, next_allow);
            FAIL_LINK_REPLACE.with(|fail| fail.set(false));
            assert!(result.is_err());
            assert_eq!(published(dir.path()), before, "previous {previous_allow}, next {next_allow}");
            // Nothing left over from the attempt.
            let leftovers: Vec<_> = std::fs::read_dir(dir.path().join("pairing")).unwrap()
                .filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.ends_with(".tmp")).collect();
            assert!(leftovers.is_empty(), "{leftovers:?}");
            // And a working publish afterwards pairs link and terms again.
            ticket(&path, next_allow).unwrap();
            let after = published(dir.path());
            assert_eq!(after.1.is_some(), next_allow);
            if next_allow {
                let uri = String::from_utf8(after.0.unwrap()).unwrap();
                let code = konsensus_api::remote_access::PairLink::from_uri(uri.trim()).unwrap().code;
                assert!(allowance::read_ticket_allowance(&dir.path().join("pairing"), &code, chrono::Utc::now().timestamp()).is_some());
            }
        }
    }

    /// If the terms cannot be published after the ticket was replaced, the
    /// previous ticket is put back, so the published ticket and its terms
    /// still belong together.
    #[test]
    fn a_failed_terms_publish_puts_the_previous_ticket_back() {
        for previous in [None, Some(false), Some(true)] {
            let dir = tempfile::tempdir().unwrap();
            let path = node(dir.path());
            if let Some(allow) = previous {
                ticket(&path, allow).unwrap();
            }
            let before = published(dir.path());
            FAIL_TERMS_PUBLISH.with(|fail| fail.set(true));
            let result = ticket(&path, true);
            FAIL_TERMS_PUBLISH.with(|fail| fail.set(false));
            assert!(result.is_err());
            assert_eq!(published(dir.path()), before, "previous {previous:?}");
        }
    }

    /// A failure after the new terms were renamed into place (for example
    /// syncing the directory) puts back the previous ticket and the previous
    /// terms together.
    #[test]
    fn a_failure_after_the_terms_rename_restores_the_previous_pair() {
        for previous in [None, Some(false), Some(true)] {
            let dir = tempfile::tempdir().unwrap();
            let path = node(dir.path());
            if let Some(allow) = previous {
                ticket(&path, allow).unwrap();
            }
            let before = published(dir.path());
            FAIL_AFTER_TERMS_RENAME.with(|fail| fail.set(true));
            let result = ticket(&path, true);
            FAIL_AFTER_TERMS_RENAME.with(|fail| fail.set(false));
            assert!(result.is_err());
            assert_eq!(published(dir.path()), before, "previous {previous:?}");
        }
    }

    /// A failure right after the new ticket was renamed into place (for
    /// example syncing the directory) puts the previous ticket back, so the
    /// published ticket and its terms still belong together.
    #[test]
    fn a_failure_after_the_ticket_rename_restores_the_previous_pair() {
        for previous in [None, Some(false), Some(true)] {
            for next_allow in [false, true] {
                let dir = tempfile::tempdir().unwrap();
                let path = node(dir.path());
                if let Some(allow) = previous {
                    ticket(&path, allow).unwrap();
                }
                let before = published(dir.path());
                FAIL_AFTER_LINK_RENAME.with(|fail| fail.set(true));
                let result = ticket(&path, next_allow);
                FAIL_AFTER_LINK_RENAME.with(|fail| fail.set(false));
                assert!(result.is_err(), "previous {previous:?}, next {next_allow}");
                assert_eq!(published(dir.path()), before, "previous {previous:?}, next {next_allow}");
            }
        }
    }
}
