//! Operator-only enrollment tickets. Never called from an HTTP handler.
use std::{fs::File, path::Path, time::Duration};

use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use konsensus_api::{
    pairing::{fsync_dir_strict, load_box_transport_key, restrict_dir, write_protected},
    remote_access::{PairLink, PAIR_LINK_VERSION},
};
use rand::RngCore;

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
    rand::thread_rng().fill_bytes(&mut bytes);
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

pub fn cmd_pair_ticket(config_path: &Path, qr: bool, ttl: Duration, legacy: bool) -> Result<()> {
    let config = NodeConfig::load_before_identity_validation(config_path)?;
    config.node.validate()?;
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
        code: new_code(),
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
    let temporary = dir.join(format!(".remote-access-{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| -> Result<()> {
        write_protected(&temporary, uri.as_bytes())?;
        std::fs::rename(&temporary, dir.join("remote-access-link"))?;
        fsync_dir_strict(&dir)?;
        Ok(())
    })();
    let _ = std::fs::remove_file(temporary);
    result?;
    // Only this explicit operator command prints the secret link.
    println!("{uri}");
    if let Some(rendered) = rendered {
        println!("{rendered}");
    }
    Ok(())
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
