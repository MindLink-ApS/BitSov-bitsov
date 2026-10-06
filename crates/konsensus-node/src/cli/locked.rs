//! Locked startup has no KonsensusNode, peer transport, wallet or chain source.
use std::{net::SocketAddr, path::Path, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use konsensus_api::{
    locked::{locked_router, LockedState, UnlockError},
    pairing::{identity_fingerprint, PairingService},
    rate_limit::RemoteTunnelClients,
};
use konsensus_core::{NodeIdentity, OwnerApprovalKey};
use tokio::{
    net::TcpListener,
    sync::{oneshot, watch},
    task::JoinSet,
};
use zeroize::Zeroizing;

use crate::{
    config::NodeConfig,
    mnemonic_crypto, owner_cmd,
    remote_access::{LockedIdentity, RemoteAccessServer},
};

fn verify_password(
    config: &NodeConfig,
    password: &str,
) -> Result<(String, ed25519_dalek::VerifyingKey), UnlockError> {
    let mnemonic = mnemonic_crypto::read_mnemonic(&config.identity.mnemonic_file, Some(password))
        .map_err(|_| UnlockError::Failed)?;
    let identity = NodeIdentity::from_mnemonic(&mnemonic, &config.identity.passphrase)
        .map_err(|_| UnlockError::Failed)?;
    let node_id = identity.node_id().to_hex();
    let secret =
        mnemonic_crypto::owner_secret(password, &node_id).map_err(|_| UnlockError::Failed)?;
    let owner = OwnerApprovalKey::from_mnemonic(&mnemonic, &config.identity.passphrase, &secret)
        .map_err(|_| UnlockError::Failed)?;
    Ok((node_id, owner.verifying_key()))
}

fn read_identity(data_dir: &Path, pairing: &PairingService) -> Result<LockedIdentity> {
    let identity: LockedIdentity =
        serde_json::from_slice(&std::fs::read(data_dir.join("identity/identity.json"))?)
            .context("remote unlock needs public identity metadata from an unlocked start")?;
    anyhow::ensure!(
        identity.identity_fingerprint == identity_fingerprint(&identity.node_id),
        "public identity fingerprint mismatch; start unlocked to repair"
    );
    anyhow::ensure!(
        identity.box_transport_pubkey == hex::encode(pairing.box_transport_pubkey()),
        "box transport key changed; start unlocked and re-pin the device"
    );
    let node_bytes: [u8; 32] = hex::decode(&identity.node_id)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid node id"))?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(&node_bytes)?;
    let signature = ed25519_dalek::Signature::from_slice(
        &URL_SAFE_NO_PAD.decode(&identity.box_transport_signature)?,
    )?;
    key.verify_strict(
        konsensus_api::remote_access::box_transport_proof_message(
            &identity.node_id,
            &identity.box_transport_pubkey,
        )
        .as_bytes(),
        &signature,
    )
    .context("public box transport signature invalid; start unlocked to repair")?;
    Ok(identity)
}

// Axum owns connection tasks beneath the listener future. Cancellation must
// signal graceful shutdown, not abort that future and strand keepalive tasks.
struct LockedServers {
    shutdown: watch::Sender<bool>,
    tasks: JoinSet<Result<()>>,
}
impl Drop for LockedServers {
    fn drop(&mut self) {
        self.shutdown.send_replace(true);
        // Each server observes the shutdown and releases its listener and
        // connections, even when the caller cancels during password derivation.
        self.tasks.detach_all();
    }
}

/// Returns only after a device signature, seed/password, owner signature and
/// saved identity all verify. Dropping this future shuts down every listener;
/// dropping the one-shot receiver also wipes any in-flight password handoff.
pub async fn serve_locked_mode(
    config_path: &Path,
    config: &NodeConfig,
) -> Result<Zeroizing<String>> {
    anyhow::ensure!(
        mnemonic_crypto::is_encrypted_path(&config.identity.mnemonic_file)
            && !config.identity.mnemonic_file.with_extension("txt").exists(),
        "{}: remote unlock requires an encrypted seed without a plaintext sibling",
        konsensus_api::pairing::device::SEED_NOT_ENCRYPTED
    );
    anyhow::ensure!(
        config.api.listen_addr.ip().is_loopback(),
        "remote unlock requires a loopback API listen address"
    );
    anyhow::ensure!(
        config.remote_access.listen_addr.is_some(),
        "remote unlock requires remote_access.listen_addr"
    );
    let data_dir = owner_cmd::data_dir_of(config_path);
    // Read only public data before opening the pairing state. It is verified
    // against both the persisted box key and, after unlock, the decrypted seed.
    let metadata: LockedIdentity = serde_json::from_slice(
        &std::fs::read(data_dir.join("identity/identity.json"))
            .context("remote unlock requires identity/identity.json; start unlocked once first")?,
    )?;
    let pairing = Arc::new(
        PairingService::open(&data_dir, metadata.identity_fingerprint, false)?
            .with_pairing_closed()
            .with_hosted_by(config.node.hosted_by.clone()),
    );
    let identity = read_identity(&data_dir, &pairing)?;
    let clients = Arc::new(RemoteTunnelClients::default());
    let (tx, rx) = oneshot::channel();
    let verify_config = config.clone();
    let state = Arc::new(LockedState::new(
        identity.node_id.clone(),
        pairing.clone(),
        clients.clone(),
        move |password| verify_password(&verify_config, password),
        tx,
    ));
    let local = TcpListener::bind(config.api.listen_addr)
        .await
        .context("could not bind locked loopback API")?;
    let internal = TcpListener::bind("127.0.0.1:0").await?;
    let server = RemoteAccessServer::bind_locked(
        &config.remote_access,
        identity,
        pairing,
        internal.local_addr()?,
        clients,
    )
    .await?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut servers = LockedServers {
        shutdown: shutdown_tx,
        tasks: JoinSet::new(),
    };
    for listener in [local, internal] {
        let router =
            locked_router(state.clone()).into_make_service_with_connect_info::<SocketAddr>();
        let mut stop = shutdown_rx.clone();
        servers.tasks.spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async move {
                    if !*stop.borrow_and_update() {
                        let _ = stop.changed().await;
                    }
                })
                .await
                .context("locked API stopped")
        });
    }
    servers.tasks.spawn(async move {
        server.serve(shutdown_rx).await;
        Ok(())
    });
    tracing::info!(
        code = "NODE_LOCKED",
        "node locked; awaiting an existing owner device"
    );
    let password = tokio::select! {
        result = rx => result.context("unlock handoff closed")?,
        result = servers.tasks.join_next() => {
            if let Some(result) = result { result??; }
            anyhow::bail!("locked listener stopped before unlock");
        }
    };
    // Give the 204 time to traverse the Noise bridge, then close all listeners
    // before handing the password to the normal startup path (same process).
    tokio::time::sleep(Duration::from_millis(100)).await;
    servers.shutdown.send_replace(true);
    tokio::time::timeout(Duration::from_millis(150), async {
        while let Some(result) = servers.tasks.join_next().await {
            result??;
        }
        anyhow::Ok(())
    })
    .await
    .context("locked listeners did not stop before startup")??;
    Ok(password)
}
