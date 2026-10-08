//! Bind the home page only to actual LAN interfaces, on a separate HTTP port.
use crate::{config::NodeConfig, endpoints};
use anyhow::{Context, Result};
use konsensus_api::bootstrap::{
    setup::{self, SetupPage, SetupTickets},
    BootstrapState,
};
use std::{net::SocketAddr, sync::Arc};

pub struct Listener {
    page: Arc<SetupPage>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    initial_status: String,
}
impl Listener {
    pub fn set_unlocked(&self) {
        self.page
            .set_status(&self.initial_status.replace("LOCKED", "UNLOCKED"));
    }
}
impl Drop for Listener {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}
pub async fn start(
    config: &NodeConfig,
    bootstrap: Option<Arc<BootstrapState>>,
    tickets: Option<Arc<dyn SetupTickets>>,
    status: String,
) -> Result<Listener> {
    anyhow::ensure!(
        config.setup_page.port != 0,
        "setup_page.port must be nonzero"
    );
    let interfaces = if_addrs::get_if_addrs().context("could not enumerate setup interfaces")?;
    let mut listeners = Vec::new();
    let mut hosts = vec![format!("bitsov.local:{}", config.setup_page.port)];
    if config.setup_page.port == 80 {
        hosts.push("bitsov.local".into());
    }
    for interface in interfaces {
        let ip = interface.ip();
        if !interface.is_oper_up() || !setup::lan_source(ip) || endpoints::is_tailscale(ip) {
            continue;
        }
        let mut addr = SocketAddr::new(ip, config.setup_page.port);
        if let SocketAddr::V6(v6) = &mut addr {
            if v6.ip().is_unicast_link_local() {
                v6.set_scope_id(interface.index.unwrap_or(0));
            }
        }
        if listeners
            .iter()
            .any(|l: &tokio::net::TcpListener| l.local_addr().ok() == Some(addr))
        {
            continue;
        }
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .with_context(|| format!("could not bind home page at {addr}"))?;
        hosts.push(addr.to_string());
        if config.setup_page.port == 80 {
            hosts.push(match ip {
                std::net::IpAddr::V6(ip) => format!("[{ip}]"),
                _ => ip.to_string(),
            });
        }
        listeners.push(listener);
    }
    anyhow::ensure!(
        !listeners.is_empty(),
        "--home setup page needs a private LAN interface"
    );
    let page = Arc::new(SetupPage::new(
        bootstrap,
        tickets,
        hosts,
        config
            .node
            .hosted_by
            .clone()
            .unwrap_or_else(|| "BitSov box".into()),
        status.clone(),
    ));
    let mut tasks = Vec::new();
    for listener in listeners {
        let router = setup::router(page.clone());
        tasks.push(tokio::spawn(async move {
            if let Err(error) = axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            {
                tracing::error!(%error,"home page listener failed");
            }
        }));
    }
    Ok(Listener {
        page,
        tasks,
        initial_status: status,
    })
}
