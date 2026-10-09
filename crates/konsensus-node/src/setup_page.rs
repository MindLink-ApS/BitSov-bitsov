//! Bind the home page only to actual LAN interfaces, on a separate HTTP port.
use crate::{config::NodeConfig, endpoints};
use anyhow::{Context, Result};
use axum::{extract::ConnectInfo, Extension, Router};
use hyper::server::conn::http1;
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    service::TowerToHyperService,
};
use konsensus_api::bootstrap::{
    setup::{self, SetupPage, SetupTickets},
    BootstrapState,
};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{net::TcpListener, sync::Semaphore, task::JoinSet};

const MAX_CONNECTIONS: usize = 32;
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Admission is shared across all interface listeners. Excess sockets are closed
/// immediately, without spawning a task or waiting in an unbounded permit queue.
async fn serve(
    listener: TcpListener,
    router: Router,
    slots: Arc<Semaphore>,
) -> std::io::Result<()> {
    // Owning the tasks also ensures dropping the listener closes its connections.
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(connection) => connection,
                    Err(error) => {
                        // Preserve axum::serve's recovery from aborted accepts and
                        // resource exhaustion instead of losing this LAN listener.
                        if !matches!(error.kind(), std::io::ErrorKind::ConnectionRefused
                            | std::io::ErrorKind::ConnectionAborted | std::io::ErrorKind::ConnectionReset) {
                            tracing::error!(%error, "home page accept failed; retrying");
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        }
                        continue;
                    }
                };
                let Ok(permit) = slots.clone().try_acquire_owned() else {
                    drop(stream);
                    continue;
                };
                // Only the socket peer supplies identity; no forwarded headers.
                let service = TowerToHyperService::new(router.clone().layer(Extension(ConnectInfo(peer))));
                connections.spawn(async move {
                    let _permit = permit;
                    let _ = http1::Builder::new()
                        .timer(TokioTimer::new())
                        .header_read_timeout(HEADER_READ_TIMEOUT)
                        .max_buf_size(8192)
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        }
    }
}

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
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    for listener in listeners {
        let router = setup::router(page.clone());
        let slots = slots.clone();
        tasks.push(tokio::spawn(async move {
            if let Err(error) = serve(listener, router, slots).await {
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        sync::Semaphore,
        time::{timeout, Duration},
    };

    async fn server(slots: Arc<Semaphore>) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = axum::Router::new().route("/", axum::routing::get(|| async { "ok" }));
        let task = tokio::spawn(async move {
            serve(listener, router, slots).await.unwrap();
        });
        (addr, task)
    }

    #[tokio::test]
    async fn slow_headers_time_out_even_when_bytes_keep_arriving() {
        let (addr, task) = server(Arc::new(Semaphore::new(32))).await;
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Slow: ")
            .await
            .unwrap();
        for _ in 0..4 {
            tokio::time::sleep(Duration::from_secs(1)).await;
            stream.write_all(b"x").await.unwrap();
        }
        let mut response = Vec::new();
        let result = timeout(Duration::from_secs(2), stream.read_to_end(&mut response)).await;
        task.abort();
        assert!(
            result.is_ok(),
            "partial headers held the connection beyond its deadline"
        );
        assert!(response.is_empty() || String::from_utf8_lossy(&response).contains("408"));
    }

    #[tokio::test]
    async fn concurrent_connections_are_capped_across_listeners_and_slots_recover() {
        let slots = Arc::new(Semaphore::new(2));
        let (addr, task) = server(slots.clone()).await;
        let (other_addr, other_task) = server(slots.clone()).await;
        let first = TcpStream::connect(addr).await.unwrap();
        let second = TcpStream::connect(other_addr).await.unwrap();
        let admitted = timeout(Duration::from_secs(1), async {
            while slots.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await;
        if admitted.is_err() {
            task.abort();
            other_task.abort();
        }
        assert!(
            admitted.is_ok(),
            "connections did not reserve shared admission slots"
        );
        let mut excess = TcpStream::connect(addr).await.unwrap();
        let mut byte = [0];
        assert_eq!(
            timeout(Duration::from_secs(1), excess.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        drop(first);
        timeout(Duration::from_secs(1), async {
            while slots.available_permits() != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let mut replacement = TcpStream::connect(addr).await.unwrap();
        replacement
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        timeout(
            Duration::from_secs(1),
            replacement.read_to_string(&mut response),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(response.starts_with("HTTP/1.1 200"));
        // Aborting the listener must also drop its in-flight sockets and permits.
        task.abort();
        other_task.abort();
        let _ = task.await;
        let _ = other_task.await;
        drop(second);
        timeout(Duration::from_secs(1), async {
            while slots.available_permits() != 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
}
