//! Regression coverage for #206. Signals run in child processes, never in the
//! parallel test runner. The LDK lifecycle check needs no chain server or socket.
use super::*;

#[test]
fn stopped_ldk_does_not_report_drop_fallback() {
    let dir = tempfile::tempdir().unwrap();
    let log = tempfile::tempfile().unwrap();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(log.try_clone().unwrap())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    let config = ldk_node::config::Config {
        network: bitcoin::Network::Regtest,
        storage_dir_path: dir.path().to_str().unwrap().to_owned(),
        ..Default::default()
    };
    let mut builder = ldk_node::Builder::from_config(config);
    builder.set_entropy_seed_bytes([42; 64]);
    let node = Arc::new(builder.build().unwrap());
    assert!(!node.status().is_running);
    drop(konsensus_lightning::LdkProvider::from_node(node));
    use std::io::{Read, Seek, SeekFrom};
    let mut log = log;
    log.seek(SeekFrom::Start(0)).unwrap();
    let mut output = String::new();
    log.read_to_string(&mut output).unwrap();
    assert!(!output.contains("panic-path fallback"), "{output}");
}

#[cfg(unix)]
#[test]
fn signals_persist_before_drop() {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    const CHILD: &str = "BITSOV_SHUTDOWN_TEST_CHILD";
    if let Ok(mode) = std::env::var(CHILD) {
        logging::init();
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let signal = shutdown_signal().unwrap();
            let accepting = std::sync::atomic::AtomicBool::new(true);
            let provider = PersistenceProbe {
                accepting: &accepting,
                persisted: Default::default(),
            };
            let startup = async {
                println!("SIGNAL_READY");
                use std::io::Write;
                std::io::stdout().flush().unwrap();
                if mode == "stalled_startup" {
                    std::future::pending::<()>().await;
                }
                let failure = std::future::pending::<Result<()>>();
                let cleanup = async {
                    assert!(provider.persisted.load(std::sync::atomic::Ordering::SeqCst));
                    println!("DRAINED");
                    Ok(())
                };
                Ok((failure, cleanup))
            };
            run_node_lifecycle(
                startup,
                signal,
                || accepting.store(false, std::sync::atomic::Ordering::SeqCst),
                &provider,
            )
            .await
            .unwrap();
            assert!(provider.persisted.load(std::sync::atomic::Ordering::SeqCst));
            drop(provider);
            // Async timeouts do not bound Runtime::drop's blocking-task join.
            if mode == "blocked_runtime" {
                tokio::task::spawn_blocking(|| std::thread::sleep(Duration::from_secs(120)));
            }
        });
        drop(rt);
        return;
    }
    for (signal, mode) in [
        (libc::SIGTERM, "normal"),
        (libc::SIGINT, "normal"),
        (libc::SIGTERM, "stalled_startup"),
        (libc::SIGTERM, "blocked_runtime"),
    ] {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "shutdown_tests::signals_persist_before_drop",
                "--nocapture",
            ])
            .env(CHILD, mode)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        // Readiness uses a pipe, not a guessed delay or a listening socket.
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            use std::io::BufRead;
            let mut output = String::new();
            for line in std::io::BufReader::new(stdout).lines() {
                let line = line.unwrap();
                if line == "SIGNAL_READY" {
                    let _ = tx.send(());
                }
                output.push_str(&line);
                output.push('\n');
            }
            output
        });
        if rx.recv_timeout(Duration::from_secs(10)).is_err() {
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            panic!(
                "child failed before signal registration: {} {}",
                reader.join().unwrap(),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let started = Instant::now();
        // SAFETY: signal only the live child we own, never the test runner.
        assert_eq!(unsafe { libc::kill(child.id() as i32, signal) }, 0);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if started.elapsed() > Duration::from_secs(35) {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("shutdown exceeded its process deadline");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let output = child.wait_with_output().unwrap();
        let stdout = reader.join().unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stdout.contains("panic-path fallback"), "{stdout}");
        assert!(!stderr.contains("panic-path fallback"), "{stderr}");
        assert!(stdout.contains("PERSISTED"), "{stdout}\n{stderr}");
        assert_eq!(
            stdout.contains("DRAINED"),
            mode != "stalled_startup",
            "{stdout}"
        );
        if mode != "blocked_runtime" {
            assert!(status.success(), "{status}: {stdout}\n{stderr}");
            assert!(started.elapsed() < Duration::from_secs(5));
        } else {
            assert_eq!(status.code(), Some(1), "{stdout}\n{stderr}");
            assert!(stderr.contains("shutdown deadline exceeded"), "{stderr}");
        }
    }
}

struct PersistenceProbe<'a> {
    accepting: &'a std::sync::atomic::AtomicBool,
    persisted: std::sync::atomic::AtomicBool,
}

impl Drop for PersistenceProbe<'_> {
    fn drop(&mut self) {
        assert!(
            self.persisted.load(std::sync::atomic::Ordering::SeqCst),
            "panic-path fallback"
        );
    }
}

#[async_trait::async_trait]
impl konsensus_core::traits::lightning::LightningProvider for PersistenceProbe<'_> {
    async fn shutdown(&self) -> Result<(), konsensus_core::traits::lightning::LightningError> {
        use std::sync::atomic::Ordering;
        assert!(
            !self.accepting.load(Ordering::SeqCst),
            "must stop accepting before persistence"
        );
        tokio::task::yield_now().await;
        self.persisted.store(true, Ordering::SeqCst);
        println!("PERSISTED");
        Ok(())
    }
    async fn create_invoice(
        &self,
        _: u64,
        _: &str,
        _: u32,
    ) -> Result<
        konsensus_core::traits::lightning::Invoice,
        konsensus_core::traits::lightning::LightningError,
    > {
        unreachable!()
    }
    async fn pay_invoice(
        &self,
        _: &str,
    ) -> Result<
        konsensus_core::traits::lightning::PaymentDetails,
        konsensus_core::traits::lightning::LightningError,
    > {
        unreachable!()
    }
    async fn get_payment_status(
        &self,
        _: &str,
    ) -> Result<
        konsensus_core::traits::lightning::PaymentDetails,
        konsensus_core::traits::lightning::LightningError,
    > {
        unreachable!()
    }
    async fn get_balance_msat(
        &self,
    ) -> Result<u64, konsensus_core::traits::lightning::LightningError> {
        unreachable!()
    }
    async fn is_available(&self) -> bool {
        unreachable!()
    }
}
