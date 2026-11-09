// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Accept loop for inbound peer connections.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;

use crate::logger::{log_debug, log_error, log_trace, LdkLogger, Logger};
use crate::runtime::Runtime;

// How long the accept loop pauses after a failed `accept`, so a persistent error (such as running
// out of file descriptors) does not turn into a busy loop.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);

/// Accepts inbound connections on `listener` until `stop_listen` fires and hands each accepted
/// socket to `handle_connection`, which runs as a cancellable runtime task.
///
/// Every handled connection holds one permit of `connection_slots` until its task ends. A socket
/// accepted while no permit is available is closed right away. Only newly accepted sockets are
/// affected: connections that are already being handled keep running, and outbound connections
/// do not use this accept loop at all.
pub(crate) fn spawn_inbound_listener<H, Fut>(
	runtime: &Arc<Runtime>, listener: tokio::net::TcpListener, connection_slots: Arc<Semaphore>,
	mut stop_listen: tokio::sync::watch::Receiver<()>, logger: Arc<Logger>, handle_connection: H,
) where
	H: Fn(tokio::net::TcpStream) -> Fut + Send + Sync + 'static,
	Fut: Future<Output = ()> + Send + 'static,
{
	let task_runtime = Arc::clone(runtime);
	runtime.spawn_cancellable_background_task(async move {
		loop {
			tokio::select! {
				_ = stop_listen.changed() => {
					log_debug!(logger, "Stopping listening to inbound connections.");
					break;
				}
				res = listener.accept() => {
					let tcp_stream = match res {
						Ok((tcp_stream, _)) => tcp_stream,
						Err(e) => {
							log_error!(logger, "Failed to accept inbound connection: {}", e);
							tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
							continue;
						},
					};
					let slot = match Arc::clone(&connection_slots).try_acquire_owned() {
						Ok(slot) => slot,
						Err(_) => {
							log_trace!(logger, "Closing an inbound connection: too many are open.");
							drop(tcp_stream);
							continue;
						},
					};
					let connection = handle_connection(tcp_stream);
					task_runtime.spawn_cancellable_background_task(async move {
						connection.await;
						drop(slot);
					});
				}
			}
		}
	});
}

#[cfg(test)]
mod tests {
	use std::io::{Read, Write};
	use std::sync::atomic::{AtomicUsize, Ordering};
	use std::time::Instant;

	use tokio::io::AsyncReadExt;

	use super::*;
	use crate::config::MAX_CONCURRENT_INBOUND_CONNECTIONS;

	const CONNECTIONS: usize = 200;

	struct Fixture {
		runtime: Arc<Runtime>,
		addr: std::net::SocketAddr,
		slots: Arc<Semaphore>,
		started: Arc<AtomicUsize>,
		finished: Arc<AtomicUsize>,
		_stop_sender: tokio::sync::watch::Sender<()>,
	}

	impl Fixture {
		fn new(slots: usize) -> Self {
			let runtime =
				Arc::new(Runtime::new(Arc::new(Logger::new_log_facade())).expect("test runtime"));
			let listener = runtime
				.block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
				.expect("bind an ephemeral loopback port");
			let addr = listener.local_addr().expect("listener address");
			let (stop_sender, stop_listen) = tokio::sync::watch::channel(());
			let slots = Arc::new(Semaphore::new(slots));
			let started = Arc::new(AtomicUsize::new(0));
			let finished = Arc::new(AtomicUsize::new(0));
			let (handler_started, handler_finished) = (Arc::clone(&started), Arc::clone(&finished));
			spawn_inbound_listener(
				&runtime,
				listener,
				Arc::clone(&slots),
				stop_listen,
				Arc::new(Logger::new_log_facade()),
				move |tcp_stream| {
					let started = Arc::clone(&handler_started);
					let finished = Arc::clone(&handler_finished);
					async move {
						started.fetch_add(1, Ordering::SeqCst);
						read_to_eof(tcp_stream).await;
						finished.fetch_add(1, Ordering::SeqCst);
					}
				},
			);
			Self { runtime, addr, slots, started, finished, _stop_sender: stop_sender }
		}

		fn connect(&self) -> std::net::TcpStream {
			std::net::TcpStream::connect(self.addr).expect("connect")
		}
	}

	// Reads until the remote side closes, like a peer connection does.
	async fn read_to_eof(mut tcp_stream: tokio::net::TcpStream) {
		let mut buf = [0u8; 64];
		while matches!(tcp_stream.read(&mut buf).await, Ok(n) if n > 0) {}
	}

	fn wait_until(what: &str, mut condition: impl FnMut() -> bool) {
		let deadline = Instant::now() + Duration::from_secs(10);
		while !condition() {
			assert!(Instant::now() < deadline, "timed out waiting until {}", what);
			std::thread::sleep(Duration::from_millis(5));
		}
	}

	// Whether the server closed this connection within `wait`, rather than keeping it open.
	fn closed_by_server(client: &mut std::net::TcpStream, wait: Duration) -> bool {
		client.set_read_timeout(Some(wait)).expect("read timeout");
		let mut buf = [0u8; 1];
		match client.read(&mut buf) {
			Ok(0) => true,
			Ok(_) => false,
			Err(e) => {
				!matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut)
			},
		}
	}

	#[test]
	fn finished_inbound_connection_tasks_are_released() {
		let fixture = Fixture::new(MAX_CONCURRENT_INBOUND_CONNECTIONS);

		for _ in 0..CONNECTIONS {
			drop(fixture.connect());
		}
		wait_until("every connection task finished", || {
			fixture.finished.load(Ordering::SeqCst) == CONNECTIONS
		});

		// Only the accept loop itself remains tracked.
		let mut retained = usize::MAX;
		let deadline = Instant::now() + Duration::from_secs(5);
		while Instant::now() < deadline {
			retained = fixture.runtime.cancellable_background_task_count();
			if retained <= 1 {
				break;
			}
			std::thread::sleep(Duration::from_millis(5));
		}
		assert!(
			retained <= 1,
			"{} cancellable tasks retained after {} connections finished",
			retained,
			CONNECTIONS
		);
		assert_eq!(fixture.slots.available_permits(), MAX_CONCURRENT_INBOUND_CONNECTIONS);
	}

	#[test]
	fn connections_beyond_the_limit_are_closed_and_slots_are_reused() {
		const SLOTS: usize = 4;
		let fixture = Fixture::new(SLOTS);

		let mut held: Vec<_> = (0..SLOTS).map(|_| fixture.connect()).collect();
		wait_until("all slots in use", || fixture.started.load(Ordering::SeqCst) == SLOTS);

		let mut excess = fixture.connect();
		assert!(
			closed_by_server(&mut excess, Duration::from_secs(5)),
			"a connection beyond the limit should be closed"
		);
		assert_eq!(fixture.started.load(Ordering::SeqCst), SLOTS);

		// Connections that were already being handled are unaffected.
		for client in held.iter_mut() {
			client.write_all(b"x").expect("held connection still writable");
			assert!(
				!closed_by_server(client, Duration::from_millis(300)),
				"a held connection should stay open"
			);
		}

		// Closing one held connection frees its slot for the next inbound connection.
		drop(held.pop());
		wait_until("the closed connection finished", || {
			fixture.finished.load(Ordering::SeqCst) == 1
		});
		let mut next = fixture.connect();
		wait_until("the next connection is handled", || {
			fixture.started.load(Ordering::SeqCst) == SLOTS + 1
		});
		assert!(
			!closed_by_server(&mut next, Duration::from_millis(300)),
			"a connection within the limit should stay open"
		);
	}

	#[test]
	fn stopping_cancels_open_inbound_connections() {
		const OPEN: usize = 3;
		let fixture = Fixture::new(MAX_CONCURRENT_INBOUND_CONNECTIONS);

		let mut open: Vec<_> = (0..OPEN).map(|_| fixture.connect()).collect();
		wait_until("connections handled", || fixture.started.load(Ordering::SeqCst) == OPEN);
		assert_eq!(fixture.runtime.cancellable_background_task_count(), OPEN + 1);

		fixture.runtime.abort_cancellable_background_tasks();

		assert_eq!(fixture.runtime.cancellable_background_task_count(), 0);
		assert_eq!(fixture.slots.available_permits(), MAX_CONCURRENT_INBOUND_CONNECTIONS);
		for client in open.iter_mut() {
			assert!(
				closed_by_server(client, Duration::from_secs(5)),
				"stopping should close open connections"
			);
		}
		assert_eq!(fixture.finished.load(Ordering::SeqCst), 0, "handlers were cancelled");
	}
}
