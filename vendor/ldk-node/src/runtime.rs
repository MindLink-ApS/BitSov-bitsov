// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::config::{
	BACKGROUND_TASK_SHUTDOWN_TIMEOUT_SECS, LDK_EVENT_HANDLER_SHUTDOWN_TIMEOUT_SECS,
};
use crate::logger::{log_debug, log_error, log_trace, LdkLogger, Logger};

pub(crate) struct Runtime {
	mode: RuntimeMode,
	background_tasks: Mutex<JoinSet<()>>,
	cancellable_background_tasks: Mutex<CancellableBackgroundTasks>,
	background_processor_task: Mutex<Option<JoinHandle<()>>>,
	logger: Arc<Logger>,
}

/// Cancellable tasks are tracked without keeping a handle to them, so a task's resources are
/// released as soon as it finishes rather than when the runtime shuts down.
struct CancellableBackgroundTasks {
	tasks: TaskTracker,
	cancellation_token: CancellationToken,
}

impl CancellableBackgroundTasks {
	fn new() -> Self {
		Self { tasks: TaskTracker::new(), cancellation_token: CancellationToken::new() }
	}
}

impl Drop for CancellableBackgroundTasks {
	fn drop(&mut self) {
		// Like dropping a `JoinSet`, this cancels every task still running.
		self.tasks.close();
		self.cancellation_token.cancel();
	}
}

impl Runtime {
	pub fn new(logger: Arc<Logger>) -> Result<Self, std::io::Error> {
		let mode = match tokio::runtime::Handle::try_current() {
			Ok(handle) => RuntimeMode::Handle(handle),
			Err(_) => {
				let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
				RuntimeMode::Owned(rt)
			},
		};
		let background_tasks = Mutex::new(JoinSet::new());
		let cancellable_background_tasks = Mutex::new(CancellableBackgroundTasks::new());
		let background_processor_task = Mutex::new(None);

		Ok(Self {
			mode,
			background_tasks,
			cancellable_background_tasks,
			background_processor_task,
			logger,
		})
	}

	pub fn with_handle(handle: tokio::runtime::Handle, logger: Arc<Logger>) -> Self {
		let mode = RuntimeMode::Handle(handle);
		let background_tasks = Mutex::new(JoinSet::new());
		let cancellable_background_tasks = Mutex::new(CancellableBackgroundTasks::new());
		let background_processor_task = Mutex::new(None);

		Self {
			mode,
			background_tasks,
			cancellable_background_tasks,
			background_processor_task,
			logger,
		}
	}

	pub fn spawn_background_task<F>(&self, future: F)
	where
		F: Future<Output = ()> + Send + 'static,
	{
		let mut background_tasks = self.background_tasks.lock().unwrap();
		let runtime_handle = self.handle();
		// Since it seems to make a difference to `tokio` (see
		// https://docs.rs/tokio/latest/tokio/time/fn.timeout.html#panics) we make sure the futures
		// are always put in an `async` / `.await` closure.
		background_tasks.spawn_on(async { future.await }, runtime_handle);
	}

	pub fn spawn_cancellable_background_task<F>(&self, future: F)
	where
		F: Future<Output = ()> + Send + 'static,
	{
		let cancellable_background_tasks = self.cancellable_background_tasks.lock().unwrap();
		if cancellable_background_tasks.tasks.is_closed() {
			// The node is stopping or stopped. A task spawned now would escape the cancellation
			// already in progress, so it is dropped without being polled.
			drop(cancellable_background_tasks);
			log_trace!(
				self.logger,
				"Ignoring cancellable background task spawned during shutdown."
			);
			return;
		}
		let runtime_handle = self.handle();
		let cancellation_token = cancellable_background_tasks.cancellation_token.clone();
		// Since it seems to make a difference to `tokio` (see
		// https://docs.rs/tokio/latest/tokio/time/fn.timeout.html#panics) we make sure the futures
		// are always put in an `async` / `.await` closure. Dropping the returned handle detaches
		// the task; the tracker keeps tracking it until it finishes.
		drop(cancellable_background_tasks.tasks.spawn_on(
			async move {
				tokio::select! {
					biased;
					_ = cancellation_token.cancelled() => {},
					_ = future => {},
				}
			},
			runtime_handle,
		));
	}

	/// Accepts cancellable tasks again after a stop, in a fresh set. Called when the node starts.
	pub fn allow_cancellable_background_task_spawns(&self) {
		let mut cancellable_background_tasks = self.cancellable_background_tasks.lock().unwrap();
		if cancellable_background_tasks.tasks.is_closed() {
			// A stop may still be waiting on the previous tracker, so start a new set rather than
			// reopening that one.
			*cancellable_background_tasks = CancellableBackgroundTasks::new();
		}
	}

	#[cfg(test)]
	pub(crate) fn cancellable_background_task_count(&self) -> usize {
		self.cancellable_background_tasks.lock().unwrap().tasks.len()
	}

	#[cfg(test)]
	fn current_cancellable_tracker(&self) -> TaskTracker {
		self.cancellable_background_tasks.lock().unwrap().tasks.clone()
	}

	pub fn spawn_background_processor_task<F>(&self, future: F)
	where
		F: Future<Output = ()> + Send + 'static,
	{
		let mut background_processor_task = self.background_processor_task.lock().unwrap();
		debug_assert!(background_processor_task.is_none(), "Expected no background processor_task");

		let runtime_handle = self.handle();
		let handle = runtime_handle.spawn(future);
		*background_processor_task = Some(handle);
	}

	pub fn spawn_blocking<F, R>(&self, func: F) -> JoinHandle<R>
	where
		F: FnOnce() -> R + Send + 'static,
		R: Send + 'static,
	{
		let handle = self.handle();
		handle.spawn_blocking(func)
	}

	pub fn block_on<F: Future>(&self, future: F) -> F::Output {
		// While we generally decided not to overthink via which call graph users would enter our
		// runtime context, we'd still try to reuse whatever current context would be present
		// during `block_on`, as this is the context `block_in_place` would operate on. So we try
		// to detect the outer context here, and otherwise use whatever was set during
		// initialization.
		let handle = tokio::runtime::Handle::try_current().unwrap_or(self.handle().clone());
		// Since it seems to make a difference to `tokio` (see
		// https://docs.rs/tokio/latest/tokio/time/fn.timeout.html#panics) we make sure the futures
		// are always put in an `async` / `.await` closure.
		tokio::task::block_in_place(move || handle.block_on(async { future.await }))
	}

	pub fn abort_cancellable_background_tasks(&self) {
		// Closing the tracker refuses further spawns until the node starts again, so a task that
		// spawns while this stop is in progress cannot outlive it.
		let tracker = {
			let cancellable_background_tasks = self.cancellable_background_tasks.lock().unwrap();
			cancellable_background_tasks.tasks.close();
			cancellable_background_tasks.cancellation_token.cancel();
			cancellable_background_tasks.tasks.clone()
		};
		self.block_on(tracker.wait())
	}

	pub fn wait_on_background_tasks(&self) {
		let mut tasks = core::mem::take(&mut *self.background_tasks.lock().unwrap());
		debug_assert!(tasks.len() > 0, "Expected some background_tasks");
		self.block_on(async {
			loop {
				let timeout_fut = tokio::time::timeout(
					Duration::from_secs(BACKGROUND_TASK_SHUTDOWN_TIMEOUT_SECS),
					tasks.join_next_with_id(),
				);
				match timeout_fut.await {
					Ok(Some(Ok((id, _)))) => {
						log_trace!(self.logger, "Stopped background task with id {}", id);
					},
					Ok(Some(Err(e))) => {
						tasks.abort_all();
						log_trace!(self.logger, "Stopping background task failed: {}", e);
						break;
					},
					Ok(None) => {
						log_debug!(self.logger, "Stopped all background tasks");
						break;
					},
					Err(e) => {
						tasks.abort_all();
						log_error!(self.logger, "Stopping background task timed out: {}", e);
						break;
					},
				}
			}
		})
	}

	pub fn wait_on_background_processor_task(&self) {
		if let Some(background_processor_task) =
			self.background_processor_task.lock().unwrap().take()
		{
			let abort_handle = background_processor_task.abort_handle();
			// Since it seems to make a difference to `tokio` (see
			// https://docs.rs/tokio/latest/tokio/time/fn.timeout.html#panics) we make sure the futures
			// are always put in an `async` / `.await` closure.
			let timeout_res = self.block_on(async {
				tokio::time::timeout(
					Duration::from_secs(LDK_EVENT_HANDLER_SHUTDOWN_TIMEOUT_SECS),
					background_processor_task,
				)
				.await
			});

			match timeout_res {
				Ok(stop_res) => match stop_res {
					Ok(()) => log_debug!(self.logger, "Stopped background processing of events."),
					Err(e) => {
						abort_handle.abort();
						log_error!(
							self.logger,
							"Stopping event handling failed. This should never happen: {}",
							e
						);
						panic!("Stopping event handling failed. This should never happen.");
					},
				},
				Err(e) => {
					abort_handle.abort();
					log_error!(self.logger, "Stopping event handling timed out: {}", e);
				},
			}
		} else {
			debug_assert!(false, "Expected a background processing task");
		};
	}

	#[cfg(tokio_unstable)]
	pub fn log_metrics(&self) {
		let runtime_handle = self.handle();
		log_trace!(
			self.logger,
			"Active runtime tasks left prior to shutdown: {}",
			runtime_handle.metrics().active_tasks_count()
		);
	}

	fn handle(&self) -> &tokio::runtime::Handle {
		match &self.mode {
			RuntimeMode::Owned(rt) => rt.handle(),
			RuntimeMode::Handle(handle) => handle,
		}
	}
}

enum RuntimeMode {
	Owned(tokio::runtime::Runtime),
	Handle(tokio::runtime::Handle),
}

#[cfg(test)]
mod tests {
	use tokio::sync::{mpsc, oneshot};

	use super::*;

	struct DropNotifier(Option<oneshot::Sender<()>>);

	impl Drop for DropNotifier {
		fn drop(&mut self) {
			if let Some(sender) = self.0.take() {
				let _ = sender.send(());
			}
		}
	}

	fn test_runtime() -> Runtime {
		Runtime::new(Arc::new(Logger::new_log_facade())).expect("test runtime")
	}

	#[test]
	fn completed_cancellable_tasks_are_released_before_shutdown() {
		const TASK_COUNT: usize = 64;

		let runtime = test_runtime();
		let (completion_sender, mut completion_receiver) = mpsc::channel(TASK_COUNT);
		for _ in 0..TASK_COUNT {
			let completion_sender = completion_sender.clone();
			runtime.spawn_cancellable_background_task(async move {
				completion_sender.send(()).await.expect("completion receiver should be open");
			});
		}
		drop(completion_sender);

		let released = runtime.block_on(async {
			for _ in 0..TASK_COUNT {
				completion_receiver.recv().await.expect("cancellable task should complete");
			}
			tokio::time::timeout(Duration::from_secs(1), async {
				while runtime.cancellable_background_task_count() != 0 {
					tokio::task::yield_now().await;
				}
			})
			.await
			.is_ok()
		});
		assert!(released, "completed cancellable tasks should be released before shutdown");
	}

	#[test]
	fn abort_cancels_running_tasks_and_restart_accepts_spawns() {
		let runtime = test_runtime();
		let (started_sender, started_receiver) = oneshot::channel();
		let (dropped_sender, dropped_receiver) = oneshot::channel();
		runtime.spawn_cancellable_background_task(async move {
			let _drop_notifier = DropNotifier(Some(dropped_sender));
			let _ = started_sender.send(());
			std::future::pending::<()>().await;
		});
		runtime.block_on(async { started_receiver.await.expect("task should start") });

		runtime.abort_cancellable_background_tasks();
		assert_eq!(runtime.cancellable_background_task_count(), 0);
		runtime.block_on(async {
			dropped_receiver.await.expect("aborted task should be dropped before abort returns");
		});

		// A task spawned after the stop is never polled.
		let (late_sender, late_receiver) = oneshot::channel::<()>();
		runtime.spawn_cancellable_background_task(async move {
			let _ = late_sender.send(());
		});
		assert_eq!(runtime.cancellable_background_task_count(), 0);
		let late_was_polled = runtime.block_on(async {
			matches!(
				tokio::time::timeout(Duration::from_millis(200), late_receiver).await,
				Ok(Ok(()))
			)
		});
		assert!(!late_was_polled, "a task spawned after stop should not be polled");

		// After a restart, spawned tasks run normally.
		runtime.allow_cancellable_background_task_spawns();
		let (ran_sender, ran_receiver) = oneshot::channel();
		runtime.spawn_cancellable_background_task(async move {
			let _ = ran_sender.send(());
		});
		runtime.block_on(async {
			tokio::time::timeout(Duration::from_secs(1), ran_receiver)
				.await
				.expect("later task should run")
				.expect("later task should send");
		});
		runtime.abort_cancellable_background_tasks();
	}

	#[test]
	fn task_spawned_while_stopping_does_not_outlive_the_stop() {
		let runtime = Arc::new(test_runtime());
		let (started_sender, started_receiver) = std::sync::mpsc::sync_channel(1);
		let (release_sender, release_receiver) = std::sync::mpsc::sync_channel::<()>(1);
		let (child_polled_sender, mut child_polled_receiver) = oneshot::channel::<()>();
		let parent_runtime = Arc::clone(&runtime);
		runtime.spawn_cancellable_background_task(async move {
			started_sender.send(()).expect("test should still be running");
			// Stay inside this poll until the stop has begun, then spawn a child that would run
			// forever.
			release_receiver.recv().expect("test should release the parent");
			parent_runtime.spawn_cancellable_background_task(async move {
				let _ = child_polled_sender.send(());
				std::future::pending::<()>().await;
			});
			std::future::pending::<()>().await;
		});
		started_receiver.recv_timeout(Duration::from_secs(5)).expect("parent should start");

		let stopping_tracker = runtime.current_cancellable_tracker();
		let abort_runtime = Arc::clone(&runtime);
		let abort_thread =
			std::thread::spawn(move || abort_runtime.abort_cancellable_background_tasks());
		let deadline = std::time::Instant::now() + Duration::from_secs(5);
		while !stopping_tracker.is_closed() {
			assert!(std::time::Instant::now() < deadline, "stop should close the tracker");
			std::thread::yield_now();
		}
		release_sender.send(()).expect("parent should be waiting");
		abort_thread.join().expect("stop should finish");

		assert_eq!(
			runtime.cancellable_background_task_count(),
			0,
			"no cancellable task should remain tracked after stop"
		);
		assert!(
			child_polled_receiver.try_recv().is_err(),
			"a task spawned while stopping should not be polled"
		);
	}

	#[test]
	fn dropping_runtime_cancels_tracked_tasks() {
		let tokio_runtime =
			tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("test runtime");
		let runtime = Runtime::with_handle(
			tokio_runtime.handle().clone(),
			Arc::new(Logger::new_log_facade()),
		);
		let (started_sender, started_receiver) = oneshot::channel();
		let (dropped_sender, dropped_receiver) = oneshot::channel();
		runtime.spawn_cancellable_background_task(async move {
			let _drop_notifier = DropNotifier(Some(dropped_sender));
			let _ = started_sender.send(());
			std::future::pending::<()>().await;
		});
		tokio_runtime.block_on(async { started_receiver.await.expect("task should start") });

		drop(runtime);

		let dropped = tokio_runtime.block_on(async {
			matches!(
				tokio::time::timeout(Duration::from_secs(1), dropped_receiver).await,
				Ok(Ok(()))
			)
		});
		assert!(dropped, "dropping the runtime should cancel tracked tasks");
	}
}
