use std::sync::{Arc, Mutex, OnceLock};

struct InterestFallback;

impl tracing::Subscriber for InterestFallback {
    fn register_callsite(
        &self,
        _: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        tracing::subscriber::Interest::sometimes()
    }

    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        false
    }

    fn max_level_hint(&self) -> Option<tracing::metadata::LevelFilter> {
        None
    }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, _: &tracing::Event<'_>) {}
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

fn preserve_scoped_interest() {
    // Keep a second registrar alive so an initial hit on an uncaptured thread
    // cannot cache Interest::never for all threads. Leave the global default
    // available to tests that capture tasks running on other runtime threads.
    static FALLBACK: OnceLock<tracing::Dispatch> = OnceLock::new();
    FALLBACK.get_or_init(|| tracing::Dispatch::new(InterestFallback));
}

/// Captures this thread's log output, including tasks on its current-thread runtime.
#[derive(Clone, Default)]
pub struct LogBuf(pub Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogBuf {
    type Writer = LogBuf;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

pub fn capture_logs() -> (LogBuf, tracing::subscriber::DefaultGuard) {
    preserve_scoped_interest();
    let buf = LogBuf::default();
    let sub = tracing_subscriber::fmt()
        .with_writer(buf.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::INFO)
        .finish();
    let guard = tracing::subscriber::set_default(sub);
    (buf, guard)
}
