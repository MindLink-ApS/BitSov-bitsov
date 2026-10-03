//! Preserve LDK's filesystem log format and level policy with bounded storage.
use konsensus_core::logging::{LoggingConfig, RotatingLog};
use ldk_node::logger::{LogLevel, LogRecord, LogWriter};
use std::{
    io::{self, Write},
    path::Path,
};

pub(crate) struct BoundedLdkLogger {
    writer: RotatingLog,
    level: LogLevel,
}
impl BoundedLdkLogger {
    pub(crate) fn open(path: &Path, config: LoggingConfig, level: LogLevel) -> io::Result<Self> {
        Ok(Self {
            writer: RotatingLog::open(path, config)?,
            level,
        })
    }
}
impl LogWriter for BoundedLdkLogger {
    fn log(&self, record: LogRecord<'_>) {
        if record.level < self.level {
            return;
        }
        let line = format!(
            "{} {:<5} [{}:{}] {}\n",
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S%.3f"),
            record.level.to_string(),
            record.module_path,
            record.line,
            record.args
        );
        if self.writer.clone().write_all(line.as_bytes()).is_err() {
            // Never fall back to emitting the record or backend error details.
            eprintln!("failed to write bounded LDK log");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ldk_writer_rotates_and_keeps_private_invoice_filter() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ldk_node.log");
        let writer = BoundedLdkLogger::open(
            &path,
            LoggingConfig {
                max_file_size_bytes: 128.try_into().unwrap(),
                max_files: 3.try_into().unwrap(),
            },
            LogLevel::Warn,
        )
        .unwrap();
        for _ in 0..30 {
            writer.log(LogRecord {
                level: LogLevel::Info,
                args: format_args!("private-invoice-canary"),
                module_path: "test",
                line: 1,
            });
            writer.log(LogRecord {
                level: LogLevel::Warn,
                args: format_args!("safe bounded diagnostic"),
                module_path: "test",
                line: 2,
            });
        }
        assert!(dir.path().join("ldk_node.log.2").exists());
        let logs: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| std::fs::read(e.unwrap().path()).unwrap())
            .collect();
        assert_eq!(logs.len(), 3);
        assert!(logs.iter().all(|b| b.len() <= 128));
        assert!(logs.iter().map(Vec::len).sum::<usize>() <= 384);
        for log in logs {
            let text = String::from_utf8(log).unwrap();
            assert!(text.contains("safe bounded diagnostic"));
            assert!(!text.contains("private-invoice-canary"));
        }
    }
}
