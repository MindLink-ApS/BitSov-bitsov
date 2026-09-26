use std::io::{self, Write};
use std::sync::{Arc, Mutex};

/// Captures the trusted terminal separately from HTTP responses and data_dir.
#[derive(Clone, Default)]
pub struct OwnerConsole(Arc<Mutex<Vec<u8>>>);

impl OwnerConsole {
    pub fn confirmation(&self, label: &str) -> String {
        let text = String::from_utf8(self.0.lock().unwrap().clone()).unwrap();
        text.lines()
            .filter(|line| line.starts_with(&format!("{label} CODE ")))
            .next_back()
            .unwrap_or_else(|| panic!("owner console has no confirmation for {label}"))
            .to_owned()
    }
}

impl Write for OwnerConsole {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
