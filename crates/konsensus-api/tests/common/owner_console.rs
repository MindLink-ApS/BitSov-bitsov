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

#[allow(dead_code)]
impl OwnerConsole {
    /// The short owner code printed for `op_id`.
    pub fn owner_code(&self, op_id: &str) -> String {
        let text = self.text();
        let mut lines = text.lines();
        let mut found = None;
        while let Some(line) = lines.next() {
            if line.starts_with("To approve, run: konsensus grant --op ")
                && line.split_whitespace().any(|w| w == op_id)
            {
                found = lines
                    .next()
                    .and_then(|l| l.split("type this code when it asks: ").nth(1))
                    .map(str::to_owned);
            }
        }
        found.unwrap_or_else(|| panic!("owner console has no code for {op_id}"))
    }

    /// Everything the owner terminal showed.
    pub fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
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
