//! Owner-local claim-code lifecycle. Never writes secrets to stdout or tracing.
use anyhow::{Context, Result};
use std::{
    io::{IsTerminal, Write},
    path::Path,
};

fn console() -> Result<std::fs::File> {
    #[cfg(unix)]
    let path = "/dev/tty";
    #[cfg(not(unix))]
    let path = "CONOUT$";
    let tty = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .context("claim code requires an owner console")?;
    anyhow::ensure!(tty.is_terminal(), "claim code requires an owner console");
    Ok(tty)
}
fn check_owner(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: getuid reads process credentials and has no pointer arguments.
        let uid = unsafe { libc::getuid() };
        anyhow::ensure!(
            std::fs::metadata(dir)?.uid() == uid,
            "claim code requires the data-directory owner"
        );
    }
    Ok(())
}
/// Initialize at first init/SETUP; display only on a dedicated terminal.
pub fn initialize(dir: &Path) -> Result<()> {
    let (code, created) = konsensus_api::sas::initialize(dir)?;
    if created {
        if let Ok(mut tty) = console() {
            check_owner(dir)?;
            tty.write_all(b"BitSov claim code (keep with this box): ")?;
            code.write_local(&mut tty)?;
            tty.write_all(b"\n")?;
            tty.flush()?;
        }
    }
    Ok(())
}
/// Explicit owner-console recovery; never stdout, an HTTP route or a socket.
pub fn show(config: &Path) -> Result<()> {
    let dir = crate::owner_cmd::data_dir_of(config);
    check_owner(&dir)?;
    let mut tty = console()?;
    let code = konsensus_api::sas::load(&dir)?;
    code.write_local(&mut tty)?;
    tty.write_all(b"\n")?;
    tty.flush()?;
    Ok(())
}
