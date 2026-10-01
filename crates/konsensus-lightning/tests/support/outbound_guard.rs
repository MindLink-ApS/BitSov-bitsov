//! Isolate this regression so the guard also covers LDK's background threads
//! without affecting other tests. Requires the system C compiler used by Cargo.
use std::path::Path;

pub async fn run(test: &str, dir: &Path, core: &str, primary: &str, fallback: &str) -> String {
    assert!(
        cfg!(any(target_os = "macos", target_os = "linux")),
        "the no-fallback network guard requires macOS or Linux"
    );
    let library = dir.join(if cfg!(target_os = "macos") {
        "guard.dylib"
    } else {
        "guard.so"
    });
    let mut compiler = std::process::Command::new("cc");
    compiler
        .args([
            if cfg!(target_os = "macos") {
                "-dynamiclib"
            } else {
                "-shared"
            },
            "-fPIC",
            "-Wall",
            "-Wextra",
            "-Werror",
        ])
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/support/outbound_guard.c"
        ))
        .arg("-o")
        .arg(&library);
    if cfg!(target_os = "linux") {
        compiler.arg("-ldl");
    }
    let compiler = compiler.output().expect("compile network guard");
    assert!(
        compiler.status.success(),
        "{}",
        String::from_utf8_lossy(&compiler.stderr)
    );
    let log = dir.join("outbound.log");
    let output = tokio::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test, "--nocapture"])
        .env(
            if cfg!(target_os = "macos") {
                "DYLD_INSERT_LIBRARIES"
            } else {
                "LD_PRELOAD"
            },
            &library,
        )
        .env("BITSOV_GUARD_LOG", &log)
        .env("BITSOV_GUARD_PORT", core.rsplit(':').next().unwrap())
        .env("BITSOV_GUARD_CORE", core)
        .env("BITSOV_GUARD_PRIMARY", primary)
        .env("BITSOV_GUARD_FALLBACK", fallback)
        // The test's destinations must not depend on the developer's proxy.
        .env_remove("HTTP_PROXY")
        .env_remove("HTTPS_PROXY")
        .env_remove("ALL_PROXY")
        .env_remove("http_proxy")
        .env_remove("https_proxy")
        .env_remove("all_proxy")
        .output()
        .await
        .unwrap();
    let attempts = std::fs::read_to_string(log).expect("guard must record fixture traffic");
    assert!(
        output.status.success(),
        "guarded test failed: {}\n{}\n{}\n{attempts}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!attempts.contains("DENY"), "{attempts}");
    assert!(
        attempts.contains(&format!(
            "ALLOW connect {}",
            core.trim_start_matches("http://")
        )),
        "guard must intercept the actual RPC connections: {attempts}"
    );
    attempts
}

/// Count only actual TCP connection attempts in the isolated child.
pub fn connection_count() -> usize {
    std::fs::read_to_string(std::env::var_os("BITSOV_GUARD_LOG").unwrap())
        .unwrap()
        .lines()
        .filter(|line| line.starts_with("ALLOW connect "))
        .count()
}
