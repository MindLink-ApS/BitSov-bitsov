// Semgrep-only fixture: intentionally unsafe examples, never compiled.
fn tls(client: Client) {
    // ruleid: bitsov-cln-insecure-tls
    client.danger_accept_invalid_certs(true);
    // ruleid: bitsov-cln-insecure-tls
    client.tls_built_in_root_certs(true);
    // ruleid: bitsov-cln-insecure-tls
    client.danger_accept_invalid_hostnames(true);
    // ruleid: bitsov-cln-insecure-tls
    client.https_only(false);
    // ok: bitsov-cln-insecure-tls
    client.tls_built_in_root_certs(false);
}
// ruleid: bitsov-cln-rune-debug
#[derive(Debug)]
struct Leaks { rune: String }
// ok: bitsov-cln-rune-debug
#[derive(Clone)]
struct Secret { rune: String }
fn leaks(rune: String, cmd: Command, request: Request) {
    // ruleid: bitsov-cln-rune-exposure
    info!(rune = %rune, "leak");
    // ruleid: bitsov-cln-rune-exposure
    format!("https://localhost/?rune={rune}");
    // ruleid: bitsov-cln-rune-exposure
    cmd.arg(rune);
    // ruleid: bitsov-cln-rune-exposure
    request.json(&rune);
    // ok: bitsov-cln-rune-exposure
    request.header("Rune", self.rune.clone());
    // ok: bitsov-cln-rune-exposure
    f.debug_struct("ClnProvider").field("rune", &"<redacted>");
}
