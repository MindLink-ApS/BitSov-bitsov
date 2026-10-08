//! SAS v1: fixed-length binary transcript, never a mnemonic recovery phrase.
use rand::RngCore;
use std::{
    fmt,
    io::{self, Read, Write},
    path::Path,
};
use zeroize::Zeroizing;

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const CLAIM_FILE: &str = "claim-code";

/// A box-local secret. Deliberately neither serializable nor printable.
pub struct ClaimCode(Zeroizing<[u8; 18]>);
impl fmt::Debug for ClaimCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClaimCode([REDACTED])")
    }
}
impl ClaimCode {
    /// Domain-separated commitment. Never return this in a network response.
    pub fn commitment(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"bitsov-claim-code-v1");
        h.update(self.0.as_ref());
        *h.finalize().as_bytes()
    }
    /// Explicit local-console output only. No Display implementation.
    pub fn write_local(&self, out: &mut impl Write) -> io::Result<()> {
        out.write_all(self.0.as_ref())
    }
}
fn checksum(code: &mut [u8; 18]) {
    let hash = blake3::hash(&code[..16]);
    code[16] = ALPHABET[(hash.as_bytes()[0] >> 3) as usize];
    code[17] = ALPHABET[(((hash.as_bytes()[0] & 7) << 2) | (hash.as_bytes()[1] >> 6)) as usize];
}
/// An existing (even unreadable or malformed) claim file prohibits downgrade.
pub fn required(dir: &Path) -> bool {
    !matches!(std::fs::symlink_metadata(dir.join(CLAIM_FILE)), Err(e) if e.kind() == io::ErrorKind::NotFound)
}
/// Read an existing protected local code; reject malformed files without echoing bytes.
pub fn load(dir: &Path) -> io::Result<ClaimCode> {
    let path = dir.join(CLAIM_FILE);
    let meta = std::fs::symlink_metadata(&path)?;
    if !meta.is_file() || meta.len() != 18 {
        return Err(io::Error::other("invalid claim-code file"));
    }
    let mut file = std::fs::File::open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    let mut bytes = Zeroizing::new([0; 18]);
    file.read_exact(bytes.as_mut())?;
    let mut expected = Zeroizing::new(*bytes);
    checksum(&mut expected);
    if bytes.iter().any(|c| !ALPHABET.contains(c)) || *expected != *bytes {
        return Err(io::Error::other("invalid claim-code file"));
    }
    Ok(ClaimCode(bytes))
}
/// Atomically initialize once. Returns whether this caller created the code.
/// A headless process retains it for the explicit owner-console CLI.
pub fn initialize(dir: &Path) -> io::Result<(ClaimCode, bool)> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join(CLAIM_FILE);
    match std::fs::symlink_metadata(&path) {
        Ok(_) => return load(dir).map(|code| (code, false)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let mut code = Zeroizing::new([0; 18]);
    let mut random = Zeroizing::new([0u8; 16]);
    rand::rngs::OsRng.fill_bytes(random.as_mut());
    for (out, byte) in code.iter_mut().zip(random.iter()) {
        *out = ALPHABET[(byte & 31) as usize];
    }
    checksum(&mut code);
    let temporary = dir.join(format!(".claim-{}.tmp", uuid::Uuid::new_v4()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options.open(&temporary)?;
        file.write_all(code.as_ref())?;
        file.sync_all()?;
        let created = match std::fs::hard_link(&temporary, &path) {
            Ok(()) => true,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => false,
            Err(e) => return Err(e),
        };
        crate::pairing::fsync_dir_strict(dir)?;
        load(dir).map(|code| (code, created))
    })();
    let _ = std::fs::remove_file(temporary);
    result
}

/// Authenticated by the server's completed Noise session, never HTTP input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoiseBinding {
    /// Noise XX transcript hash.
    pub handshake_hash: [u8; 32],
    /// Persistent box transport public key (also bound by the Noise pin at SETUP).
    pub box_public_key: [u8; 32],
    /// Initiator static public key used on this connection.
    pub client_static: [u8; 32],
}
/// Full BLAKE3 digest. Compare all 32 bytes at finalization, constant time.
pub fn digest(
    binding: &NoiseBinding,
    device: &[u8; 65],
    nonce: &[u8; 16],
    claim: &[u8; 32],
) -> blake3::Hash {
    let mut h = blake3::Hasher::new();
    for bytes in [
        b"bitsov-sas-v1".as_slice(),
        &binding.handshake_hash,
        &binding.box_public_key,
        &binding.client_static,
        device,
        nonce,
        claim,
    ] {
        h.update(bytes);
    }
    h.finalize()
}
/// First 44 bits, most significant bit first, four BIP-39 English word indices.
pub fn words(digest: &blake3::Hash) -> [&'static str; 4] {
    let mut first = [0; 8];
    first[..6].copy_from_slice(&digest.as_bytes()[..6]);
    let bits = u64::from_be_bytes(first);
    let list = bip39::Language::English.word_list();
    std::array::from_fn(|i| list[((bits >> (64 - 11 * (i + 1))) & 2047) as usize])
}
/// Validate a canonical uncompressed P-256 point before generating a nonce.
pub fn device_key(hex_key: &str) -> Result<[u8; 65], &'static str> {
    let raw: [u8; 65] = hex::decode(hex_key)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or("invalid_device_key")?;
    if raw[0] != 4 {
        return Err("invalid_device_key");
    }
    // Actual curve/possession verification is performed by registration proof validation.
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn claim_is_stable_protected_checksummed_and_redacted() {
        let dir = tempfile::tempdir().unwrap();
        let (code, created) = initialize(dir.path()).unwrap();
        assert!(created);
        let (again, created) = initialize(dir.path()).unwrap();
        assert!(!created);
        assert_eq!(code.commitment(), again.commitment());
        let mut bytes = Vec::new();
        code.write_local(&mut bytes).unwrap();
        assert_eq!(bytes.len(), 18);
        assert!(!format!("{code:?}").contains(std::str::from_utf8(&bytes).unwrap()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(dir.path().join(CLAIM_FILE))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        bytes[17] = if bytes[17] == b'A' { b'B' } else { b'A' };
        std::fs::write(dir.path().join(CLAIM_FILE), &bytes).unwrap();
        assert!(initialize(dir.path()).is_err());
        assert_eq!(std::fs::read(dir.path().join(CLAIM_FILE)).unwrap(), bytes);
    }
    #[test]
    fn concurrent_initializers_publish_one_code() {
        let dir = tempfile::tempdir().unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let tasks: Vec<_> = (0..8)
            .map(|_| {
                let path = dir.path().to_path_buf();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    let (code, created) = initialize(&path).unwrap();
                    (code.commitment(), created)
                })
            })
            .collect();
        let results: Vec<_> = tasks.into_iter().map(|t| t.join().unwrap()).collect();
        assert_eq!(results.iter().filter(|(_, created)| *created).count(), 1);
        assert!(results.iter().all(|(code, _)| *code == results[0].0));
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn claim_rejects_symlink_and_never_rotates() {
        let dir = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        initialize(other.path()).unwrap();
        std::os::unix::fs::symlink(other.path().join(CLAIM_FILE), dir.path().join(CLAIM_FILE))
            .unwrap();
        assert!(initialize(dir.path()).is_err());
    }
    #[test]
    fn word_indices_are_big_endian_and_use_only_44_bits() {
        assert_eq!(words(&blake3::Hash::from([0; 32])), ["abandon"; 4]);
        assert_eq!(words(&blake3::Hash::from([255; 32])), ["zoo"; 4]);
        let mut bytes = [0; 32];
        bytes[5] = 15;
        bytes[6..].fill(255);
        assert_eq!(words(&blake3::Hash::from(bytes)), ["abandon"; 4]);
    }
    #[test]
    fn sas_vector_and_all_fields_bound() {
        let binding = NoiseBinding {
            handshake_hash: std::array::from_fn(|i| i as u8),
            box_public_key: [0x22; 32],
            client_static: [0x33; 32],
        };
        let mut device = [0x44; 65];
        device[0] = 4;
        let nonce = [0x55; 16];
        let claim = [0x66; 32];
        let result = digest(&binding, &device, &nonce, &claim);
        // Frozen vector, cross-checkable using the exact concatenation in the protocol doc.
        assert_eq!(
            result.to_hex().as_str(),
            "960be0e8e070d1089b55da2113669f8530ee396eb36cd0fa04e82cb9ae346f35"
        );
        assert_eq!(words(&result), ["noodle", "gallery", "demand", "science"]);
        let mut b = binding;
        b.handshake_hash[0] ^= 1;
        assert_ne!(digest(&b, &device, &nonce, &claim), result);
        b = binding;
        b.box_public_key[0] ^= 1;
        assert_ne!(digest(&b, &device, &nonce, &claim), result);
        b = binding;
        b.client_static[0] ^= 1;
        assert_ne!(digest(&b, &device, &nonce, &claim), result);
        device[64] ^= 1;
        assert_ne!(digest(&binding, &device, &nonce, &claim), result);
        device[64] ^= 1;
        assert_ne!(digest(&binding, &device, &[0x56; 16], &claim), result);
        assert_ne!(digest(&binding, &device, &nonce, &[0x67; 32]), result);
        assert_eq!(digest(&binding, &device, &nonce, &claim), result);
    }
}
