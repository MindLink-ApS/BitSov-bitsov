//! Stable OS identity probes. No hostname, boot ID or random fallback.
//! On Linux the volume id is `statfs` `f_fsid`; on XFS and F2FS that value is
//! derived from the device number, so renumbering a device can change the binding.
use anyhow::{Context, Result};
use std::path::Path;

fn valid_uuid(text: &str) -> Result<String> {
    let id = uuid::Uuid::parse_str(text.trim()).context("missing or invalid platform UUID")?;
    anyhow::ensure!(
        !id.is_nil() && id != uuid::Uuid::max(),
        "platform UUID is unset"
    );
    Ok(id.simple().to_string())
}

#[cfg(target_os = "linux")]
fn machine_id() -> Result<String> {
    let text = match std::fs::read_to_string("/etc/machine-id") {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::read_to_string("/var/lib/dbus/machine-id")
                .context("neither /etc/machine-id nor /var/lib/dbus/machine-id is available")?
        }
        Err(e) => return Err(e).context("cannot read /etc/machine-id"),
    };
    valid_uuid(&text).context("provision a persistent unique machine-id before starting")
}

#[cfg(target_os = "macos")]
fn machine_id() -> Result<String> {
    let output = std::process::Command::new("/usr/sbin/ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output()
        .context("cannot read IOPlatformUUID using /usr/sbin/ioreg")?;
    anyhow::ensure!(
        output.status.success(),
        "ioreg could not read IOPlatformUUID"
    );
    parse_ioreg(&String::from_utf8(output.stdout)?)
}

#[cfg(any(target_os = "macos", test))]
fn parse_ioreg(text: &str) -> Result<String> {
    let value = text
        .lines()
        .find_map(|line| {
            let (key, value) = line.trim().split_once(" = ")?;
            (key == "\"IOPlatformUUID\"").then_some(value)
        })
        .context("IOPlatformUUID missing")?;
    valid_uuid(value.trim_matches('"'))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn identity(dir: &Path) -> Result<(String, String)> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    let machine = machine_id()?;
    let path = CString::new(dir.as_os_str().as_bytes())?;
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: NUL-terminated path and correctly sized writable output. Read only on success.
    anyhow::ensure!(
        unsafe { libc::statfs(path.as_ptr(), stat.as_mut_ptr()) } == 0,
        "cannot identify data filesystem: {}",
        std::io::Error::last_os_error()
    );
    let stat = unsafe { stat.assume_init() };

    #[cfg(target_os = "linux")]
    let volume = {
        // SAFETY: Linux fsid_t is a repr(C) pair of c_int with no padding.
        // Encode the words explicitly so the persisted representation is endian-independent.
        let words: [libc::c_int; 2] = unsafe { std::mem::transmute(stat.f_fsid) };
        anyhow::ensure!(words != [0, 0], "filesystem returned an unset ID");
        format!("linux-fsid:{:08x}{:08x}", words[0] as u32, words[1] as u32)
    };
    #[cfg(target_os = "macos")]
    let volume = {
        let mut attrs = libc::attrlist {
            bitmapcount: libc::ATTR_BIT_MAP_COUNT,
            reserved: 0,
            commonattr: 0,
            volattr: libc::ATTR_VOL_INFO | libc::ATTR_VOL_UUID,
            dirattr: 0,
            fileattr: 0,
            forkattr: 0,
        };
        // getattrlist's packed output: u32 byte count followed by a 16-byte UUID.
        #[repr(C)]
        struct VolumeUuid {
            length: u32,
            uuid: [u8; 16],
        }
        let mut out = VolumeUuid {
            length: 0,
            uuid: [0; 16],
        };
        // SAFETY: statfs returned the NUL-terminated mount path. Attribute/output
        // buffers match the requested volume UUID ABI and live for the call.
        anyhow::ensure!(
            unsafe {
                libc::getattrlist(
                    stat.f_mntonname.as_ptr(),
                    (&mut attrs as *mut libc::attrlist).cast(),
                    (&mut out as *mut VolumeUuid).cast(),
                    std::mem::size_of::<VolumeUuid>(),
                    0,
                )
            } == 0,
            "cannot read volume UUID: {}",
            std::io::Error::last_os_error()
        );
        anyhow::ensure!(
            out.length as usize == std::mem::size_of::<VolumeUuid>(),
            "volume UUID unavailable"
        );
        format!(
            "macos-volume:{}",
            valid_uuid(&uuid::Uuid::from_bytes(out.uuid).to_string())?
        )
    };
    Ok((machine, volume))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(super) fn identity(_dir: &Path) -> Result<(String, String)> {
    anyhow::bail!("host binding supports Linux and macOS only")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_unset_and_malformed_platform_ids_refuse() {
        for value in [
            "",
            "uninitialized",
            "host-name",
            "00000000000000000000000000000000",
            "ffffffffffffffffffffffffffffffff",
        ] {
            assert!(valid_uuid(value).is_err());
        }
        assert_eq!(
            valid_uuid("01234567-89AB-CDEF-0123-456789ABCDEF\n").unwrap(),
            "0123456789abcdef0123456789abcdef"
        );
        assert!(
            parse_ioreg("\"SomeOtherUUID\" = \"01234567-89AB-CDEF-0123-456789ABCDEF\"").is_err()
        );
        assert_eq!(
            parse_ioreg("    \"IOPlatformUUID\" = \"01234567-89AB-CDEF-0123-456789ABCDEF\"")
                .unwrap(),
            "0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn native_identity_is_available_and_stable() {
        let dir = tempfile::tempdir().unwrap();
        let a = identity(dir.path()).unwrap();
        let b = identity(dir.path()).unwrap();
        assert_eq!(a, b);
        assert!(!a.0.is_empty() && !a.1.is_empty());
    }
}
