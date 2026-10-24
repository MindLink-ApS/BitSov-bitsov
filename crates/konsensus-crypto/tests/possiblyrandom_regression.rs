//! #4719: a supported OS must not silently use the all-zero fallback merely
//! because the getrandom Cargo feature was not explicitly enabled.
//! This is an entropy-availability smoke test, not a cryptographic RNG test.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[test]
fn default_features_use_os_randomness_for_hashdos_and_jitter_defense() {
    let mut first = [0u8; 32];
    let mut second = [0u8; 32];
    possiblyrandom::getpossiblyrandom(&mut first);
    possiblyrandom::getpossiblyrandom(&mut second);
    assert_ne!(
        first, [0; 32],
        "OS randomness unexpectedly fell back to zeros"
    );
    assert_ne!(
        second, [0; 32],
        "OS randomness unexpectedly fell back to zeros"
    );
    assert_ne!(first, second, "independent calls must not be deterministic");
}
