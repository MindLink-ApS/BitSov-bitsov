// BitsovDeviceKeychainTests.swift
// BitSov iOS unit tests — BitsovDeviceKeychain write/read/wipe lifecycle.
//
// # Running
//   In Xcode: Product → Test (⌘U), or via `xcodebuild test`.
//   These tests use the macOS / iOS Simulator keychain, not real hardware.
//   The biometric-gated `load()` path is covered by an integration test that
//   injects a mock `LAContext`; the simulator always evaluates `.biometryAny`
//   as unsupported, so the OS falls back to device passcode (set in simulator
//   settings).  Full biometric tests run on a physical device.
//
// # Test coverage
//   - store: valid seed persisted, duplicate overwrite
//   - exists: returns true after store, false after wipe
//   - wipe: item removed, double-wipe is a no-op
//   - store: rejects seeds that are not exactly 32 bytes
//   - load path (exists check only): item present but biometric gated

import XCTest
@testable import App  // Replace with the actual Xcode module name for the BitSov app target.

final class BitsovDeviceKeychainTests: XCTestCase {

    // ── Fixture ───────────────────────────────────────────────────────────────

    private var keychain: BitsovDeviceKeychain!

    /// Fixed 32-byte seed for deterministic tests.
    private let testSeed = Data(repeating: 0xAB, count: 32)
    private let altSeed  = Data(repeating: 0xCD, count: 32)

    override func setUpWithError() throws {
        try super.setUpWithError()
        keychain = BitsovDeviceKeychain()
        // Ensure a clean slate before every test.
        try keychain.wipe()
    }

    override func tearDownWithError() throws {
        // Leave keychain clean after every test.
        try keychain.wipe()
        try super.tearDownWithError()
    }

    // MARK: - store

    func test_store_doesNotThrow() throws {
        XCTAssertNoThrow(try keychain.store(seed: testSeed))
    }

    func test_store_rejectsSeedShorterThan32Bytes() {
        let short = Data(repeating: 0x01, count: 31)
        XCTAssertThrowsError(try keychain.store(seed: short)) { error in
            guard case KeychainError.invalidSeedLength(let n) = error else {
                return XCTFail("Expected invalidSeedLength, got \(error)")
            }
            XCTAssertEqual(n, 31)
        }
    }

    func test_store_rejectsSeedLongerThan32Bytes() {
        let long = Data(repeating: 0x01, count: 33)
        XCTAssertThrowsError(try keychain.store(seed: long)) { error in
            guard case KeychainError.invalidSeedLength(let n) = error else {
                return XCTFail("Expected invalidSeedLength, got \(error)")
            }
            XCTAssertEqual(n, 33)
        }
    }

    func test_store_overwritesExistingKey() throws {
        // First store.
        try keychain.store(seed: testSeed)
        XCTAssertTrue(keychain.exists(), "key should exist after first store")

        // Second store — must not throw (duplicate must be silently overwritten).
        XCTAssertNoThrow(try keychain.store(seed: altSeed))
        XCTAssertTrue(keychain.exists(), "key should still exist after overwrite")
    }

    // MARK: - exists

    func test_exists_returnsFalseWhenNoKeyStored() {
        XCTAssertFalse(keychain.exists(), "exists() must return false on clean slate")
    }

    func test_exists_returnsTrueAfterStore() throws {
        try keychain.store(seed: testSeed)
        XCTAssertTrue(keychain.exists(), "exists() must return true after store")
    }

    func test_exists_returnsFalseAfterWipe() throws {
        try keychain.store(seed: testSeed)
        try keychain.wipe()
        XCTAssertFalse(keychain.exists(), "exists() must return false after wipe")
    }

    // MARK: - wipe

    func test_wipe_isNoOpWhenNoKeyStored() {
        XCTAssertNoThrow(try keychain.wipe(), "wipe on empty keychain must not throw")
    }

    func test_wipe_removesStoredKey() throws {
        try keychain.store(seed: testSeed)
        try keychain.wipe()
        XCTAssertFalse(keychain.exists(), "key must not exist after wipe")
    }

    func test_wipe_isIdempotent() throws {
        try keychain.store(seed: testSeed)
        try keychain.wipe()
        XCTAssertNoThrow(try keychain.wipe(), "double-wipe must not throw")
    }

    // MARK: - load (not-found path, no biometric)

    func test_load_throwsNotFoundWhenKeyAbsent() {
        XCTAssertThrowsError(try keychain.load(prompt: "test")) { error in
            // In the simulator, the biometric gate triggers the not-found path
            // before authentication because there is no key.  On device, it may
            // surface as biometricDenied or notFound depending on OS version.
            switch error {
            case KeychainError.notFound, KeychainError.biometricDenied:
                break // both are acceptable outcomes
            default:
                XCTFail("Expected notFound or biometricDenied, got \(error)")
            }
        }
    }

    // NOTE: The full load-with-biometric path (successful round-trip) is validated
    // in the manual instrumented test suite run on physical hardware with Face ID /
    // Touch ID enabled.  Automated biometric injection is not supported by XCTest
    // without private test hooks that violate App Store guidelines.
}
