// BitsovDeviceKeychain.swift
// BitSov iOS — stores the Ed25519 device identity key in the iOS Keychain.
//
// # Security design
//   - The 32-byte Ed25519 seed is stored with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
//     so it is never included in iCloud backups and is inaccessible while the device is locked.
//   - A `SecAccessControl` with `.userPresence` (biometric or device passcode) is set on the
//     item, ensuring the OS enforces biometric authentication on every `load` call.
//   - Keys never cross process boundaries in plaintext. After loading, callers should pass
//     the seed immediately to `ed25519Sign()` (via UniFFI) and zero the buffer.
//
// # Usage
//   let keychain = BitsovDeviceKeychain.shared
//   try keychain.store(seed: keypair.privateKey)   // on first-launch onboarding
//   let seed = try keychain.load(prompt: "…")      // triggers Face ID / Touch ID
//   try keychain.wipe()                             // on logout / account reset
//
// # Integration
//   1. Import `KonsensusCore` (UniFFI-generated) into the Xcode project.
//   2. Add this file to the App target.
//   3. Ensure the app has the `Keychain Sharing` capability or uses its own bundle ID.
//   4. No entitlements or provisioning changes are needed beyond standard app signing.

import Foundation
import LocalAuthentication
import Security

// MARK: - BitsovDeviceKeychain

/// Thread-safe keychain accessor for the BitSov device identity (Ed25519 seed).
public final class BitsovDeviceKeychain {

    // ── Singleton ─────────────────────────────────────────────────────────
    public static let shared = BitsovDeviceKeychain()

    // ── Constants ─────────────────────────────────────────────────────────
    private let service = "network.bitsov.device_identity"
    private let account = "device_sk_v1"

    // MARK: - Init

    /// Use `BitsovDeviceKeychain.shared` in production.
    /// An internal init is exposed for dependency injection in unit tests.
    internal init() {}

    // MARK: - Store

    /// Persist the 32-byte Ed25519 seed in the Keychain.
    ///
    /// Accessibility: `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` — the key is
    /// inaccessible while the device is locked and excluded from iCloud backups.
    ///
    /// Access control: `.userPresence` — every subsequent `load` call requires the
    /// user to authenticate via Face ID, Touch ID, or device passcode.
    ///
    /// If a key already exists for this account, it is overwritten atomically.
    ///
    /// - Parameter seed: Exactly 32 bytes (Ed25519 seed / RFC 8032 private key).
    /// - Throws: `KeychainError` on OS-level failure.
    public func store(seed: Data) throws {
        guard seed.count == 32 else {
            throw KeychainError.invalidSeedLength(seed.count)
        }

        // Build access control: biometric or passcode required for every read.
        var cfError: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .userPresence,
            &cfError
        ) else {
            throw KeychainError.accessControlCreationFailed(cfError?.takeRetainedValue())
        }

        // Remove any existing item before adding — SecItemUpdate cannot change access control.
        try wipe()

        let attributes: [CFString: Any] = [
            kSecClass:             kSecClassGenericPassword,
            kSecAttrService:       service,
            kSecAttrAccount:       account,
            kSecValueData:         seed,
            kSecAttrAccessControl: accessControl,
        ]

        let status = SecItemAdd(attributes as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.osStatus(status, operation: "store")
        }
    }

    // MARK: - Load (biometric-gated)

    /// Retrieve the 32-byte Ed25519 seed.
    ///
    /// The OS presents a biometric prompt before returning the value.
    /// The prompt text visible to the user is controlled by `prompt`.
    ///
    /// - Parameter prompt: User-visible reason shown in the Face ID / Touch ID dialog.
    ///   Defaults to a standard BitSov identity message.
    /// - Returns: The 32-byte Ed25519 seed.
    /// - Throws:
    ///   - `KeychainError.notFound` if no key has been stored yet.
    ///   - `KeychainError.biometricDenied` if the user cancels or biometric fails.
    ///   - `KeychainError.osStatus` for other OS errors.
    public func load(
        prompt: String = "Authenticate to use your BitSov identity"
    ) throws -> Data {
        let context = LAContext()
        context.localizedReason = prompt

        let query: [CFString: Any] = [
            kSecClass:                    kSecClassGenericPassword,
            kSecAttrService:              service,
            kSecAttrAccount:              account,
            kSecReturnData:               kCFBooleanTrue!,
            kSecMatchLimit:               kSecMatchLimitOne,
            kSecUseOperationPrompt:       prompt,
            kSecUseAuthenticationContext: context,
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        switch status {
        case errSecSuccess:
            guard let data = result as? Data, data.count == 32 else {
                throw KeychainError.unexpectedData
            }
            return data
        case errSecItemNotFound:
            throw KeychainError.notFound
        case errSecUserCanceled, errSecAuthFailed:
            throw KeychainError.biometricDenied
        default:
            throw KeychainError.osStatus(status, operation: "load")
        }
    }

    // MARK: - Exists (no biometric required)

    /// Returns `true` if a device key exists in the Keychain, without loading it.
    ///
    /// Uses `kSecUseAuthenticationUISkip` so the check does not trigger Face ID.
    /// Returns `true` even if the item exists but requires authentication.
    public func exists() -> Bool {
        let query: [CFString: Any] = [
            kSecClass:                  kSecClassGenericPassword,
            kSecAttrService:            service,
            kSecAttrAccount:            account,
            kSecReturnData:             kCFBooleanFalse!,
            kSecMatchLimit:             kSecMatchLimitOne,
            kSecUseAuthenticationUI:    kSecUseAuthenticationUISkip,
        ]
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        // errSecInteractionNotAllowed means the item exists but requires auth — counts as "exists".
        return status == errSecSuccess || status == errSecInteractionNotAllowed
    }

    // MARK: - Wipe

    /// Delete the device identity key. Irreversible — the user must re-onboard.
    ///
    /// No-ops if no key is stored.
    /// Does not require biometric authentication.
    public func wipe() throws {
        let query: [CFString: Any] = [
            kSecClass:       kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.osStatus(status, operation: "wipe")
        }
    }
}

// MARK: - KeychainError

/// Errors thrown by `BitsovDeviceKeychain`.
public enum KeychainError: Error, LocalizedError {
    /// The seed passed to `store(seed:)` was not exactly 32 bytes.
    case invalidSeedLength(Int)
    /// `SecAccessControlCreateWithFlags` returned nil.
    case accessControlCreationFailed(CFError?)
    /// An OS-level Keychain call returned an unexpected `OSStatus`.
    case osStatus(OSStatus, operation: String)
    /// No device key has been stored — the user must complete onboarding first.
    case notFound
    /// The user cancelled or failed biometric / passcode authentication.
    case biometricDenied
    /// The Keychain returned data in an unexpected format.
    case unexpectedData

    public var errorDescription: String? {
        switch self {
        case .invalidSeedLength(let n):
            return "Ed25519 seed must be 32 bytes, got \(n)"
        case .accessControlCreationFailed(let e):
            return "Failed to create access control: \(e?.localizedDescription ?? "unknown")"
        case .osStatus(let code, let op):
            return "Keychain \(op) failed with OSStatus \(code)"
        case .notFound:
            return "Device identity key not found — complete onboarding first"
        case .biometricDenied:
            return "Biometric authentication was denied or cancelled"
        case .unexpectedData:
            return "Unexpected data format returned from Keychain"
        }
    }
}
