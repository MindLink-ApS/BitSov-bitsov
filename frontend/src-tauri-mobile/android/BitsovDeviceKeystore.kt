package network.bitsov.app

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Base64
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * BitsovDeviceKeystore — stores the Ed25519 device identity key using the Android Keystore.
 *
 * ## Security design
 *
 * The 32-byte Ed25519 seed is encrypted with an AES-256-GCM key backed by the Android Keystore
 * (StrongBox if the device supports it, software TEE otherwise).  The Keystore key requires a
 * fresh biometric authentication for every use: both `store` (encryption) and `load` (decryption)
 * present a [BiometricPrompt] with a `CryptoObject`, so the OS enforces the biometric gate at the
 * hardware level rather than relying on application-level checks.
 *
 * - **Store**: caller initiates biometric prompt with [buildEncryptionCipher], then calls
 *   [completeStore] inside the `onAuthenticationSucceeded` callback.
 * - **Load**: caller initiates biometric prompt with [buildDecryptionCipher], then calls
 *   [completeLoad] inside the `onAuthenticationSucceeded` callback.
 * - **Wipe**: deletes the Keystore key and the encrypted blob from SharedPreferences.
 *   No biometric required.
 *
 * ## Integration
 *
 * 1. Add `androidx.biometric:biometric:1.2.0-alpha05+` to `build.gradle`.
 * 2. Add `android:name=".BitsovApplication"` to `<application>` in AndroidManifest.xml.
 * 3. Call [storeWithBiometric] during onboarding from a [FragmentActivity].
 * 4. Call [loadWithBiometric] before passing the seed to `ed25519Sign()` (UniFFI).
 *
 * ## Example
 * ```kotlin
 * val ks = BitsovDeviceKeystore(context)
 * // Onboarding:
 * val kp = generateEd25519Keypair()          // UniFFI call
 * ks.storeWithBiometric(activity, kp.privateKey.toByteArray(),
 *     onSuccess = { /* seed stored */ },
 *     onError   = { msg -> showError(msg) })
 *
 * // Signing:
 * ks.loadWithBiometric(activity,
 *     onSuccess = { seed ->
 *         val sig = ed25519Sign(seed.toList(), message.toList())  // UniFFI
 *         seed.fill(0)  // zeroize
 *     },
 *     onError = { msg -> showError(msg) })
 * ```
 */
class BitsovDeviceKeystore(private val context: Context) {

    // ── Constants ─────────────────────────────────────────────────────────────────────────────────

    companion object {
        private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
        private const val KEY_ALIAS = "bitsov_device_identity_v1"
        private const val PREFS_NAME = "bitsov_device_keystore_v1"
        private const val PREF_IV = "device_sk_iv"
        private const val PREF_CT = "device_sk_ct"
        private const val GCM_IV_SIZE_BYTES = 12
        private const val GCM_TAG_SIZE_BITS = 128
        private const val SEED_SIZE = 32
        private const val AES_CIPHER = "AES/GCM/NoPadding"
    }

    // ── Public API ────────────────────────────────────────────────────────────────────────────────

    /**
     * Returns true if a device key has been stored (ciphertext present in SharedPreferences).
     * Does not require biometric authentication.
     */
    fun deviceKeyExists(): Boolean =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).contains(PREF_CT)

    /**
     * Store the Ed25519 seed with a biometric-gated encryption step.
     *
     * Presents a [BiometricPrompt] to the user.  On success, the seed is AES-GCM encrypted
     * using the hardware-backed Keystore key and the ciphertext is saved to SharedPreferences.
     *
     * @param activity The foreground [FragmentActivity] needed to show the biometric prompt.
     * @param seed     32-byte Ed25519 seed. The array is zeroized by this function after use.
     * @param title    Biometric dialog title (user-visible).
     * @param subtitle Biometric dialog subtitle (user-visible).
     * @param onSuccess Invoked on the main thread if the key was stored successfully.
     * @param onError   Invoked on the main thread with a human-readable message on failure.
     */
    fun storeWithBiometric(
        activity: FragmentActivity,
        seed: ByteArray,
        title: String = "BitSov Identity",
        subtitle: String = "Authenticate to store your device identity",
        onSuccess: () -> Unit,
        onError: (String) -> Unit,
    ) {
        if (seed.size != SEED_SIZE) {
            onError("Ed25519 seed must be $SEED_SIZE bytes, got ${seed.size}")
            return
        }
        val cipher = try {
            buildEncryptionCipher()
        } catch (e: Exception) {
            onError("Failed to initialize encryption: ${e.message}")
            return
        }

        showBiometricPrompt(
            activity = activity,
            title = title,
            subtitle = subtitle,
            cryptoObject = BiometricPrompt.CryptoObject(cipher),
            onSuccess = { result ->
                val encryptCipher = result.cryptoObject?.cipher
                if (encryptCipher == null) {
                    onError("Biometric result missing cipher")
                    return@showBiometricPrompt
                }
                try {
                    completeStore(encryptCipher, seed)
                    onSuccess()
                } catch (e: Exception) {
                    onError("Encryption failed: ${e.message}")
                } finally {
                    seed.fill(0) // zeroize
                }
            },
            onError = onError,
        )
    }

    /**
     * Load the Ed25519 seed with a biometric-gated decryption step.
     *
     * Presents a [BiometricPrompt] to the user.  On success, the stored ciphertext is decrypted
     * and the 32-byte seed is delivered to [onSuccess].  **Zeroize the seed array after use.**
     *
     * @param activity  The foreground [FragmentActivity] needed to show the biometric prompt.
     * @param title     Biometric dialog title (user-visible).
     * @param subtitle  Biometric dialog subtitle (user-visible).
     * @param onSuccess Invoked on the main thread with the decrypted 32-byte seed.
     * @param onError   Invoked on the main thread with a human-readable message on failure.
     */
    fun loadWithBiometric(
        activity: FragmentActivity,
        title: String = "BitSov Identity",
        subtitle: String = "Authenticate to use your device identity",
        onSuccess: (ByteArray) -> Unit,
        onError: (String) -> Unit,
    ) {
        val cipher = try {
            buildDecryptionCipher()
        } catch (e: DeviceKeystoreException.NotFound) {
            onError("Device key not found — run onboarding first")
            return
        } catch (e: Exception) {
            onError("Failed to initialize decryption: ${e.message}")
            return
        }

        showBiometricPrompt(
            activity = activity,
            title = title,
            subtitle = subtitle,
            cryptoObject = BiometricPrompt.CryptoObject(cipher),
            onSuccess = { result ->
                val decryptCipher = result.cryptoObject?.cipher
                if (decryptCipher == null) {
                    onError("Biometric result missing cipher")
                    return@showBiometricPrompt
                }
                try {
                    onSuccess(completeLoad(decryptCipher))
                } catch (e: Exception) {
                    onError("Decryption failed: ${e.message}")
                }
            },
            onError = onError,
        )
    }

    /**
     * Delete the device key (Keystore entry + encrypted blob).
     *
     * Irreversible — the user must re-run onboarding to generate a new identity.
     * Does not require biometric authentication.
     */
    fun wipeDeviceKey() {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .remove(PREF_IV)
            .remove(PREF_CT)
            .apply()
        runCatching {
            KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }.deleteEntry(KEY_ALIAS)
        }
    }

    // ── Cipher construction (internal; exposed for testing) ───────────────────────────────────────

    /**
     * Build an AES-GCM [Cipher] initialized for encryption using the Keystore key.
     * Pass this to [BiometricPrompt] as a [BiometricPrompt.CryptoObject].
     * Complete the operation by calling [completeStore] in the success callback.
     */
    internal fun buildEncryptionCipher(): Cipher {
        val key = getOrCreateKey()
        return Cipher.getInstance(AES_CIPHER).apply {
            init(Cipher.ENCRYPT_MODE, key)
        }
    }

    /**
     * Build an AES-GCM [Cipher] initialized for decryption using the stored IV.
     * Pass this to [BiometricPrompt] as a [BiometricPrompt.CryptoObject].
     * Complete the operation by calling [completeLoad] in the success callback.
     *
     * @throws DeviceKeystoreException.NotFound if no key has been stored yet.
     */
    internal fun buildDecryptionCipher(): Cipher {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val ivB64 = prefs.getString(PREF_IV, null) ?: throw DeviceKeystoreException.NotFound
        val iv = Base64.decode(ivB64, Base64.NO_WRAP)
        val key = getKey() ?: throw DeviceKeystoreException.NotFound
        return Cipher.getInstance(AES_CIPHER).apply {
            init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_SIZE_BITS, iv))
        }
    }

    /**
     * Complete an encryption operation with the cipher from a successful biometric prompt.
     * Saves the IV and ciphertext to SharedPreferences.
     */
    internal fun completeStore(cipher: Cipher, seed: ByteArray) {
        val ciphertext = cipher.doFinal(seed)
        val iv = cipher.iv
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putString(PREF_IV, Base64.encodeToString(iv, Base64.NO_WRAP))
            .putString(PREF_CT, Base64.encodeToString(ciphertext, Base64.NO_WRAP))
            .apply()
    }

    /**
     * Complete a decryption operation with the cipher from a successful biometric prompt.
     * Returns the decrypted 32-byte seed.
     *
     * @throws DeviceKeystoreException.NotFound if no ciphertext is stored.
     */
    internal fun completeLoad(cipher: Cipher): ByteArray {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val ctB64 = prefs.getString(PREF_CT, null) ?: throw DeviceKeystoreException.NotFound
        val ciphertext = Base64.decode(ctB64, Base64.NO_WRAP)
        return cipher.doFinal(ciphertext)
    }

    // ── Private helpers ───────────────────────────────────────────────────────────────────────────

    private fun showBiometricPrompt(
        activity: FragmentActivity,
        title: String,
        subtitle: String,
        cryptoObject: BiometricPrompt.CryptoObject,
        onSuccess: (BiometricPrompt.AuthenticationResult) -> Unit,
        onError: (String) -> Unit,
    ) {
        val executor = ContextCompat.getMainExecutor(activity)
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) =
                onSuccess(result)

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) =
                onError("Authentication error ($errorCode): $errString")

            // onAuthenticationFailed is a recoverable event (wrong finger, etc.) —
            // the prompt stays visible, so we do not invoke onError here.
            override fun onAuthenticationFailed() = Unit
        }

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setNegativeButtonText("Cancel")
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .build()

        BiometricPrompt(activity, executor, callback)
            .authenticate(promptInfo, cryptoObject)
    }

    private fun getOrCreateKey(): SecretKey = getKey() ?: createKey(tryStrongBox = true)

    private fun getKey(): SecretKey? {
        val ks = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        return (ks.getEntry(KEY_ALIAS, null) as? KeyStore.SecretKeyEntry)?.secretKey
    }

    private fun createKey(tryStrongBox: Boolean): SecretKey {
        val purposeMask = KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        val spec = KeyGenParameterSpec.Builder(KEY_ALIAS, purposeMask).apply {
            setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            setKeySize(256)
            setUserAuthenticationRequired(true)
            // Require fresh biometric authentication for every key operation (no time window).
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                setUserAuthenticationParameters(
                    0, // validity duration: 0 = require auth for each use
                    KeyProperties.AUTH_BIOMETRIC_STRONG,
                )
            } else {
                @Suppress("DEPRECATION")
                setUserAuthenticationValidityDurationSeconds(-1)
            }
            // Request StrongBox (dedicated secure element) if available.
            if (tryStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                setIsStrongBoxBacked(true)
            }
        }.build()

        return try {
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER)
                .apply { init(spec) }
                .generateKey()
        } catch (e: StrongBoxUnavailableException) {
            // Device lacks StrongBox — fall back to software-backed TEE.
            if (tryStrongBox) createKey(tryStrongBox = false) else throw e
        }
    }
}

// MARK: - DeviceKeystoreException

/**
 * Errors thrown by [BitsovDeviceKeystore] synchronous operations.
 * Asynchronous errors (biometric cancellation, timeout) are delivered via the `onError` callback.
 */
sealed class DeviceKeystoreException(message: String) : Exception(message) {
    /** No device key has been stored — the user must run onboarding. */
    object NotFound : DeviceKeystoreException(
        "Device key not found — run onboarding first"
    )

    /** The biometric authentication was denied or cancelled by the user. */
    object BiometricDenied : DeviceKeystoreException(
        "Biometric authentication was denied or cancelled"
    )

    /** A Keystore or cipher operation failed unexpectedly. */
    data class StorageError(val cause: Exception) : DeviceKeystoreException(
        "Keystore operation failed: ${cause.message}"
    )
}
