/**
 * Ed25519 signing for authentication.
 *
 * The node's Ed25519 private key is used to sign the challenge string
 * "konsensus-auth". The signature is sent to the API to obtain a JWT.
 *
 * In the Tauri desktop app, the private key is read from the mnemonic file
 * on disk via a Tauri command. For development/testing, the key can be
 * provided directly.
 */

import * as ed from "@noble/ed25519";

/** Hex-encode a Uint8Array. */
export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Hex-decode a string to Uint8Array. */
export function fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

const AUTH_CHALLENGE = new TextEncoder().encode("konsensus-auth");

/**
 * Sign the authentication challenge with an Ed25519 private key.
 * Returns the hex-encoded signature.
 */
export async function signChallenge(privateKeyHex: string): Promise<string> {
  const privateKey = fromHex(privateKeyHex);
  const signature = await ed.signAsync(AUTH_CHALLENGE, privateKey);
  return toHex(signature);
}

/**
 * Derive the Ed25519 public key from a private key.
 * Returns the hex-encoded public key (node ID).
 */
export async function derivePublicKey(privateKeyHex: string): Promise<string> {
  const privateKey = fromHex(privateKeyHex);
  const publicKey = await ed.getPublicKeyAsync(privateKey);
  return toHex(publicKey);
}
