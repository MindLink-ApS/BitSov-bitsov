/**
 * Auth store — manages authentication state.
 *
 * The auth flow:
 * 1. User provides their Ed25519 private key (from mnemonic/keyfile)
 * 2. Frontend signs the "konsensus-auth" challenge
 * 3. Sends signature to POST /api/v1/auth/token
 * 4. Receives JWT, stores in session, configures API client
 * 5. Connects WebSocket for real-time updates
 */

import { createSignal } from "solid-js";
import { ApiClient } from "../api/client";
import { WsClient } from "../api/ws";
import type { WsStatus } from "../api/ws";
import type { IdentityResponse } from "../api/types";
import { signChallenge, derivePublicKey } from "../auth/crypto";
import { storeToken, getToken, clearToken } from "../auth/session";
import { toast } from "./toast";
import { loadString, saveString } from "../utils/storage";

// Default node URL — can be overridden via setNodeUrl before login
const NODE_URL_KEY = "konsensus_node_url";
const DEFAULT_NODE_URL = "http://127.0.0.1:3141";

function getStoredNodeUrl(): string {
  return loadString(NODE_URL_KEY) || DEFAULT_NODE_URL;
}

// Singleton instances
export const api = new ApiClient(getStoredNodeUrl());
export const ws = new WsClient("");

/** Change the node URL the frontend connects to. Persists across sessions. */
export function setNodeUrl(url: string): void {
  const cleaned = url.replace(/\/$/, "") || DEFAULT_NODE_URL;
  saveString(NODE_URL_KEY, cleaned);
  api.setBaseUrl(cleaned);
}

/** Get the current node URL. */
export function getNodeUrl(): string {
  return api.getBaseUrl();
}

// Reactive state
const [authenticated, setAuthenticated] = createSignal(false);
const [nodeId, setNodeId] = createSignal<string | null>(null);
const [identity, setIdentity] = createSignal<IdentityResponse | null>(null);
const [wsStatus, setWsStatus] = createSignal<WsStatus>("disconnected");
const [authError, setAuthError] = createSignal<string | null>(null);
const [loading, setLoading] = createSignal(false);

// Track WS status
ws.onStatus((status) => setWsStatus(status));

// Handle token refresh and expiry
api.onTokenRefreshed((token, expiresAt) => {
  storeToken(token, expiresAt);
  // Reconnect WebSocket with new token
  ws.setUrl(api.wsUrl);
  ws.connect();
});

api.onAuthExpired(() => {
  toast.error("Session expired. Please log in again.");
  logout();
});

/** Try to restore session from stored token. */
export async function restoreSession(): Promise<boolean> {
  const token = getToken();
  if (!token) return false;

  api.setToken(token);
  try {
    const id = await api.identity();
    setIdentity(id);
    setNodeId(id.node_id);
    setAuthenticated(true);

    // Connect WebSocket
    ws.setUrl(api.wsUrl);
    ws.connect();

    return true;
  } catch {
    api.clearToken();
    clearToken();
    return false;
  }
}

/** Authenticate via localhost — no credentials needed. */
export async function loginLocal(): Promise<void> {
  setLoading(true);
  setAuthError(null);

  try {
    const tokenRes = await api.localAuth();
    api.setToken(tokenRes.token);
    storeToken(tokenRes.token, tokenRes.expires_at);

    const id = await api.identity();
    setIdentity(id);
    setNodeId(id.node_id);
    setAuthenticated(true);

    ws.setUrl(api.wsUrl);
    ws.connect();
  } catch (e) {
    setAuthError(
      e instanceof Error ? e.message : "Local authentication failed",
    );
    throw e;
  } finally {
    setLoading(false);
  }
}

/** Authenticate with an Ed25519 private key. */
export async function login(privateKeyHex: string): Promise<void> {
  setLoading(true);
  setAuthError(null);

  try {
    // Derive public key to verify we have the right key
    const pubHex = await derivePublicKey(privateKeyHex);

    // Check node health first
    const health = await api.health();
    if (health.node_id !== pubHex) {
      throw new Error(
        `Key mismatch: your key derives node ${pubHex.slice(0, 16)}... but the node reports ${health.node_id.slice(0, 16)}...`,
      );
    }

    // Sign the challenge
    const signature = await signChallenge(privateKeyHex);

    // Exchange signature for JWT
    const tokenRes = await api.authenticate({ signature });
    api.setToken(tokenRes.token);
    storeToken(tokenRes.token, tokenRes.expires_at);

    // Load identity
    const id = await api.identity();
    setIdentity(id);
    setNodeId(id.node_id);
    setAuthenticated(true);

    // Connect WebSocket
    ws.setUrl(api.wsUrl);
    ws.connect();
  } catch (e) {
    setAuthError(e instanceof Error ? e.message : "Authentication failed");
    throw e;
  } finally {
    setLoading(false);
  }
}

/** Log out — clear token, disconnect WebSocket. */
export function logout(): void {
  ws.disconnect();
  api.clearToken();
  clearToken();
  setAuthenticated(false);
  setNodeId(null);
  setIdentity(null);
}

// Export reactive getters
export {
  authenticated,
  nodeId,
  identity,
  wsStatus,
  authError,
  loading,
};
