/** HTTP client for the BitSov REST API. */

import type {
  HealthResponse,
  TokenRequest,
  TokenResponse,
  IdentityResponse,
  SendMessageRequest,
  SendMessageResponse,
  ComposeRequest,
  ComposeResponse,
  MessageResponse,
  ListMessagesQuery,
  ResyncDiscoverResponse,
  ResyncFulfillResponse,
  CreateRoomRequest,
  RoomResponse,
  PeerResponse,
  AddPeerRequest,
  UpdatePeerRequest,
  PeerBackup,
  ImportPeersRequest,
  ImportPeersResponse,
  CreateInvoiceRequest,
  InvoiceResponse,
  PaymentStatusResponse,
  BalanceResponse,
  PriceResponse,
  UploadFileRequest,
  UploadFileResponse,
  FileResponse as FileMetaResponse,
  DownloadFileResponse,
  SendFileRequest,
  SendFileResponse,
  PayInvoiceRequest,
  PayInvoiceResponse,
  PaymentListEntry,
  ChannelResponse,
  ChannelStatsResponse,
  ContentPageList,
  ContentPageRead,
  ContentPageWrite,
  SessionStatusResponse,
  PeerPricingResponse,
  NodePricingInfo,
  ContactResponse,
  PatchContactRequest,
  FreeBusyResponse,
  MessageReactionsResponse,
  ReactResponse,
  IssueInviteRequest,
  IssueInviteResponse,
  InviteCapabilitiesResponse,
  InviteListEntry,
  OnboardingStateResponse,
} from "./types";

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(friendlyErrorMessage(status, message));
    this.name = "ApiError";
    this.technicalMessage = message;
  }
  /** The original raw message from the server. */
  technicalMessage: string;
}

/** Extract the error message from a JSON error body, or return the raw string. */
function extractErrorMessage(raw: string): string {
  try {
    const parsed = JSON.parse(raw);
    if (typeof parsed === "object" && parsed !== null && typeof parsed.error === "string") {
      return parsed.error;
    }
  } catch {
    // Not JSON — use raw string as-is
  }
  return raw;
}

/** Translate HTTP status codes and raw error messages to user-friendly text. */
function friendlyErrorMessage(status: number, raw: string): string {
  // Always extract the error message from JSON body if present
  const msg = extractErrorMessage(raw);

  switch (status) {
    case 0:
      return "Cannot reach the node. Check that it is running and accessible.";
    case 400: {
      // Try to extract a useful message from the server's response
      if (msg.includes("invalid node ID")) return "The Node ID is not valid. It must be a 64-character hex string.";
      if (msg.includes("invalid address")) return "The address format is not valid. Use host:port (e.g. 10.0.0.1:9735).";
      if (msg.includes("E2EE") || msg.includes("session") || msg.includes("encrypt"))
        return "Secure connection not yet established with this peer. Please wait a moment and try again.";
      if (msg.includes("expired")) return "This invite has expired. Ask the peer for a new invite link.";
      if (msg.includes("invalid invite")) return "This invite link is not valid. Check that you copied it correctly.";
      if (msg.includes("cannot add yourself")) return "You cannot add yourself as a peer.";
      if (msg.includes("no members") || msg.includes("room has no"))
        return "This group has no members yet. Add members before sending messages.";
      if (msg.includes("member") || msg.includes("room") || msg.includes("group"))
        return msg.length > 120 ? msg.slice(0, 120) + "..." : msg;
      return "The request was not valid. Please check your input and try again.";
    }
    case 401:
      return "Your session has expired. Please sign in again.";
    case 403:
      return "You do not have permission for this action.";
    case 404: {
      if (msg.includes("peer")) return "Peer not found. They may have been removed.";
      if (msg.includes("room")) return "Group not found. It may have been deleted.";
      if (msg.includes("message")) return "Message not found.";
      if (msg.includes("file")) return "File not found.";
      return "The requested resource was not found.";
    }
    case 429:
      return "Too many requests. Please wait a moment and try again.";
    case 500:
      return "Something went wrong on the node. Please try again or check the node logs.";
    case 502: {
      // 502 comes from Lightning and Transport errors — give specific feedback
      if (msg.includes("Lightning") || msg.includes("lightning") || msg.includes("wallet"))
        return "Lightning wallet is unavailable. Check that your Lightning node is running and connected.";
      if (msg.includes("offline") || msg.includes("not connected") || msg.includes("Recipient is offline"))
        return "Recipient is offline. The message will be queued and sent when they reconnect.";
      if (msg.includes("invoice") || msg.includes("Invoice"))
        return "Lightning payment failed. The recipient may be offline or their wallet may be unavailable.";
      if (msg.includes("keysend"))
        return "Lightning payment failed. Falling back to invoice flow was also unsuccessful.";
      if (msg.includes("E2EE") || msg.includes("session") || msg.includes("encrypt"))
        return "Secure connection not yet established with this peer. Please wait a moment and try again.";
      return "The node could not complete this request. Check Lightning wallet and peer connectivity.";
    }
    case 503:
    case 504:
      return "The node is temporarily unavailable. Please try again in a moment.";
    default:
      // For network errors (TypeError: Failed to fetch), simplify
      if (msg.includes("Failed to fetch") || msg.includes("NetworkError"))
        return "Cannot reach the node. Check your connection and that the node is running.";
      // Keep unknown errors but cap length
      return msg.length > 120 ? msg.slice(0, 120) + "..." : msg;
  }
}

/** Convert any caught error into a user-friendly message string. */
export function toUserMessage(err: unknown): string {
  if (err instanceof ApiError) return err.message;
  if (err instanceof TypeError && err.message.includes("fetch"))
    return "Cannot reach the node. Check your connection.";
  if (err instanceof Error) return err.message;
  return "An unexpected error occurred. Please try again.";
}

export class ApiClient {
  private baseUrl: string;
  private token: string | null = null;
  private refreshing: Promise<boolean> | null = null;
  private _onAuthExpired: (() => void) | null = null;
  private _onTokenRefreshed: ((token: string, expiresAt: number) => void) | null = null;

  constructor(baseUrl: string = "http://127.0.0.1:3141") {
    this.baseUrl = baseUrl.replace(/\/$/, "");
  }

  /** Get the current base URL. */
  getBaseUrl(): string {
    return this.baseUrl;
  }

  /** Update the base URL (e.g. when connecting to a different node). */
  setBaseUrl(url: string): void {
    this.baseUrl = url.replace(/\/$/, "");
  }

  setToken(token: string): void {
    this.token = token;
  }

  clearToken(): void {
    this.token = null;
  }

  /** Register callback for when auth cannot be recovered. */
  onAuthExpired(cb: () => void): void {
    this._onAuthExpired = cb;
  }

  /** Register callback for when token is successfully refreshed. */
  onTokenRefreshed(cb: (token: string, expiresAt: number) => void): void {
    this._onTokenRefreshed = cb;
  }

  get isAuthenticated(): boolean {
    return this.token !== null;
  }

  get wsUrl(): string {
    const proto = this.baseUrl.startsWith("https") ? "wss" : "ws";
    const host = this.baseUrl.replace(/^https?:\/\//, "");
    return `${proto}://${host}/api/v1/ws?token=${this.token}`;
  }

  // ── Internal request helpers ────────────────────────────────────────

  /** Attempt to refresh the token via localhost auth. Returns true on success. */
  private async tryRefreshToken(): Promise<boolean> {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), this.requestTimeout);
      const res = await fetch(`${this.baseUrl}/api/v1/auth/local`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{}",
        signal: controller.signal,
      });
      clearTimeout(timeout);
      if (!res.ok) return false;
      const data = await res.json() as { token: string; expires_at: number };
      this.token = data.token;
      this._onTokenRefreshed?.(data.token, data.expires_at);
      return true;
    } catch {
      return false;
    }
  }

  /** Default request timeout in milliseconds (30 seconds). */
  private readonly requestTimeout = 30000;

  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
    auth = true,
  ): Promise<T> {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    if (auth && this.token) {
      headers["Authorization"] = `Bearer ${this.token}`;
    }

    let res: Response;
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), this.requestTimeout);
      res = await fetch(`${this.baseUrl}${path}`, {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });
      clearTimeout(timeout);
    } catch (e) {
      if (e instanceof DOMException && e.name === "AbortError") {
        throw new ApiError(0, "Request timed out");
      }
      throw new ApiError(0, "Failed to fetch");
    }

    // On 401, attempt token refresh and retry once
    if (res.status === 401 && auth && this.token) {
      // Deduplicate concurrent refresh attempts
      if (!this.refreshing) {
        this.refreshing = this.tryRefreshToken().finally(() => {
          this.refreshing = null;
        });
      }
      const refreshed = await this.refreshing;
      if (refreshed) {
        // Retry with new token
        const retryHeaders: Record<string, string> = {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${this.token}`,
        };
        const retryController = new AbortController();
        const retryTimeout = setTimeout(() => retryController.abort(), this.requestTimeout);
        const retryRes = await fetch(`${this.baseUrl}${path}`, {
          method,
          headers: retryHeaders,
          body: body ? JSON.stringify(body) : undefined,
          signal: retryController.signal,
        });
        clearTimeout(retryTimeout);
        if (!retryRes.ok) {
          const text = await retryRes.text().catch(() => "unknown error");
          throw new ApiError(retryRes.status, text);
        }
        return retryRes.json() as Promise<T>;
      }
      // Refresh failed — notify listeners
      this._onAuthExpired?.();
      throw new ApiError(401, "Session expired");
    }

    if (!res.ok) {
      const text = await res.text().catch(() => "unknown error");
      throw new ApiError(res.status, text);
    }

    return res.json() as Promise<T>;
  }

  private get<T>(path: string, auth = true): Promise<T> {
    return this.request("GET", path, undefined, auth);
  }

  private post<T>(path: string, body?: unknown, auth = true): Promise<T> {
    return this.request("POST", path, body, auth);
  }

  private put<T>(path: string, body?: unknown, auth = true): Promise<T> {
    return this.request("PUT", path, body, auth);
  }

  private del<T>(path: string, auth = true): Promise<T> {
    return this.request("DELETE", path, undefined, auth);
  }

  private patch<T>(path: string, body?: unknown, auth = true): Promise<T> {
    return this.request("PATCH", path, body, auth);
  }

  // ── Health (no auth) ────────────────────────────────────────────────

  health(): Promise<HealthResponse> {
    return this.get("/api/v1/health", false);
  }

  // ── Auth ────────────────────────────────────────────────────────────

  authenticate(req: TokenRequest): Promise<TokenResponse> {
    return this.post("/api/v1/auth/token", req, false);
  }

  /** Authenticate via localhost — no credentials needed. */
  localAuth(): Promise<TokenResponse> {
    return this.post("/api/v1/auth/local", {}, false);
  }

  // ── Identity ────────────────────────────────────────────────────────

  identity(): Promise<IdentityResponse> {
    return this.get("/api/v1/identity");
  }

  /** Retrieve the node's mnemonic for backup display (plaintext only). */
  mnemonic(): Promise<{ mnemonic: string }> {
    return this.get("/api/v1/identity/mnemonic");
  }

  // ── Messages ────────────────────────────────────────────────────────

  sendMessage(req: SendMessageRequest): Promise<SendMessageResponse> {
    return this.post("/api/v1/messages", req);
  }

  /** Compose, encrypt, pay, and send a message (node handles all crypto). */
  composeMessage(req: ComposeRequest): Promise<ComposeResponse> {
    return this.post("/api/v1/messages/compose", req);
  }

  getMessage(id: string): Promise<MessageResponse> {
    return this.get(`/api/v1/messages/${id}`);
  }

  /** Fetch decrypted plaintext for a specific message from the plaintext cache. */
  getMessagePlaintext(id: string): Promise<{ message_id: string; plaintext: string; encoding: string }> {
    return this.get(`/api/v1/messages/${id}/plaintext`);
  }

  listMessages(query?: ListMessagesQuery): Promise<MessageResponse[]> {
    const params = new URLSearchParams();
    if (query?.limit) params.set("limit", String(query.limit));
    if (query?.before) params.set("before", String(query.before));
    if (query?.peer) params.set("peer", query.peer);
    const qs = params.toString();
    return this.get(`/api/v1/messages${qs ? "?" + qs : ""}`);
  }

  resyncDiscover(peerId: string, fromMs: number, toMs: number): Promise<ResyncDiscoverResponse> {
    return this.post("/api/v1/messages/resync", { phase: "discover", peer_id: peerId, from_ms: fromMs, to_ms: toMs });
  }
  resyncFulfill(peerId: string, messageIds: string[]): Promise<ResyncFulfillResponse> {
    return this.post("/api/v1/messages/resync", { phase: "fulfill", peer_id: peerId, message_ids: messageIds });
  }

  // ── Rooms ───────────────────────────────────────────────────────────

  createRoom(req: CreateRoomRequest): Promise<RoomResponse> {
    return this.post("/api/v1/rooms", req);
  }

  listRooms(): Promise<RoomResponse[]> {
    return this.get("/api/v1/rooms");
  }

  listRoomMembers(roomId: string): Promise<string[]> {
    return this.get(`/api/v1/rooms/${roomId}/members`);
  }

  addRoomMember(roomId: string, nodeId: string): Promise<{ added: boolean }> {
    return this.post(`/api/v1/rooms/${roomId}/members`, { node_id: nodeId });
  }

  removeRoomMember(
    roomId: string,
    nodeId: string,
  ): Promise<{ removed: boolean }> {
    return this.del(`/api/v1/rooms/${roomId}/members/${nodeId}`);
  }

  deleteRoom(roomId: string): Promise<{ deleted: boolean }> {
    return this.del(`/api/v1/rooms/${roomId}`);
  }

  // ── Peers ───────────────────────────────────────────────────────────

  listPeers(): Promise<PeerResponse[]> {
    return this.get("/api/v1/peers");
  }

  addPeer(req: AddPeerRequest): Promise<PeerResponse> {
    return this.post("/api/v1/peers", req);
  }

  updatePeer(nodeId: string, req: UpdatePeerRequest): Promise<PeerResponse> {
    return this.put(`/api/v1/peers/${nodeId}`, req);
  }

  removePeer(nodeId: string): Promise<{ removed: boolean }> {
    return this.del(`/api/v1/peers/${nodeId}`);
  }

  connectPeer(nodeId: string): Promise<{ connected: boolean }> {
    return this.post(`/api/v1/peers/${nodeId}/connect`);
  }

  /** Export all peers as a JSON backup. */
  exportPeers(): Promise<PeerBackup> {
    return this.get("/api/v1/peers/export");
  }

  /** Import peers from a JSON backup. */
  importPeers(req: ImportPeersRequest): Promise<ImportPeersResponse> {
    return this.post("/api/v1/peers/import", req);
  }

  // ── Payments ────────────────────────────────────────────────────────

  createInvoice(req: CreateInvoiceRequest): Promise<InvoiceResponse> {
    return this.post("/api/v1/payments/invoice", req);
  }

  balance(): Promise<BalanceResponse> {
    return this.get("/api/v1/payments/balance");
  }

  price(kind: number): Promise<PriceResponse> {
    return this.get(`/api/v1/payments/price/${kind}`);
  }

  paymentStatus(hash: string): Promise<PaymentStatusResponse> {
    return this.get(`/api/v1/payments/${hash}`);
  }

  /** Pay a BOLT11 invoice. */
  payInvoice(req: PayInvoiceRequest): Promise<PayInvoiceResponse> {
    return this.post("/api/v1/payments/pay", req);
  }

  /** List recent Lightning payments. */
  listPayments(limit = 50): Promise<PaymentListEntry[]> {
    return this.get(`/api/v1/payments?limit=${limit}`);
  }

  /** List Lightning channels. */
  listChannels(): Promise<ChannelResponse[]> {
    return this.get("/api/v1/payments/channels");
  }

  /** Close a Lightning channel cooperatively or by force. */
  closeChannel(channelId: string, force: boolean): Promise<{ channel_id: string; force: boolean; status: string }> {
    return this.post(`/api/v1/payments/channels/${encodeURIComponent(channelId)}/close`, { force });
  }

  /** Get runtime statistics for a Lightning channel. */
  getChannelStats(channelId: string): Promise<ChannelStatsResponse> {
    return this.get(`/api/v1/payments/channels/${encodeURIComponent(channelId)}/stats`);
  }

  // ── Files ─────────────────────────────────────────────────────────────

  uploadFile(req: UploadFileRequest): Promise<UploadFileResponse> {
    return this.post("/api/v1/files", req);
  }

  listFiles(limit = 50): Promise<FileMetaResponse[]> {
    return this.get(`/api/v1/files?limit=${limit}`);
  }

  downloadFile(fileId: string): Promise<DownloadFileResponse> {
    return this.get(`/api/v1/files/${fileId}`);
  }

  deleteFile(fileId: string): Promise<{ deleted: boolean }> {
    return this.del(`/api/v1/files/${fileId}`);
  }

  sendFile(fileId: string, req: SendFileRequest): Promise<SendFileResponse> {
    return this.post(`/api/v1/files/${fileId}/send`, req);
  }

  // ── Contacts ──────────────────────────────────────────────────────────

  /** List all contacts (peers whose profile has been received). */
  listContacts(blocked?: boolean): Promise<ContactResponse[]> {
    const params = blocked !== undefined ? `?blocked=${blocked}` : "";
    return this.get(`/api/v1/contacts${params}`);
  }

  /** Get a single contact by node ID. */
  getContact(nodeId: string): Promise<ContactResponse> {
    return this.get(`/api/v1/contacts/${nodeId}`);
  }

  /** Update local-only fields on a contact (alias, muted, blocked, notes, tags). */
  patchContact(nodeId: string, req: PatchContactRequest): Promise<ContactResponse> {
    return this.patch(`/api/v1/contacts/${nodeId}`, req);
  }

  /** Send our profile to a peer to prompt them to reply with theirs. */
  refreshProfile(nodeId: string): Promise<{ sent: boolean; to: string; note: string }> {
    return this.post(`/api/v1/contacts/${nodeId}/refresh-profile`);
  }

  // ── Pricing ────────────────────────────────────────────────────────────

  /** Get this node's current pricing info (mode, chain state, category prices). */
  pricing(): Promise<NodePricingInfo> {
    return this.get("/api/v1/pricing");
  }

  /** Get cached pricing tables from all peers. */
  peerPricing(): Promise<PeerPricingResponse[]> {
    return this.get("/api/v1/pricing/peers");
  }

  // ── Sessions ──────────────────────────────────────────────────────────

  /** List all active E2EE sessions. */
  listSessions(): Promise<SessionStatusResponse[]> {
    return this.get("/api/v1/sessions");
  }

  // ── Browser (Sovereign Web) ──────────────────────────────────────────

  // ── Content Management ─────────────────────────────────────────────

  /** List all published pages. */
  listPages(): Promise<ContentPageList> {
    return this.get("/api/v1/content/pages");
  }

  /** Read a single page's content. */
  readPage(path: string): Promise<ContentPageRead> {
    const clean = path.replace(/^\//, "");
    return this.get(`/api/v1/content/pages/${clean}`);
  }

  /** Create or update a page. */
  writePage(path: string, content: string): Promise<ContentPageWrite> {
    const clean = path.replace(/^\//, "");
    return this.put(`/api/v1/content/pages/${clean}`, { content });
  }

  /** Delete a page. */
  deletePage(path: string): Promise<{ deleted: string }> {
    const clean = path.replace(/^\//, "");
    return this.del(`/api/v1/content/pages/${clean}`);
  }

  /** Browse a page on a peer's node. Sends KIND_PAGE_REQUEST (500). */
  browsePage(peerId: string, path: string): Promise<ComposeResponse> {
    const pageRequest = JSON.stringify({
      request_id: crypto.randomUUID(),
      path,
      method: "GET",
      accept: ["text/markdown"],
    });
    return this.post("/api/v1/messages/compose", {
      recipient: peerId,
      kind: 500,
      plaintext: pageRequest,
    });
  }

  /** Request a web manifest from a peer. Sends KIND_WEB_MANIFEST (510). */
  fetchManifest(peerId: string): Promise<ComposeResponse> {
    const manifestReq = JSON.stringify({
      request_id: crypto.randomUUID(),
      type: "request",
    });
    return this.post("/api/v1/messages/compose", {
      recipient: peerId,
      kind: 510,
      plaintext: manifestReq,
    });
  }

  // ── Peer Discovery ────────────────────────────────────────────────────

  /** Request peer exchange from a connected peer. */
  discoverPeers(nodeId: string): Promise<{ requested: boolean }> {
    return this.post(`/api/v1/peers/${nodeId}/discover`, {});
  }

  // ── Invite ────────────────────────────────────────────────────────────

  /** Generate a signed invite token for this node. */
  generateInvite(
    addr: string,
    label?: string,
    expirySecs?: number,
  ): Promise<import("./types").GenerateInviteResponse> {
    return this.post("/api/v1/invite", {
      addr,
      label,
      expiry_secs: expirySecs ?? 0,
    });
  }

  /** Redeem an invite token, adding the inviter as a peer. */
  redeemInvite(
    invite: string,
    autoConnect = true,
  ): Promise<import("./types").RedeemInviteResponse> {
    return this.post("/api/v1/invite/redeem", {
      invite,
      auto_connect: autoConnect,
    });
  }

  // ── Invites (plural, Track ONB) ──────────────────────────────────────────

  /** Accept a signed invite token as invitee. */
  acceptInvite(req: import("./types").AcceptInviteRequest): Promise<import("./types").AcceptInviteResponse> {
    return this.post("/api/v1/invites/accept", req);
  }

  onboardingState(): Promise<OnboardingStateResponse> {
    return this.get("/api/v1/onboarding/state");
  }

  listIssuedInvites(): Promise<InviteListEntry[]> {
    return this.get("/api/v1/invites");
  }

  getInviteCapabilities(): Promise<InviteCapabilitiesResponse> {
    return this.get("/api/v1/invites/capabilities");
  }

  issueInvite(req: IssueInviteRequest): Promise<IssueInviteResponse> {
    return this.post("/api/v1/invites", req);
  }

  revokeIssuedInvite(id: string): Promise<{ revoked: boolean }> {
    return this.del(`/api/v1/invites/${id}`);
  }

  // ── Reactions ─────────────────────────────────────────────────────────────

  /** Fetch aggregated reaction counts for a message. */
  getMessageReactions(messageId: string): Promise<MessageReactionsResponse> {
    return this.get(`/api/v1/messages/${messageId}/reactions`);
  }

  /** Send (or toggle off) a reaction on a message. */
  reactToMessage(messageId: string, emoji: string): Promise<ReactResponse> {
    return this.post(`/api/v1/messages/${messageId}/react`, { emoji });
  }

  // ── Calendar Free/Busy ────────────────────────────────────────────────

  /** Fetch busy blocks for a peer within a time window. */
  getFreeBusy(peer: string, from: number, to: number): Promise<import("./types").FreeBusyResponse> {
    const params = new URLSearchParams({ peer, from: String(from), to: String(to) });
    return this.get(`/api/v1/calendar/freebusy?${params.toString()}`);
  }
}
