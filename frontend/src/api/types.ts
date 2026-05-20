/** API response types matching the BitSov REST API. */

// ── Health ──────────────────────────────────────────────────────────────

export interface HealthResponse {
  status: string;
  node_id: string;
  connected_peers: number;
  connected_peer_ids: string[];
  e2ee_sessions: number;
  pending_deliveries: number;
  lightning_available: boolean;
  lightning_payment_capable: boolean;
  lightning_balance_msat?: number;
  uptime_secs: number;
  version: number;
  lightning_backend: string;
}

// ── Auth ────────────────────────────────────────────────────────────────

export interface TokenRequest {
  signature: string;
}

export interface TokenResponse {
  token: string;
  expires_at: number;
}

// ── Identity ────────────────────────────────────────────────────────────

export interface IdentityResponse {
  node_id: string;
  x25519_public: string;
  secp256k1_public: string;
}

// ── Messages ────────────────────────────────────────────────────────────

export interface SendMessageRequest {
  recipient: string;
  is_room: boolean;
  kind: number;
  ciphertext: string;
  payment_hash: string;
  preimage: string;
  amount_msat: number;
}

export interface SendMessageResponse {
  message_id: string;
  delivered: boolean;
}

export interface MessageResponse {
  id: string;
  kind: number;
  sender: string;
  recipient: string;
  timestamp: number;
  ciphertext: string;
  /** Decrypted plaintext (UTF-8). Present when the node decrypted the message. */
  plaintext?: string;
  payment_amount_msat: number;
  /** Payment hash (hex, 32 bytes). */
  payment_hash: string;
  /** Message references for threading (hex IDs). Present on KIND_REPLY messages. */
  references?: string[];
}

export interface ListMessagesQuery {
  limit?: number;
  before?: number;
  /** Filter to a specific conversation (peer node ID or room UUID). */
  peer?: string;
}

export interface ComposeRequest {
  recipient: string;
  is_room?: boolean;
  kind: number;
  plaintext: string;
  references?: string[];
}

export interface ComposeResponse {
  message_id: string;
  delivered: boolean;
  amount_msat: number;
}

// ── Resync (message history restore) ────────────────────────────────────
export interface ResyncEntry { id: string; kind: number; timestamp: number; estimated_fee_msat: number; plaintext_available: boolean; }
export interface ResyncDiscoverResponse { phase: "discover"; peer_id: string; messages: ResyncEntry[]; total_count: number; estimated_total_msat: number; from_ms: number; to_ms: number; }
export interface ResyncFulfillResponse { phase: "fulfill"; resynced_count: number; failed_count: number; plaintext_count: number; total_msat: number; }
export interface SessionStatusResponse {
  peer_id: string;
  active: boolean;
}

export interface PeerPricingResponse {
  peer_id: string;
  prices: Record<string, number>;
  block_height: number;
  valid_blocks: number;
  age_secs: number;
  stale: boolean;
}

// ── Rooms ───────────────────────────────────────────────────────────────

export interface CreateRoomRequest {
  name: string;
  metadata?: Record<string, unknown>;
}

export interface RoomResponse {
  id: string;
  name: string;
  created_by: string;
  created_at: string;
  metadata: Record<string, unknown>;
}

// ── Peers ───────────────────────────────────────────────────────────────

export interface PeerResponse {
  node_id: string;
  addr: string;
  label: string | null;
  connected: boolean;
  auto_connect: boolean;
  fingerprint: string;
  safety_number: string;
  /** Sovereignty tier advertised during federation handshake (e.g. "T1", "T2"). */
  tier?: string;
  /** Capabilities advertised during federation handshake (e.g. "X3dh", "FileTransfer"). */
  capabilities?: string[];
}

export interface AddPeerRequest {
  node_id: string;
  addr: string;
  label?: string;
  auto_connect?: boolean;
}

export interface UpdatePeerRequest {
  addr?: string;
  label?: string;
  auto_connect?: boolean;
}

export interface PeerBackupEntry {
  node_id: string;
  addr: string;
  label: string | null;
  auto_connect: boolean;
}

export interface PeerBackup {
  version: number;
  exported_at: string;
  exported_by: string;
  peers: PeerBackupEntry[];
}

export interface ImportPeersRequest {
  backup: PeerBackup;
  skip_existing?: boolean;
}

export interface ImportPeersResponse {
  imported: number;
  skipped: number;
  errors: string[];
}

// ── Payments ────────────────────────────────────────────────────────────

export interface CreateInvoiceRequest {
  amount_msat: number;
  description?: string;
  expiry_secs?: number;
}

export interface InvoiceResponse {
  bolt11: string;
  payment_hash: string;
}

export interface PaymentStatusResponse {
  payment_hash: string;
  status: string;
  amount_msat: number;
  direction: string;
}

export interface BalanceResponse {
  balance_msat: number;
}

export interface PayInvoiceRequest {
  bolt11: string;
}

export interface PayInvoiceResponse {
  payment_hash: string;
  amount_msat: number;
  preimage: string;
}

export interface ChannelResponse {
  /** Stable channel identifier used for close/stats operations. */
  channel_id: string;
  peer_pubkey: string;
  capacity_msat: number;
  local_balance_msat: number;
  remote_balance_msat: number;
  active: boolean;
  short_channel_id: string | null;
}

export interface ChannelStatsResponse {
  channel_id: string;
  /** Seconds the node has been running (proxy for channel uptime). */
  uptime_secs: number;
  /** Total value routed through this channel in millisatoshis. */
  routed_volume_msat: number;
  /** Total routing fees earned on this channel in millisatoshis. */
  fees_earned_msat: number;
}

export interface PaymentListEntry {
  payment_hash: string;
  preimage: string | null;
  amount_msat: number;
  status: string;
  direction: string;
  timestamp: number;
  memo: string | null;
  fee_msat: number | null;
}

export interface PriceResponse {
  kind: number;
  price_msat: number;
}

export interface NodePricingInfo {
  mode: string;
  block_height: number;
  valid_blocks: number;
  trust_level: string;
  difficulty_epoch_position: number;
  prices: Record<string, number>;
  raw_fee_rate?: number;
  ema_fee_rate?: number;
  max_price_multiplier?: number;
}

// ── Files ───────────────────────────────────────────────────────────────

export interface UploadFileRequest {
  filename: string;
  mime_type?: string;
  data_b64: string;
}

export interface UploadFileResponse {
  file_id: string;
  size_bytes: number;
  blake3_hash: string;
}

export interface FileResponse {
  id: string;
  filename: string;
  mime_type: string;
  size_bytes: number;
  blake3_hash: string;
  sender: string;
  message_id: string | null;
  created_at: string;
}

export interface DownloadFileResponse {
  id: string;
  filename: string;
  mime_type: string;
  size_bytes: number;
  blake3_hash: string;
  sender: string;
  data_b64: string;
}

export interface SendFileRequest {
  recipient: string;
}

export interface SendFileResponse {
  message_id: string;
  delivered: boolean;
  amount_msat: number;
}

// ── Content Management ──────────────────────────────────────────────────

export interface ContentPageInfo {
  path: string;
  title: string;
  size_bytes: number;
  modified_ms: number;
  content_type: string;
}

export interface ContentPageList {
  enabled: boolean;
  content_dir: string;
  pages: ContentPageInfo[];
}

export interface ContentPageRead {
  path: string;
  title: string;
  content: string;
  size_bytes: number;
  content_type: string;
}

export interface ContentPageWrite {
  path: string;
  title: string;
  size_bytes: number;
}

// ── Web Manifest ───────────────────────────────────────────────────────

export interface ManifestPage {
  path: string;
  title: string;
  description: string;
  price_msat: number | null;
}

export interface WebManifest {
  site_name: string;
  pages: ManifestPage[];
  default_price_msat: number;
  free_paths: string[];
  block_height: number;
}

// ── WebSocket ───────────────────────────────────────────────────────────

/** A UKM envelope received over the WebSocket, with optional decrypted content. */
export interface WsEnvelope {
  id: string;
  kind: number;
  sender: string;
  recipient: { Node: string } | { Room: string };
  timestamp: number;
  ciphertext: string;
  /** Decrypted plaintext (UTF-8). Present when the node has an active E2EE session. */
  plaintext?: string;
  payment_proof: {
    payment_hash: string;
    preimage: string;
    amount_msat: number;
  };
  signature: string;
  /** Message references for threading (hex IDs). Present on KIND_REPLY messages. */
  references?: string[];
}

/** Delivery status update received over the WebSocket. */
export interface WsDeliveryStatus {
  type: "delivery_status" | "onboarding_progress";
  message_id: string;
  status: string;
  reason?: string;
}

/** Operator hosting payment status update received over the WebSocket. */
export interface WsHostingEvent {
  type: "operator_hosting_overdue";
  /** Hosting contract id. Reuses the backend status envelope's message_id field. */
  message_id: string;
  status: "overdue" | "paused";
  reason?: string;
}

// ── Message Kinds ───────────────────────────────────────────────────────

export const MessageKind = {
  // Communication (0-99) — must match crates/konsensus-core/src/kind.rs
  CHAT: 0,
  LONGFORM: 1,
  REPLY: 2,
  REACTION: 3,
  EDIT: 4,
  DELETE: 5,
  FORWARD: 6,

  // Structured Data (100-199)
  CALENDAR_EVENT: 100,
  CALENDAR_RSVP: 101,
  CONTACT: 102,
  CALENDAR_UPDATE: 103,

  // Files & Media (200-299)
  FILE_REF: 200,
  INLINE_IMAGE: 201,
  VOICE_MEMO: 202,

  // Collaboration (300-399)
  CRDT_OP: 300,
  DOC_SNAPSHOT: 301,

  // Real-time Signaling (400-499)
  CALL_INVITE: 400,
  CALL_ANSWER: 401,
  ICE_CANDIDATE: 402,
  CALL_HANGUP: 403,

  // Web Content (500-599)
  PAGE_REQUEST: 500,
  PAGE_RESPONSE: 501,
  WEB_MANIFEST: 510,

  // Control (900-999)
  TYPING: 900,
  READ_RECEIPT: 901,
  PRESENCE: 902,
  ROOM_CREATE: 910,
  KEY_EXCHANGE: 950,
} as const;

// ── Contacts ─────────────────────────────────────────────────────────────

/** API representation of a contact (peer whose profile has been received). */
export interface ContactResponse {
  node_id: string;
  /** Local nickname set by this node — never shared with the peer. */
  local_alias?: string;
  /** Display name claimed by the peer in their last received profile. */
  claimed_name?: string;
  /** Full NodeProfile payload (last received). */
  profile: Record<string, unknown>;
  /** Blake3 hash of the avatar image; fetch via `/api/v1/avatars/:hash`. */
  avatar_blake3?: string;
  /** Verified external identity claims (e.g. domain, GitHub). */
  verified_identities: unknown[];
  muted: boolean;
  blocked: boolean;
  tags: string[];
  notes?: string;
  created_at: string;
  updated_at: string;
}

/** Updatable local-only fields for a contact. */
export interface PatchContactRequest {
  /** Set to empty string to clear. */
  local_alias?: string;
  muted?: boolean;
  blocked?: boolean;
  tags?: string[];
  notes?: string;
}

// ── Calendar Free/Busy ──────────────────────────────────────────────────

/** A single busy time interval (Unix ms). */
export interface BusyBlock {
  start: number;
  end: number;
}

/** Response from `GET /api/v1/calendar/freebusy`. */
export interface FreeBusyResponse {
  peer: string;
  from: number;
  to: number;
  busy: BusyBlock[];
}

// ── Invite ──────────────────────────────────────────────────────────────

export interface GenerateInviteRequest {
  addr: string;
  label?: string;
  expiry_secs?: number;
}

export interface GenerateInviteResponse {
  token: string;
  uri: string;
  expiry: number;
}

export interface RedeemInviteRequest {
  invite: string;
  auto_connect?: boolean;
}

export interface RedeemInviteResponse {
  node_id: string;
  addr: string;
  label?: string;
  added: boolean;
  fingerprint: string;
}

// ── Invites (plural, Track ONB) ──────────────────────────────────────────

export interface AcceptInviteRequest {
  token: string;
}

export interface AcceptInviteResponse {
  inviter_pubkey: string;
  channel_size_hint: number | null;
  addr: string;
  max_fee_rate_sat_per_vb: number | null;
  channel_open_intent_expiry_unix: number | null;
}

export interface StartOnboardingRequest {
  tier: "light" | "full";
  funding_amount_sats?: number;
  invite_id?: string;
  inviter_pubkey?: string;
}

export interface OnboardingStateResponse {
  invite_id?: string;
  inviter_pubkey?: string;
  inviter_ln_pubkey?: string;
  current_step: string;
  tier?: "light" | "full";
  funding_address?: string;
  funding_amount_sats_required?: number;
  funding_amount_sats_received: number;
  last_poll_at?: number;
  funding_evidence?: "wallet_balance_observed";
}

export interface IssueInviteRequest {
  invitee_pubkey: string;
  expiry_unix: number;
  channel_size_hint_sats?: number;
  addr: string;
  max_fee_rate_sat_per_vb?: number;
  channel_open_intent_expiry_unix?: number;
}

export interface IssueInviteResponse {
  invite_id: string;
  invite_token_b64: string;
  invite_link: string;
}

export interface InviteCapabilitiesResponse {
  supported_versions: number[];
  default_version: number;
  invite_v2_runtime_ready: boolean;
  invite_v2_storage_ready: boolean;
  invite_v2_ready: boolean;
  addr_column: boolean;
  max_fee_rate_sat_per_vb_column: boolean;
  channel_open_intent_expiry_unix_column: boolean;
}

export interface InviteListEntry {
  id: string;
  invitee_pubkey: string;
  expiry_unix: number;
  channel_size_hint_sats: number | null;
  addr: string;
  max_fee_rate_sat_per_vb: number | null;
  channel_open_intent_expiry_unix: number | null;
  state: "pending" | "accepted" | "opening" | "revoked" | "expired";
  created_at: number;
  invite_token_b64: string;
}

// ── Reactions ────────────────────────────────────────────────────────────────

/** A single aggregated reaction on a message. */
export interface ReactionCount {
  emoji: string;
  count: number;
  /** True if the local node has already sent this reaction. */
  reacted_by_me: boolean;
}

/** Response from `GET /api/v1/messages/:id/reactions`. */
export interface MessageReactionsResponse {
  message_id: string;
  reactions: ReactionCount[];
}

/** Request body for `POST /api/v1/messages/:id/react`. */
export interface ReactRequest {
  emoji: string;
}

/** Response from `POST /api/v1/messages/:id/react`. */
export interface ReactResponse {
  message_id: string;
  emoji: string;
  action: "added" | "removed";
}

export function kindName(kind: number): string {
  // Communication (0-99)
  if (kind === MessageKind.CHAT) return "Chat";
  if (kind === MessageKind.LONGFORM) return "Long-form";
  if (kind === MessageKind.REPLY) return "Reply";
  if (kind === MessageKind.REACTION) return "Reaction";
  if (kind === MessageKind.EDIT) return "Edit";
  if (kind === MessageKind.DELETE) return "Delete";
  if (kind === MessageKind.FORWARD) return "Forward";
  if (kind <= 99) return "Chat";

  // Structured Data (100-199)
  if (kind === MessageKind.CALENDAR_EVENT) return "Calendar Event";
  if (kind === MessageKind.CALENDAR_RSVP) return "RSVP";
  if (kind === MessageKind.CONTACT) return "Contact";
  if (kind === MessageKind.CALENDAR_UPDATE) return "Calendar Update";
  if (kind <= 199) return "Structured";

  // Files & Media (200-299)
  if (kind === MessageKind.FILE_REF) return "File";
  if (kind === MessageKind.INLINE_IMAGE) return "Image";
  if (kind === MessageKind.VOICE_MEMO) return "Voice Memo";
  if (kind <= 299) return "File";

  if (kind <= 399) return "Collaboration";
  if (kind <= 499) return "Signaling";
  if (kind <= 599) return "Web Content";
  if (kind <= 899) return "Reserved";
  if (kind <= 999) return "Control";
  return "App Extension";
}

// ── Calendar Free/Busy ──────────────────────────────────────────────────

export interface BusyBlock {
  /** Unix ms start of busy period. */
  start: number;
  /** Unix ms end of busy period. */
  end: number;
}

export interface FreeBusyResponse {
  peer: string;
  from: number;
  to: number;
  busy: BusyBlock[];
}
