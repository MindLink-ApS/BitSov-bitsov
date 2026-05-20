/**
 * Onboarding state machine — manages the invite-paste-accept flow.
 */

import { createSignal } from "solid-js";
import type { WsDeliveryStatus } from "../api/types";
import { api, ws } from "../stores/auth";

export type OnboardingStep =
  | "paste-invite"
  | "confirm-invite"
  | "funding"
  | "connecting"
  | "first-message";

const [step, setStep] = createSignal<OnboardingStep>("paste-invite");
const [inviteToken, setInviteToken] = createSignal("");
const [inviterPubkey, setInviterPubkey] = createSignal("");
const [channelSizeHint, setChannelSizeHint] = createSignal(0);
const [error, setError] = createSignal<string | null>(null);
const [isProcessing, setIsProcessing] = createSignal(false);
const [inFlow, setInFlow] = createSignal(false);
const [dismissed, setDismissed] = createSignal(false);
const [progressText, setProgressText] = createSignal("Waiting for secure connection...");
const [lastProgressAt, setLastProgressAt] = createSignal<number>(0);

const PENDING_CONVERSATION_KEY = "bitsov_pending_conv";
let stopWsProgress: (() => void) | null = null;
let pollTimer: ReturnType<typeof setInterval> | null = null;

function reset() {
  stopProgressTracking();
  setStep("paste-invite");
  setInviteToken("");
  setInviterPubkey("");
  setChannelSizeHint(0);
  setError(null);
  setIsProcessing(false);
  setInFlow(false);
  setProgressText("Waiting for secure connection...");
  setLastProgressAt(0);
}

function goToStep(s: OnboardingStep) {
  setStep(s);
  setError(null);
}

function extractToken(input: string): string {
  const trimmed = input.trim();
  const prefix = "bitsov://invite/";
  if (trimmed.startsWith(prefix)) return trimmed.slice(prefix.length);
  return trimmed;
}

interface DecodedForDisplay {
  inviter_pubkey_hex: string;
  channel_size_hint_sats: number;
}

function decodeTokenForDisplay(token: string): DecodedForDisplay | null {
  try {
    const raw = extractToken(token);
    if (!raw) return null;
    const padded =
      raw.replace(/-/g, "+").replace(/_/g, "/") +
      "===".slice((raw.length + 3) % 4);
    const json = atob(padded);
    const parsed = JSON.parse(json);
    if (
      !parsed ||
      !Array.isArray(parsed.inviter_pubkey) ||
      parsed.inviter_pubkey.length !== 32
    ) {
      return null;
    }
    const hex = (parsed.inviter_pubkey as number[])
      .map((b) => (b & 0xff).toString(16).padStart(2, "0"))
      .join("");
    const hint =
      typeof parsed.channel_size_hint_sats === "number"
        ? parsed.channel_size_hint_sats
        : 0;
    return { inviter_pubkey_hex: hex, channel_size_hint_sats: hint };
  } catch {
    return null;
  }
}

function submitInvite(rawInput: string) {
  setInFlow(true);
  setDismissed(false);
  setError(null);
  const decoded = decodeTokenForDisplay(rawInput);
  if (!decoded) {
    setError("Invalid invite token. Check the link and try again.");
    return;
  }
  setInviteToken(extractToken(rawInput));
  setInviterPubkey(decoded.inviter_pubkey_hex);
  setChannelSizeHint(decoded.channel_size_hint_sats);
  setStep("confirm-invite");
}

function exitToHome() {
  window.history.pushState({}, "", "/home");
  reset();
  setDismissed(true);
}

function completeToChat() {
  const peerId = inviterPubkey();
  if (peerId) {
    try {
      sessionStorage.setItem(
        PENDING_CONVERSATION_KEY,
        JSON.stringify({ key: peerId, isRoom: false }),
      );
    } catch {
      // Continue to chat even if browser storage is unavailable.
    }
  }
  window.history.pushState({}, "", "/chat");
  stopProgressTracking();
  setInFlow(false);
}

async function confirmInvite() {
  setIsProcessing(true);
  setError(null);
  try {
    const res = await api.acceptInvite({ token: inviteToken() });
    setInviterPubkey(res.inviter_pubkey);
    if (typeof res.channel_size_hint === "number") {
      setChannelSizeHint(res.channel_size_hint);
    }
    setStep("connecting");
    startProgressTracking();
  } catch (e) {
    setError(e instanceof Error ? e.message : "Failed to accept invite");
  } finally {
    setIsProcessing(false);
  }
}

function progressMessage(stepValue: string): string {
  switch (stepValue) {
    case "noise_connected":
      return "Secure transport connected";
    case "lightning_info_sent":
      return "Lightning details shared";
    case "funding":
      return "Waiting for wallet funding";
    case "funding-seen":
      return "Funding observed by wallet";
    case "waiting_for_inviter_channel":
      return "Waiting for inviter channel";
    case "channel_pending":
      return "Channel opening is pending";
    case "channel_ready":
      return "Channel is ready";
    case "channel_failed":
      return "Channel opening failed";
    default:
      return "Waiting for secure connection...";
  }
}

function applyServerStep(stepValue: string): void {
  if (!stepValue) return;
  const currentStep = step();
  setLastProgressAt(Date.now());
  setProgressText(progressMessage(stepValue));
  if (stepValue === "funding") {
    setStep("funding");
  } else if (stepValue === "funding-seen") {
    if (currentStep !== "connecting" && currentStep !== "first-message") {
      setStep("connecting");
      startProgressTracking();
    }
  } else if (stepValue === "channel_ready") {
    setStep("first-message");
  } else if (stepValue === "channel_failed") {
    setError("Channel opening failed. Ask your inviter to re-issue an invite.");
  } else if (currentStep !== "connecting" && currentStep !== "first-message") {
    setStep("connecting");
  }
}

async function refreshProgressFromApi(): Promise<void> {
  try {
    const state = await api.onboardingState();
    applyServerStep(state.current_step);
  } catch {
    // Keep waiting; state may not exist yet.
  }
}

function onProgressEvent(event: WsDeliveryStatus): void {
  if (event.type !== "onboarding_progress") return;
  applyServerStep(event.status);
}

function startProgressTracking(): void {
  stopProgressTracking();
  setLastProgressAt(Date.now());
  void refreshProgressFromApi();
  stopWsProgress = ws.onDelivery(onProgressEvent);
  pollTimer = setInterval(() => {
    if (Date.now() - lastProgressAt() >= 30000) {
      void refreshProgressFromApi();
    }
  }, 5000);
}

function stopProgressTracking(): void {
  if (stopWsProgress) {
    stopWsProgress();
    stopWsProgress = null;
  }
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
}

export {
  step,
  inviteToken,
  inviterPubkey,
  channelSizeHint,
  error,
  isProcessing,
  inFlow,
  dismissed,
  progressText,
  setInFlow,
  setInviteToken,
  goToStep,
  applyServerStep,
  submitInvite,
  confirmInvite,
  exitToHome,
  completeToChat,
  PENDING_CONVERSATION_KEY,
  reset,
};
