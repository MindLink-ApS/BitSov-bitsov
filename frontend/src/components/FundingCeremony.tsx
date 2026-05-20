import { createMemo, createSignal, onCleanup, onMount, Show } from "solid-js";
import qrcode from "qrcode-generator";
import { api } from "../stores/auth";
import type { OnboardingStateResponse } from "../api/types";
import { IconCheck, IconCopy, IconLoader, IconLightning } from "./Icons";
import { applyServerStep } from "../state/onboarding";

function satsToBtc(sats: number): string {
  return (sats / 100_000_000).toFixed(8);
}

function bitcoinUri(address: string, sats: number): string {
  const amount = sats > 0 ? `?amount=${satsToBtc(sats)}` : "";
  return `bitcoin:${address}${amount}`;
}

export default function FundingCeremony() {
  const [state, setState] = createSignal<OnboardingStateResponse | null>(null);
  const [loading, setLoading] = createSignal(true);
  const [error, setError] = createSignal<string | null>(null);
  const [copied, setCopied] = createSignal(false);

  const requiredSats = () => state()?.funding_amount_sats_required ?? 0;
  const receivedSats = () => state()?.funding_amount_sats_received ?? 0;
  const address = () => state()?.funding_address ?? "";
  const progressPct = () => {
    const required = requiredSats();
    if (required <= 0) return 0;
    return Math.min(100, Math.round((receivedSats() / required) * 100));
  };

  const qrDataUrl = createMemo(() => {
    const addr = address();
    if (!addr) return "";
    const qr = qrcode(0, "M");
    qr.addData(bitcoinUri(addr, requiredSats()));
    qr.make();
    return qr.createDataURL(4, 2);
  });

  async function refresh() {
    try {
      const next = await api.onboardingState();
      setState(next);
      setError(null);
      applyServerStep(next.current_step);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to load funding state");
    } finally {
      setLoading(false);
    }
  }

  async function copyAddress() {
    const addr = address();
    if (!addr) return;
    try {
      await navigator.clipboard.writeText(addr);
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    } catch {
      setError("Unable to copy address");
    }
  }

  onMount(() => {
    void refresh();
    const timer = setInterval(() => void refresh(), 5000);
    onCleanup(() => clearInterval(timer));
  });

  return (
    <div class="onboarding-step animate-fade-in">
      <div class="onboarding-icon-large">
        <IconLightning size={48} class="text-warning" />
      </div>
      <h1 class="onboarding-title">Fund Your Node</h1>
      <p class="onboarding-desc">
        Send the required sats to this wallet address. The node advances when
        the backend observes the funding state.
      </p>

      <Show
        when={!loading() && address()}
        fallback={
          <div class="connection-status-list mt-6">
            <div class="status-item">
              <IconLoader size={16} class="animate-spin" />
              <span>Loading funding address</span>
            </div>
          </div>
        }
      >
        <div class="confirm-card glass-subtle p-4 rounded-lg mt-4">
          <div class="flex flex-col items-center gap-4">
            <img
              src={qrDataUrl()}
              alt="Bitcoin funding QR"
              width="192"
              height="192"
              style={{ "image-rendering": "pixelated" }}
            />

            <div class="w-full">
              <span class="text-xs text-muted uppercase tracking-wider">
                Funding Address
              </span>
              <button
                class="btn btn-ghost w-full mt-2"
                onClick={copyAddress}
                title="Copy funding address"
              >
                <span class="mono break-all text-sm">{address()}</span>
                <Show
                  when={copied()}
                  fallback={<IconCopy size={16} aria-hidden="true" />}
                >
                  <IconCheck size={16} class="text-success" aria-hidden="true" />
                </Show>
              </button>
            </div>

            <div class="w-full connection-status-list">
              <div class="status-item done">
                <IconLightning size={16} class="text-warning" />
                <span>
                  Required: {requiredSats().toLocaleString()} sats
                </span>
              </div>
              <div class="status-item">
                <IconLoader size={16} class="animate-spin" />
                <span>
                  Observed: {receivedSats().toLocaleString()} sats
                  <Show when={progressPct() > 0}> ({progressPct()}%)</Show>
                </span>
              </div>
            </div>
          </div>
        </div>
      </Show>

      <Show when={error()}>
        <div class="error-text mt-4">{error()}</div>
      </Show>

      <div class="onboarding-nav mt-6">
        <button class="btn btn-ghost" onClick={() => void refresh()}>
          Refresh
        </button>
      </div>
    </div>
  );
}
