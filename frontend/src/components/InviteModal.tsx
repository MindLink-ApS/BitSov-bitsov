import { createSignal, Show, For } from "solid-js";
import { IconX, IconCheck, IconCopy } from "./Icons";
import { api } from "../stores/auth";
import { toast } from "../stores/toast";

/**
 * InviteModal — modal to issue a new BitSov invite.
 * Bound to an invitee pubkey with selectable expiry and channel size hint.
 */
interface Props {
  show: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

const EXPIRY_OPTIONS = [
  { label: "24 hours", value: 24 * 3600 },
  { label: "7 days", value: 7 * 24 * 3600 },
  { label: "30 days", value: 30 * 24 * 3600 },
];

export default function InviteModal(props: Props) {
  const [inviteePubkey, setInviteePubkey] = createSignal("");
  const [addr, setAddr] = createSignal("");
  const [expirySecs, setExpirySecs] = createSignal(EXPIRY_OPTIONS[1].value); // 7 days default
  const [channelSize, setChannelSize] = createSignal<number | undefined>(50000);
  const [maxFeeRate, setMaxFeeRate] = createSignal<number | undefined>(50);
  const [loading, setLoading] = createSignal(false);
  const [result, setResult] = createSignal<{ link: string; token: string } | null>(null);
  const [copied, setCopied] = createSignal(false);

  const handleCreate = async (e: Event) => {
    e.preventDefault();
    const pubkey = inviteePubkey().trim();
    if (pubkey.length !== 64) {
      toast.error("Invitee public key must be 64 hex characters");
      return;
    }
    const inviteAddr = addr().trim();
    if (!inviteAddr || !inviteAddr.includes(":")) {
      toast.error("Enter your node address as host:port");
      return;
    }

    setLoading(true);
    try {
      const capabilities = await api.getInviteCapabilities();
      if (!capabilities.invite_v2_ready) {
        toast.error("Invite v2 is unavailable on this node; finish the node update before creating invites.");
        return;
      }
      const now = Math.floor(Date.now() / 1000);
      const res = await api.issueInvite({
        invitee_pubkey: pubkey,
        expiry_unix: now + expirySecs(),
        channel_size_hint_sats: channelSize(),
        addr: inviteAddr,
        max_fee_rate_sat_per_vb: maxFeeRate(),
      });
      setResult({ link: res.invite_link, token: res.invite_token_b64 });
      props.onSuccess();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to create invite");
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = () => {
    const res = result();
    if (!res) return;
    navigator.clipboard
      .writeText(res.link)
      .then(() => {
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      })
      .catch((e) => {
        console.error("clipboard write failed", e);
      });
  };

  const close = () => {
    setResult(null);
    setInviteePubkey("");
    setAddr("");
    props.onClose();
  };

  return (
    <Show when={props.show}>
      <div class="modal-overlay" onClick={close} style={{ "z-index": 500 }}>
        <div class="modal-card glass" onClick={(e) => e.stopPropagation()} style={{ "max-width": "480px" }}>
          <div class="modal-header">
            <h3 class="modal-title">New Invite</h3>
            <button class="btn btn-ghost btn-sm" onClick={close}>
              <IconX size={18} />
            </button>
          </div>

          <Show when={!result()} fallback={
            <div class="modal-body p-20 text-center">
              <div class="flex justify-center mb-16">
                <div style={{
                  background: "var(--color-success-dim)",
                  width: "64px",
                  height: "64px",
                  "border-radius": "50%",
                  display: "flex",
                  "align-items": "center",
                  "justify-content": "center"
                }}>
                  <IconCheck size={32} style={{ color: "var(--color-success)" }} />
                </div>
              </div>
              <h4 class="text-lg font-bold mb-8">Invite Created</h4>
              <p class="text-muted text-sm mb-20">
                Share this link with the invitee. It is single-use and bound to their node ID.
              </p>
              
              <div class="copyable mb-20">
                <span class="mono truncate text-xs flex-1 text-left">
                  {result()?.link}
                </span>
                <button class="btn btn-primary btn-sm" onClick={handleCopy}>
                  {copied() ? "Copied" : "Copy Link"}
                </button>
              </div>

              <button class="btn btn-secondary w-full" onClick={close}>
                Done
              </button>
            </div>
          }>
            <form onSubmit={handleCreate}>
              <div class="modal-body p-20">
                <div class="form-group mb-16">
                  <label class="form-label">Invitee Public Key</label>
                  <input
                    type="text"
                    class="form-input mono"
                    placeholder="Ed25519 hex (64 chars)"
                    value={inviteePubkey()}
                    onInput={(e) => setInviteePubkey(e.currentTarget.value)}
                    required
                    autofocus
                  />
                  <p class="form-hint">The node ID of the person you are inviting.</p>
                </div>

                <div class="form-group mb-16">
                  <label class="form-label">Your Node Address</label>
                  <input
                    type="text"
                    class="form-input"
                    placeholder="host:port (e.g. node.example.com:9735)"
                    value={addr()}
                    onInput={(e) => setAddr(e.currentTarget.value)}
                    required
                  />
                  <p class="form-hint">Signed into the invite so the invitee can dial you directly.</p>
                </div>

                <div class="form-group mb-16">
                  <label class="form-label">Expiry</label>
                  <div class="flex gap-8">
                    <For each={EXPIRY_OPTIONS}>
                      {(opt) => (
                        <button
                          type="button"
                          class={`btn btn-sm flex-1 ${expirySecs() === opt.value ? "btn-primary" : "btn-ghost"}`}
                          onClick={() => setExpirySecs(opt.value)}
                        >
                          {opt.label}
                        </button>
                      )}
                    </For>
                  </div>
                </div>

                <div class="form-group">
                  <label class="form-label">Channel Size Hint (sats)</label>
                  <input
                    type="number"
                    class="form-input"
                    value={channelSize() ?? ""}
                    onInput={(e) => setChannelSize(parseInt(e.currentTarget.value) || undefined)}
                    placeholder="e.g. 50000"
                  />
                  <p class="form-hint">Suggested initial capacity for the Lightning channel.</p>
                </div>

                <div class="form-group mt-16">
                  <label class="form-label">Max Channel Fee Rate (sat/vB)</label>
                  <input
                    type="number"
                    class="form-input"
                    min="1"
                    value={maxFeeRate() ?? ""}
                    onInput={(e) => setMaxFeeRate(parseInt(e.currentTarget.value) || undefined)}
                    placeholder="50"
                  />
                  <p class="form-hint">Upper bound signed into the invite for automatic channel opening.</p>
                </div>
              </div>

              <div class="modal-footer">
                <button type="button" class="btn btn-ghost" onClick={close}>
                  Cancel
                </button>
                <button type="submit" class="btn btn-primary" disabled={loading() || !inviteePubkey() || !addr()}>
                  {loading() ? "Creating..." : "Create Invite"}
                </button>
              </div>
            </form>
          </Show>
        </div>
      </div>
    </Show>
  );
}
