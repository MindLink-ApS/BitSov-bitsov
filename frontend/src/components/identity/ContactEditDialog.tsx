/**
 * ContactEditDialog — modal dialog to edit local-only contact fields:
 * local_alias, notes, muted, and blocked.
 *
 * Only local annotations are editable here.  Peer-originated fields
 * (claimed_name, verified_identities, profile) are read-only.
 */

import { createSignal, Show } from "solid-js";
import { contacts, patchContact, refreshProfile } from "../../stores/contacts";
import DisplayName from "./DisplayName";

interface ContactEditDialogProps {
  nodeId: string;
  onClose: () => void;
}

export default function ContactEditDialog(props: ContactEditDialogProps) {
  const contact = () => contacts.find((c) => c.node_id === props.nodeId);

  const [alias, setAlias] = createSignal(contact()?.local_alias ?? "");
  const [notes, setNotes] = createSignal(contact()?.notes ?? "");
  const [muted, setMuted] = createSignal(contact()?.muted ?? false);
  const [blocked, setBlocked] = createSignal(contact()?.blocked ?? false);
  const [saving, setSaving] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);

  const handleSave = async () => {
    setSaving(true);
    setError(null);
    const result = await patchContact(props.nodeId, {
      local_alias: alias().trim() || undefined,
      notes: notes().trim() || undefined,
      muted: muted(),
      blocked: blocked(),
    });
    setSaving(false);
    if (result) {
      props.onClose();
    } else {
      setError("Failed to save — please try again.");
    }
  };

  const handleRefreshProfile = async () => {
    setSaving(true);
    await refreshProfile(props.nodeId);
    setSaving(false);
  };

  const handleOverlayClick = (e: MouseEvent) => {
    if (e.target === e.currentTarget) props.onClose();
  };

  return (
    <div
      class="dialog-overlay"
      onClick={handleOverlayClick}
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0,0,0,0.5)",
        display: "flex",
        "align-items": "center",
        "justify-content": "center",
        "z-index": "1000",
      }}
    >
      <div
        class="dialog glass"
        role="dialog"
        aria-modal="true"
        aria-label={`Edit contact`}
        style={{
          "min-width": "320px",
          "max-width": "480px",
          width: "90vw",
          padding: "24px",
          "border-radius": "12px",
        }}
      >
        {/* Header */}
        <div class="flex items-center justify-between mb-16">
          <h3 class="text-base font-semibold">
            Edit <DisplayName nodeId={props.nodeId} />
          </h3>
          <button
            class="btn-icon text-muted"
            onClick={props.onClose}
            aria-label="Close dialog"
          >
            ✕
          </button>
        </div>

        {/* Read-only info */}
        <Show when={contact()?.claimed_name}>
          <div class="mb-12 text-xs text-muted">
            Self-claimed name:{" "}
            <span class="text-primary">{contact()!.claimed_name}</span>
          </div>
        </Show>

        {/* Local alias */}
        <div class="form-group mb-12">
          <label class="form-label text-sm" for="ce-alias">
            Local alias
            <span class="text-muted text-xs ml-6">(private, not shared)</span>
          </label>
          <input
            id="ce-alias"
            class="form-input"
            type="text"
            placeholder={contact()?.claimed_name ?? "Enter nickname…"}
            value={alias()}
            onInput={(e) => setAlias(e.currentTarget.value)}
            maxLength={64}
          />
        </div>

        {/* Notes */}
        <div class="form-group mb-12">
          <label class="form-label text-sm" for="ce-notes">
            Notes
            <span class="text-muted text-xs ml-6">(private)</span>
          </label>
          <textarea
            id="ce-notes"
            class="form-input"
            rows={3}
            placeholder="Private notes about this contact…"
            value={notes()}
            onInput={(e) => setNotes(e.currentTarget.value)}
            maxLength={512}
            style={{ resize: "vertical" }}
          />
        </div>

        {/* Muted / Blocked toggles */}
        <div class="flex gap-16 mb-16">
          <label class="flex items-center gap-8 text-sm cursor-pointer">
            <input
              type="checkbox"
              checked={muted()}
              onChange={(e) => setMuted(e.currentTarget.checked)}
            />
            Muted
          </label>
          <label class="flex items-center gap-8 text-sm cursor-pointer">
            <input
              type="checkbox"
              checked={blocked()}
              onChange={(e) => setBlocked(e.currentTarget.checked)}
            />
            Blocked
          </label>
        </div>

        {/* Error */}
        <Show when={error()}>
          <div class="text-xs text-error mb-12">{error()}</div>
        </Show>

        {/* Actions */}
        <div class="flex gap-8 justify-between">
          <button
            class="btn btn-ghost btn-sm"
            onClick={handleRefreshProfile}
            disabled={saving()}
            title="Ask this peer to re-send their profile"
          >
            Refresh profile
          </button>
          <div class="flex gap-8">
            <button
              class="btn btn-ghost btn-sm"
              onClick={props.onClose}
              disabled={saving()}
            >
              Cancel
            </button>
            <button
              class="btn btn-primary btn-sm"
              onClick={handleSave}
              disabled={saving()}
            >
              {saving() ? "Saving…" : "Save"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
