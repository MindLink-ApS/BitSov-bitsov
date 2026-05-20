/** Recovery wizard — restore node identity from a 24-word mnemonic.
 *
 * Two phases:
 * 1. Enter the 24-word mnemonic (paste or type word-by-word)
 * 2. Confirm — shows the derived Node ID so the user can verify it matches
 *
 * This component is used in the onboarding flow when a user chooses
 * "Restore existing identity" instead of creating a new one.
 *
 * The mnemonic is sent to the node's POST /api/v1/identity/restore endpoint
 * which re-derives the identity and reconfigures the node.
 */

import { createSignal, Show, For } from "solid-js";
import { IconKey, IconShield, IconCheck, IconLightbulb } from "./Icons";
import { getToken } from "../auth/session";

interface Props {
  onRestored: (nodeId: string) => void;
  onCancel: () => void;
}

/** BIP-39 word count options. */
const VALID_WORD_COUNTS = [12, 15, 18, 21, 24];

export default function RecoveryWizard(props: Props) {
  const [phase, setPhase] = createSignal<"input" | "confirm">("input");
  const [inputMode, setInputMode] = createSignal<"paste" | "words">("paste");
  const [pasteValue, setPasteValue] = createSignal("");
  const [wordInputs, setWordInputs] = createSignal<string[]>(Array(24).fill(""));
  const [error, setError] = createSignal("");
  const [loading, setLoading] = createSignal(false);
  const [derivedNodeId, setDerivedNodeId] = createSignal("");

  /** Get the mnemonic from whichever input mode is active. */
  const getMnemonic = (): string => {
    if (inputMode() === "paste") {
      return pasteValue().trim();
    }
    return wordInputs()
      .map((w) => w.trim().toLowerCase())
      .filter((w) => w.length > 0)
      .join(" ");
  };

  /** Basic client-side mnemonic validation. */
  const validateMnemonic = (): string | null => {
    const words = getMnemonic().split(/\s+/).filter((w) => w.length > 0);
    if (words.length === 0) return "Please enter your recovery phrase.";
    if (!VALID_WORD_COUNTS.includes(words.length)) {
      return `Expected 12, 15, 18, 21, or 24 words, got ${words.length}.`;
    }
    // Check for obviously wrong input (numbers, special chars)
    const invalid = words.find((w) => !/^[a-z]+$/.test(w));
    if (invalid) {
      return `"${invalid}" doesn't look like a BIP-39 word. Words should be lowercase letters only.`;
    }
    return null;
  };

  /** Submit mnemonic to the node for identity derivation. */
  const handleSubmit = async () => {
    const validationError = validateMnemonic();
    if (validationError) {
      setError(validationError);
      return;
    }

    setLoading(true);
    setError("");

    try {
      // Call the node API to validate the mnemonic and derive identity
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 30000);
      const resp = await fetch("/api/v1/identity/verify-mnemonic", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mnemonic: getMnemonic() }),
        signal: controller.signal,
      });
      clearTimeout(timeout);

      if (!resp.ok) {
        const body = await resp.text();
        throw new Error(body || `Server error: ${resp.status}`);
      }

      const data = await resp.json();
      setDerivedNodeId(data.node_id);
      setPhase("confirm");
    } catch (e: unknown) {
      if (e instanceof DOMException && e.name === "AbortError") {
        setError("Request timed out. Is your node running?");
      } else {
        setError(e instanceof Error ? e.message : "Failed to verify mnemonic. Is your node running?");
      }
    } finally {
      setLoading(false);
    }
  };

  /** Confirm the restore. */
  const handleConfirmRestore = async () => {
    setLoading(true);
    setError("");

    try {
      const restoreController = new AbortController();
      const restoreTimeout = setTimeout(() => restoreController.abort(), 30000);
      const headers: Record<string, string> = { "Content-Type": "application/json" };
      const token = getToken();
      if (token) {
        headers["Authorization"] = `Bearer ${token}`;
      }
      const resp = await fetch("/api/v1/identity/restore", {
        method: "POST",
        headers,
        body: JSON.stringify({ mnemonic: getMnemonic() }),
        signal: restoreController.signal,
      });
      clearTimeout(restoreTimeout);

      if (resp.status === 401) {
        throw new Error("Authentication required. Use the CLI command: konsensus restore --mnemonic <file>");
      }
      if (!resp.ok) {
        const body = await resp.text();
        throw new Error(body || `Restore failed: ${resp.status}`);
      }

      props.onRestored(derivedNodeId());
    } catch (e: unknown) {
      if (e instanceof DOMException && e.name === "AbortError") {
        setError("Request timed out. Is your node running?");
      } else {
        setError(e instanceof Error ? e.message : "Restore failed.");
      }
    } finally {
      setLoading(false);
    }
  };

  /** Update a single word input by index. */
  const updateWord = (index: number, value: string) => {
    setError("");
    const updated = [...wordInputs()];
    updated[index] = value;
    setWordInputs(updated);
  };

  /** Truncate hex string for display. */
  const truncateHex = (hex: string): string => {
    if (hex.length <= 20) return hex;
    return `${hex.slice(0, 12)}...${hex.slice(-12)}`;
  };

  return (
    <div class="mnemonic-wizard">
      <Show when={phase() === "input"}>
        <div class="mnemonic-display-phase">
          <div class="onboarding-tip" style={{ "margin-bottom": "16px" }}>
            <span class="onboarding-tip-icon"><IconKey size={18} /></span>
            <span>
              Enter your 24-word recovery phrase to restore your identity.
              Your mnemonic never leaves this device.
            </span>
          </div>

          {/* Input mode toggle */}
          <div class="flex gap-8 mb-16 justify-center">
            <button
              class={`btn btn-sm ${inputMode() === "paste" ? "btn-primary" : "btn-ghost"}`}
              onClick={() => setInputMode("paste")}
            >
              Paste phrase
            </button>
            <button
              class={`btn btn-sm ${inputMode() === "words" ? "btn-primary" : "btn-ghost"}`}
              onClick={() => setInputMode("words")}
            >
              Enter word by word
            </button>
          </div>

          {/* Paste mode */}
          <Show when={inputMode() === "paste"}>
            <div class="form-group">
              <label class="form-label">Recovery Phrase</label>
              <textarea
                class={`w-full mono ${error() ? "input-error" : ""}`}
                rows={4}
                placeholder="Enter your 24 words separated by spaces..."
                value={pasteValue()}
                onInput={(e) => {
                  setError("");
                  setPasteValue(e.currentTarget.value);
                }}
                autocomplete="off"
                spellcheck={false}
                style={{ resize: "vertical", "min-height": "80px" }}
              />
            </div>
          </Show>

          {/* Word-by-word mode */}
          <Show when={inputMode() === "words"}>
            <div class="mnemonic-grid" style={{ "max-height": "320px", "overflow-y": "auto" }}>
              <For each={wordInputs()}>
                {(word, i) => (
                  <div class="mnemonic-confirm-field">
                    <label class="form-label text-xs">Word #{i() + 1}</label>
                    <input
                      type="text"
                      class={`mnemonic-confirm-input ${error() ? "input-error" : ""}`}
                      placeholder={`Word ${i() + 1}`}
                      value={word}
                      onInput={(e) => updateWord(i(), e.currentTarget.value)}
                      autocomplete="off"
                      spellcheck={false}
                    />
                  </div>
                )}
              </For>
            </div>
          </Show>

          {/* Error */}
          <Show when={error()}>
            <div class="alert alert-error text-sm mt-12 animate-fade-in">
              {error()}
            </div>
          </Show>

          {/* Actions */}
          <div class="flex gap-8 mt-16">
            <button class="btn btn-ghost" onClick={props.onCancel}>
              Cancel
            </button>
            <button
              class="btn btn-primary"
              onClick={handleSubmit}
              disabled={loading()}
            >
              {loading() ? "Verifying..." : "Verify Mnemonic"}
            </button>
          </div>
        </div>
      </Show>

      {/* Confirmation phase — show derived Node ID */}
      <Show when={phase() === "confirm"}>
        <div class="mnemonic-confirm-phase">
          <div class="onboarding-tip" style={{ "margin-bottom": "16px" }}>
            <span class="onboarding-tip-icon"><IconShield size={18} /></span>
            <span>
              Your mnemonic is valid. Verify that this Node ID matches your
              previous identity before confirming the restore.
            </span>
          </div>

          <div class="card" style={{ padding: "16px", "text-align": "center" }}>
            <div class="text-xs text-muted mb-8">Derived Node ID</div>
            <div class="mono text-sm" style={{ "word-break": "break-all" }}>
              {derivedNodeId()}
            </div>
          </div>

          <div class="onboarding-tip mt-16" style={{ background: "var(--color-warning-bg)" }}>
            <span class="onboarding-tip-icon"><IconLightbulb size={18} /></span>
            <span>
              Restoring will replace the current node identity. This cannot be undone.
            </span>
          </div>

          {/* Error */}
          <Show when={error()}>
            <div class="alert alert-error text-sm mt-12 animate-fade-in">
              {error()}
            </div>
          </Show>

          <div class="flex gap-8 mt-16">
            <button class="btn btn-ghost" onClick={() => { setPhase("input"); setError(""); }}>
              Back
            </button>
            <button
              class="btn btn-primary"
              onClick={handleConfirmRestore}
              disabled={loading()}
            >
              <IconCheck size={14} />
              <span style={{ "margin-left": "6px" }}>
                {loading() ? "Restoring..." : "Confirm Restore"}
              </span>
            </button>
          </div>
        </div>
      </Show>
    </div>
  );
}
