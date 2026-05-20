/** Mnemonic generation/display wizard — used in onboarding.
 *
 * Two sub-steps:
 * 1. Display the 24-word mnemonic with a strong "write it down" warning
 * 2. Confirmation test: user types back 3 random words to prove they saved it
 *
 * Note: relay/cloud compatibility never means hosted identity keys. If this
 * component is shown, the user must back up the phrase before pairing a relay.
 */

import { createSignal, Show, For, createMemo } from "solid-js";
import { IconLightbulb, IconCheck } from "./Icons";

interface Props {
  /** If available, the 24-word mnemonic from the node. */
  mnemonic?: string;
  onConfirmed: () => void;
}

/** Pick 3 random unique indices from 0..length-1. */
function pickRandomIndices(length: number, count: number): number[] {
  const indices: number[] = [];
  while (indices.length < count && indices.length < length) {
    const idx = Math.floor(Math.random() * length);
    if (!indices.includes(idx)) indices.push(idx);
  }
  return indices.sort((a, b) => a - b);
}

export default function MnemonicWizard(props: Props) {
  const [phase, setPhase] = createSignal<"display" | "confirm">("display");
  const [confirmInputs, setConfirmInputs] = createSignal<Record<number, string>>({});
  const [confirmError, setConfirmError] = createSignal(false);

  const words = createMemo(() => {
    if (!props.mnemonic) return [];
    return props.mnemonic.trim().split(/\s+/);
  });

  const testIndices = createMemo(() => {
    const w = words();
    if (w.length === 0) return [];
    return pickRandomIndices(w.length, 3);
  });

  const handleConfirm = () => {
    const w = words();
    const inputs = confirmInputs();
    const correct = testIndices().every(
      (idx) => inputs[idx]?.trim().toLowerCase() === w[idx].toLowerCase()
    );
    if (correct) {
      setConfirmError(false);
      props.onConfirmed();
    } else {
      setConfirmError(true);
    }
  };

  return (
    <div class="mnemonic-wizard">
      <Show when={phase() === "display"}>
        <div class="mnemonic-display-phase">
          <div class="onboarding-tip" style={{ "margin-bottom": "16px" }}>
            <span class="onboarding-tip-icon"><IconLightbulb size={18} /></span>
            <span>
              <strong>Write down these 24 words in order.</strong> This is the
              <em> only</em> way to recover your identity. Never share them.
              Never store them digitally.
            </span>
          </div>

          <Show when={words().length > 0} fallback={
            <div class="mnemonic-placeholder">
              <p class="text-secondary text-sm text-center">
                Your 24-word recovery phrase will be displayed here after your
                node generates your identity. Run <code class="mono">konsensus init</code> first.
              </p>
            </div>
          }>
            <div class="mnemonic-grid">
              <For each={words()}>
                {(word, i) => (
                  <div class="mnemonic-word">
                    <span class="mnemonic-word-num">{i() + 1}</span>
                    <span class="mnemonic-word-text">{word}</span>
                  </div>
                )}
              </For>
            </div>

            <button
              class="btn btn-primary mt-16"
              onClick={() => setPhase("confirm")}
            >
              I've written them down
            </button>
          </Show>
        </div>
      </Show>

      <Show when={phase() === "confirm"}>
        <div class="mnemonic-confirm-phase">
          <p class="text-secondary text-sm text-center mb-16">
            Confirm your backup by entering the following words:
          </p>

          <div class="mnemonic-confirm-inputs">
            <For each={testIndices()}>
              {(idx) => (
                <div class="mnemonic-confirm-field">
                  <label class="form-label">Word #{idx + 1}</label>
                  <input
                    type="text"
                    class={`mnemonic-confirm-input ${confirmError() ? "input-error" : ""}`}
                    placeholder={`Enter word #${idx + 1}`}
                    value={confirmInputs()[idx] ?? ""}
                    onInput={(e) => {
                      setConfirmError(false);
                      setConfirmInputs((prev) => ({ ...prev, [idx]: e.currentTarget.value }));
                    }}
                    autocomplete="off"
                    spellcheck={false}
                  />
                </div>
              )}
            </For>
          </div>

          <Show when={confirmError()}>
            <div class="alert alert-error text-sm mt-12 animate-fade-in">
              One or more words don't match. Please check your backup and try again.
            </div>
          </Show>

          <div class="flex gap-8 mt-16">
            <button class="btn btn-ghost" onClick={() => { setPhase("display"); setConfirmError(false); }}>
              Show words again
            </button>
            <button class="btn btn-primary" onClick={handleConfirm}>
              <IconCheck size={14} />
              <span style={{ "margin-left": "6px" }}>Verify</span>
            </button>
          </div>
        </div>
      </Show>
    </div>
  );
}
