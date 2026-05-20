/** Onboarding wizard — shown to first-time users after login.
 *
 * 6 steps: Tier Selection, Welcome, Identity, Mnemonic Backup, Connect, Ready.
 * Stores completion flag in localStorage so it only shows once.
 */

import { createSignal, Show, For, onMount } from "solid-js";
import { identity, nodeId } from "../stores/auth";
import { api } from "../stores/auth";
import { tier } from "../stores/tier";
import TierSelection from "./TierSelection";
import MnemonicWizard from "./MnemonicWizard";
import {
  IconGlobe,
  IconKey,
  IconLightning,
  IconLock,
  IconShield,
  IconUser,
  IconLightbulb,
  IconRocket,
  IconMessages,
  IconDrive,
  IconGroups,
} from "./Icons";
import type { JSX } from "solid-js";
import { truncateId } from "../utils/formatting";
import { loadString, saveString } from "../utils/storage";

const ONBOARDING_KEY = "konsensus-onboarded";

/** Check if the user has completed onboarding. */
export function hasCompletedOnboarding(): boolean {
  return loadString(ONBOARDING_KEY) === "true";
}

/** Mark onboarding as complete. */
function completeOnboarding() {
  saveString(ONBOARDING_KEY, "true");
}

const FEATURES: { icon: (p?: { size?: number }) => JSX.Element; title: string; desc: string }[] = [
  { icon: IconMessages, title: "Message", desc: "E2E encrypted chat with payment-gated delivery" },
  { icon: IconDrive, title: "Drive", desc: "Send documents and media, encrypted end-to-end" },
  { icon: IconLightning, title: "Lightning Payments", desc: "Bitcoin-native economics power every interaction" },
  { icon: IconGroups, title: "Groups", desc: "Group conversations with Sender Keys encryption" },
];

interface Props {
  onComplete: () => void;
}

export default function Onboarding(props: Props) {
  const [step, setStep] = createSignal(0);
  const [copied, setCopied] = createSignal(false);
  const [mnemonicConfirmed, setMnemonicConfirmed] = createSignal(false);
  const [mnemonic, setMnemonic] = createSignal<string | undefined>(undefined);
  const totalSteps = 6;

  // Fetch the mnemonic from the node for Light/Full tier backup display
  onMount(async () => {
    if (tier() === "cloud") return;
    try {
      const res = await api.mnemonic();
      setMnemonic(res.mnemonic);
    } catch {
      // Mnemonic unavailable (encrypted or not found) — wizard shows placeholder
    }
  });

  const next = () => {
    if (step() < totalSteps - 1) {
      setStep(step() + 1);
    } else {
      completeOnboarding();
      props.onComplete();
    }
  };

  const back = () => {
    if (step() > 0) setStep(step() - 1);
  };

  const skip = () => {
    completeOnboarding();
    props.onComplete();
  };

  const copyNodeId = () => {
    const id = nodeId();
    if (!id) return;
    navigator.clipboard.writeText(id).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }).catch(() => {
      /* Clipboard unavailable */
    });
  };

  /** Can the user advance from the current step? */
  const canAdvance = () => {
    return true;
  };

  return (
    <div class="onboarding-container">
      <div class="onboarding-bg" />

      <div class={`onboarding-card glass animate-fade-in-scale ${step() === 0 ? "onboarding-card-wide" : ""}`}>
        {/* Progress dots */}
        <div class="onboarding-progress">
          <For each={Array.from({ length: totalSteps })}>
            {(_, i) => (
              <div
                class={`onboarding-dot ${i() === step() ? "active" : ""} ${i() < step() ? "done" : ""}`}
              />
            )}
          </For>
        </div>

        {/* Step content */}
        <div class="onboarding-content animate-fade-in" style={{ "--step": step() }}>
          {/* Step 0: Tier Selection */}
          <Show when={step() === 0}>
            <div class="onboarding-step">
              <h1 class="onboarding-title">Choose Your Sovereignty Level</h1>
              <p class="onboarding-desc">
                How much control do you want? You can change this later in Settings.
              </p>
              <TierSelection />
            </div>
          </Show>

          {/* Step 1: Welcome */}
          <Show when={step() === 1}>
            <div class="onboarding-step">
              <div class="onboarding-icon-large"><IconGlobe size={48} /></div>
              <h1 class="onboarding-title">Welcome to BitSov</h1>
              <p class="onboarding-desc">
                You are now a sovereign node in a decentralized mesh network.
                Your identity is anchored to Bitcoin, your messages are end-to-end
                encrypted, and every interaction is payment-gated.
              </p>
              <div class="onboarding-principles">
                <div class="onboarding-principle">
                  <span class="onboarding-principle-icon"><IconKey size={18} /></span>
                  <span>Your keys, your identity</span>
                </div>
                <div class="onboarding-principle">
                  <span class="onboarding-principle-icon"><IconLightning size={18} /></span>
                  <span>Lightning-powered communication</span>
                </div>
                <div class="onboarding-principle">
                  <span class="onboarding-principle-icon"><IconLock size={18} /></span>
                  <span>Zero plaintext, anywhere</span>
                </div>
                <div class="onboarding-principle">
                  <span class="onboarding-principle-icon"><IconShield size={18} /></span>
                  <span>Whitelist-only federation</span>
                </div>
              </div>
            </div>
          </Show>

          {/* Step 2: Node Identity */}
          <Show when={step() === 2}>
            <div class="onboarding-step">
              <div class="onboarding-icon-large"><IconUser size={48} /></div>
              <h1 class="onboarding-title">Your Node Identity</h1>
              <p class="onboarding-desc">
                This is your unique identity on the mesh. Share it with peers
                who want to connect with you. It's derived from your Bitcoin keys.
              </p>

              {/* Node Identity Card */}
              <div class="node-id-card">
                <div class="node-id-avatar">
                  {(nodeId() || "??").slice(0, 2).toUpperCase()}
                </div>
                <div class="node-id-details">
                  <div class="node-id-label">Node ID</div>
                  <div class="node-id-value mono">
                    {truncateId(nodeId() || "")}
                  </div>
                </div>
                <button
                  class="btn btn-secondary btn-sm"
                  onClick={copyNodeId}
                  aria-label="Copy Node ID to clipboard"
                >
                  {copied() ? "Copied!" : "Copy"}
                </button>
              </div>

              <Show when={identity()}>
                <div class="node-id-meta">
                  <div class="node-id-meta-item">
                    <span class="text-muted text-xs">Ed25519 signing key</span>
                  </div>
                  <div class="node-id-meta-item">
                    <span class="text-muted text-xs">X25519 transport encryption</span>
                  </div>
                  <div class="node-id-meta-item">
                    <span class="text-muted text-xs">secp256k1 Bitcoin compatibility</span>
                  </div>
                </div>
              </Show>
            </div>
          </Show>

          {/* Step 3: Mnemonic Backup */}
          <Show when={step() === 3}>
            <div class="onboarding-step">
              <div class="onboarding-icon-large"><IconShield size={48} /></div>
              <h1 class="onboarding-title">Your Identity is Secured</h1>
              <p class="onboarding-desc">
                Your 24-word recovery phrase was generated when your node was initialized.
                It is stored in your node's data directory.
              </p>

              <div class="onboarding-tip">
                If you haven't backed up your recovery phrase yet, find your
                <strong> mnemonic.txt</strong> file in your node directory and write
                down the 24 words on paper. This is the only way to recover your
                identity if your device is lost.
              </div>

              <div class="onboarding-principles" style={{ "margin-top": "16px" }}>
                <div class="onboarding-principle">
                  <span class="onboarding-principle-icon"><IconKey size={18} /></span>
                  <span>Your phrase was shown during <code>bitsov init</code></span>
                </div>
                <div class="onboarding-principle">
                  <span class="onboarding-principle-icon"><IconLock size={18} /></span>
                  <span>Never share it. Never store it digitally.</span>
                </div>
                <div class="onboarding-principle">
                  <span class="onboarding-principle-icon"><IconShield size={18} /></span>
                  <span>Same phrase recovers your identity on any device</span>
                </div>
              </div>
            </div>
          </Show>

          {/* Step 4: Connect to Mesh */}
          <Show when={step() === 4}>
            <div class="onboarding-step">
              <div class="onboarding-icon-large"><IconGlobe size={48} /></div>
              <h1 class="onboarding-title">Connect to the Mesh</h1>
              <p class="onboarding-desc">
                BitSov uses a whitelist model — you explicitly choose who to
                connect with. No open federation, no unsolicited contacts.
              </p>

              <div class="onboarding-steps-list">
                <div class="onboarding-step-item">
                  <div class="onboarding-step-num">1</div>
                  <div>
                    <div class="onboarding-step-title">Share an invite link</div>
                    <div class="onboarding-step-desc">
                      Go to <strong>Profile</strong> to generate a signed invite link or QR code.
                      Share it with the person you want to connect with.
                    </div>
                  </div>
                </div>
                <div class="onboarding-step-item">
                  <div class="onboarding-step-num">2</div>
                  <div>
                    <div class="onboarding-step-title">Redeem their invite</div>
                    <div class="onboarding-step-desc">
                      In <strong>Peers</strong>, click "Redeem Invite" and paste
                      the code they shared with you. This auto-whitelists and connects.
                    </div>
                  </div>
                </div>
                <div class="onboarding-step-item">
                  <div class="onboarding-step-num">3</div>
                  <div>
                    <div class="onboarding-step-title">Encrypted automatically</div>
                    <div class="onboarding-step-desc">An E2EE session establishes via X3DH — no manual setup needed</div>
                  </div>
                </div>
              </div>

              <div class="onboarding-tip">
                <span class="onboarding-tip-icon"><IconLock size={18} /></span>
                <span>Both sides must whitelist each other. You can also add peers manually with their Node ID.</span>
              </div>
            </div>
          </Show>

          {/* Step 5: Ready */}
          <Show when={step() === 5}>
            <div class="onboarding-step">
              <div class="onboarding-icon-large"><IconRocket size={48} /></div>
              <h1 class="onboarding-title">You're Ready</h1>
              <p class="onboarding-desc">
                Your sovereign node is live. Here's what you can do:
              </p>

              <div class="onboarding-features">
                <For each={FEATURES}>
                  {(f) => (
                    <div class="onboarding-feature">
                      <div class="onboarding-feature-icon">{f.icon({ size: 24 })}</div>
                      <div>
                        <div class="onboarding-feature-title">{f.title}</div>
                        <div class="onboarding-feature-desc">{f.desc}</div>
                      </div>
                    </div>
                  )}
                </For>
              </div>
            </div>
          </Show>
        </div>

        {/* Navigation */}
        <div class="onboarding-nav">
          <Show when={step() > 0} fallback={
            <button class="btn btn-ghost btn-sm" onClick={skip} aria-label="Skip onboarding">Skip</button>
          }>
            <button class="btn btn-ghost btn-sm" onClick={back} aria-label="Go to previous step">Back</button>
          </Show>

          {/* Continue button — always shown (mnemonic step uses Option A: "identity secured") */}
          <Show when={true}>
            <button
              class="btn btn-primary"
              onClick={next}
              disabled={!canAdvance()}
            >
              {step() === totalSteps - 1 ? "Enter BitSov" : "Continue"}
            </button>
          </Show>
        </div>
      </div>
    </div>
  );
}
