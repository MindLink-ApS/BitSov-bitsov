/**
 * Onboarding View — invite paste + accept flow.
 *
 * RENDERED OUTSIDE THE ROUTER (App.tsx Show fallback). Must NOT use
 * useNavigate() — it throws "Make sure your app is wrapped in a
 * <Router />" when called without Router context. Use the onboarding
 * state helpers, which update history without a browser reload.
 *
 * STATE MACHINE ORDERING (sovereignty-critical, see state/onboarding.ts):
 *   paste-invite   — user pastes; submit triggers LOCAL decode only
 *   confirm-invite — user sees inviter pubkey; clicks Confirm to commit
 *                    (confirmInvite() is what actually calls /accept)
 *   funding        — full-tier nodes wait for backend-observed wallet funding
 *   connecting     — accept committed, polling for peer to come online
 *   first-message  — peer connected, ready to send first message
 */

import { Show, Switch, Match, onMount } from "solid-js";
import * as state from "../state/onboarding";
import FundingCeremony from "../components/FundingCeremony";
import FirstMessageWizard from "../components/FirstMessageWizard";
import {
  IconGlobe,
  IconCheck,
  IconLoader,
  IconShield,
  IconLightning,
} from "../components/Icons";

function BackHomeButton(props: { disabled?: boolean }) {
  return (
    <button
      class="btn btn-ghost mt-2"
      onClick={state.exitToHome}
      disabled={props.disabled}
    >
      Back to Home
    </button>
  );
}

function ConnectingStep() {
  return (
    <div class="onboarding-step animate-fade-in">
      <div class="onboarding-icon-large">
        <IconLoader size={48} class="animate-spin text-primary" />
      </div>
      <h1 class="onboarding-title">Connecting to Mesh...</h1>
      <p class="onboarding-desc">
        Establishing a sovereign connection. This may take a few seconds
        as we perform the X3DH handshake.
      </p>

      <div class="connection-status-list mt-6">
        <div class="status-item done">
          <IconCheck size={16} class="text-success" />
          <span>Invite verified</span>
        </div>
        <div class="status-item done">
          <IconCheck size={16} class="text-success" />
          <span>Inviter whitelisted</span>
        </div>
        <div class="status-item">
          <IconLoader size={16} class="animate-spin" />
          <span>{state.progressText()}</span>
        </div>
      </div>

      <div class="onboarding-nav mt-6">
        <BackHomeButton />
      </div>
    </div>
  );
}

export default function OnboardingView() {
  // Reset state on mount to avoid cross-mount signal leak. Module-level
  // signals persist across remounts of this view; explicit reset clears
  // any stale inviterPubkey / token from a previous half-completed flow.
  onMount(() => {
    if (!state.inFlow()) {
      state.reset();
    }
  });

  return (
    <div class="onboarding-container">
      <div class="onboarding-bg" />

      <div class="onboarding-card glass animate-fade-in-scale">
        <Switch>
          {/* Step 1: Paste Invite */}
          <Match when={state.step() === "paste-invite"}>
            <div class="onboarding-step animate-fade-in">
              <div class="onboarding-icon-large">
                <IconGlobe size={48} />
              </div>
              <h1 class="onboarding-title">Welcome to BitSov</h1>
              <p class="onboarding-desc">
                BitSov is a sovereign mesh network. To join, you need an invite
                from an existing peer.
              </p>

              <div class="invite-input-group">
                <label for="invite-token" class="form-label">
                  Paste your invite token or link
                </label>
                <textarea
                  id="invite-token"
                  class="form-control mono"
                  placeholder="bitsov://invite/..."
                  rows={4}
                  value={state.inviteToken()}
                  onInput={(e) => state.setInviteToken(e.currentTarget.value)}
                />
                <Show when={state.error()}>
                  <div class="error-text mt-2">{state.error()}</div>
                </Show>
              </div>

              <div class="onboarding-nav mt-6">
                <button
                  class="btn btn-primary btn-lg w-full"
                  onClick={() => state.submitInvite(state.inviteToken())}
                  disabled={!state.inviteToken().trim() || state.isProcessing()}
                >
                  Continue
                </button>
                <BackHomeButton disabled={state.isProcessing()} />
              </div>
            </div>
          </Match>

          {/* Step 2: Confirm Invite — trust decision commits ON this screen */}
          <Match when={state.step() === "confirm-invite"}>
            <div class="onboarding-step animate-fade-in">
              <div class="onboarding-icon-large">
                <IconShield size={48} />
              </div>
              <h1 class="onboarding-title">Confirm Connection</h1>
              <p class="onboarding-desc">
                You are about to whitelist the following peer. Verify the
                inviter node ID below matches what your inviter shared with
                you out-of-band.
              </p>

              <div class="confirm-card glass-subtle p-4 rounded-lg mt-4">
                <div class="flex flex-col gap-2">
                  <span class="text-xs text-muted uppercase tracking-wider">
                    Inviter Node ID
                  </span>
                  <span class="mono break-all text-sm">
                    {state.inviterPubkey()}
                  </span>
                </div>
                <Show when={state.channelSizeHint() > 0}>
                  <div class="flex flex-col gap-2 mt-4">
                    <span class="text-xs text-muted uppercase tracking-wider">
                      Suggested Channel Size
                    </span>
                    <div class="flex items-center gap-2">
                      <IconLightning size={16} class="text-warning" />
                      <span>{state.channelSizeHint().toLocaleString()} sats</span>
                    </div>
                  </div>
                </Show>
              </div>

              <Show when={state.error()}>
                <div class="error-text mt-4">{state.error()}</div>
              </Show>

              <div class="onboarding-nav mt-6">
                <button
                  class="btn btn-primary btn-lg w-full"
                  onClick={state.confirmInvite}
                  disabled={state.isProcessing()}
                >
                  <Show
                    when={state.isProcessing()}
                    fallback={"Confirm & Connect"}
                  >
                    <IconLoader class="animate-spin mr-2" /> Processing...
                  </Show>
                </button>
                <button
                  class="btn btn-ghost mt-2"
                  onClick={() => state.goToStep("paste-invite")}
                  disabled={state.isProcessing()}
                >
                  Back
                </button>
                <BackHomeButton disabled={state.isProcessing()} />
              </div>
            </div>
          </Match>

          {/* Step 3: Connecting (after /accept committed) */}
          <Match when={state.step() === "connecting"}>
            <ConnectingStep />
          </Match>

          {/* Step 4: Full-tier Funding Ceremony */}
          <Match when={state.step() === "funding"}>
            <FundingCeremony />
          </Match>

          {/* Step 5: First Message / Ready */}
          <Match when={state.step() === "first-message"}>
            <FirstMessageWizard />
          </Match>
        </Switch>
      </div>
    </div>
  );
}
