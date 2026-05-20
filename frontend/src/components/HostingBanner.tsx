/** HostingBanner — shown when a cloud-tier node falls behind on operator hosting. */

import { createSignal, onCleanup, Show } from "solid-js";
import { A } from "@solidjs/router";
import { ws } from "../stores/auth";
import type { WsHostingEvent } from "../api/types";
import { IconLightning, IconWarning } from "./Icons";

export default function HostingBanner() {
  const [event, setEvent] = createSignal<WsHostingEvent | null>(null);
  const [dismissed, setDismissed] = createSignal(false);

  const unsubscribe = ws.onHosting((next) => {
    setEvent(next);
    setDismissed(false);
  });
  onCleanup(unsubscribe);

  const isPaused = () => event()?.status === "paused";

  return (
    <Show when={event() && !dismissed()}>
      <div class="fund-wallet-banner hosting-banner" role="alert">
        <div class="fund-wallet-banner-content">
          <span class="fund-wallet-banner-icon">
            <Show when={isPaused()} fallback={<IconWarning size={16} />}>
              <IconLightning size={16} />
            </Show>
          </span>
          <div class="fund-wallet-banner-text">
            <span>
              {isPaused()
                ? "Cloud hosting is paused. "
                : "Cloud hosting payment is overdue. "}
              <A href="/wallet" class="fund-wallet-link">Fund your node</A>
              <Show when={event()?.reason}>
                <span> — {event()!.reason}</span>
              </Show>
            </span>
          </div>
          <button
            class="fund-wallet-dismiss"
            onClick={() => setDismissed(true)}
            title="Dismiss"
            aria-label="Dismiss hosting notice"
          >
            &times;
          </button>
        </div>
      </div>
    </Show>
  );
}
