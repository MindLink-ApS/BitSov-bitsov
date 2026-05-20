/** FundWalletBanner — shown when Lightning balance is too low for messaging.
 *
 * Appears as a prominent banner when:
 * - Balance is less than 10x the chat message price (can't send ~10 messages)
 * - Lightning is unavailable
 *
 * Links to the Wallet receive tab for funding.
 */

import { Show, createSignal, createEffect, on } from "solid-js";
import { A } from "@solidjs/router";
import { balance, loadingBalance } from "../stores/payments";
import { IconLightning, IconWarning } from "./Icons";

/** Minimum balance threshold in msat — alert if below 10x chat price (250 msat = ~10 messages at 25 msat). */
const LOW_BALANCE_THRESHOLD_MSAT = 250;

export default function FundWalletBanner() {
  const [dismissed, setDismissed] = createSignal(false);

  // Reset dismissal when balance changes significantly
  createEffect(on(balance, (bal, prev) => {
    if (prev !== null && bal !== null && bal > LOW_BALANCE_THRESHOLD_MSAT) {
      setDismissed(false);
    }
  }));

  const isLowBalance = () => {
    const bal = balance();
    if (bal === null || loadingBalance()) return false;
    return bal < LOW_BALANCE_THRESHOLD_MSAT;
  };

  const isZeroBalance = () => {
    const bal = balance();
    return bal !== null && bal === 0;
  };

  return (
    <Show when={isLowBalance() && !dismissed()}>
      <div class="fund-wallet-banner" role="alert">
        <div class="fund-wallet-banner-content">
          <span class="fund-wallet-banner-icon">
            <Show when={isZeroBalance()} fallback={<IconWarning size={16} />}>
              <IconLightning size={16} />
            </Show>
          </span>
          <div class="fund-wallet-banner-text">
            <Show when={isZeroBalance()} fallback={
              <span>Low Lightning balance — you may not be able to send messages. <A href="/wallet" class="fund-wallet-link">Fund your wallet</A></span>
            }>
              <span>No Lightning balance. Fund your wallet to start sending payment-gated messages. <A href="/wallet" class="fund-wallet-link">Receive sats</A></span>
            </Show>
          </div>
          <button
            class="fund-wallet-dismiss"
            onClick={() => setDismissed(true)}
            title="Dismiss"
          >
            &times;
          </button>
        </div>
      </div>
    </Show>
  );
}
