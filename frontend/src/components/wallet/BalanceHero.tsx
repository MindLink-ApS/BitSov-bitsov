/**
 * BalanceHero — Toggleable balance display with BTC / sats / fiat views.
 *
 * Click the balance amount (or the unit badge) to cycle between units.
 * The fiat opt-out checkbox prevents "fiat" from appearing in the cycle
 * and switches back to sats if fiat was the active unit.
 *
 * Preference is persisted in localStorage under `bitsov_balance_unit`.
 * Fiat opt-out is persisted under `bitsov_fiat_enabled`.
 */

import { Show } from "solid-js";
import {
  balanceUnit,
  fiatEnabled,
  btcPriceUsd,
  cycleBalanceUnit,
  setFiatEnabled,
  formatBalanceUnit,
} from "../../stores/fiat";
import { balance, loadingBalance, refreshBalance } from "../../stores/payments";
import { toast } from "../../stores/toast";
import { IconArrowDown, IconArrowUpRight, IconRefresh } from "../Icons";

const UNIT_LABELS: Record<string, string> = {
  sats: "sats",
  btc: "BTC",
  fiat: "USD",
};

interface BalanceHeroProps {
  onReceive: () => void;
  onSend: () => void;
}

export default function BalanceHero(props: BalanceHeroProps) {
  return (
    <div class="wallet-balance-hero card">
      <div class="text-xs text-muted wallet-balance-label">Lightning Balance</div>

      {/* Balance amount — click to cycle units */}
      <Show
        when={balance() !== null}
        fallback={
          <div class="text-muted wallet-balance-fallback">
            {loadingBalance() ? "Loading..." : "Unavailable"}
          </div>
        }
      >
        <button
          class="wallet-balance-amount"
          onClick={cycleBalanceUnit}
          title={`Showing ${UNIT_LABELS[balanceUnit()]} — click to switch`}
          aria-label={`Balance ${formatBalanceUnit(balance()!)}. Click to change unit.`}
          style={{
            cursor: "pointer",
            background: "none",
            border: "none",
            padding: "0",
            font: "inherit",
            color: "inherit",
            display: "block",
            width: "100%",
          }}
        >
          {formatBalanceUnit(balance()!)}
        </button>
      </Show>

      {/* Active unit badge + price reference when in fiat mode */}
      <div class="flex justify-center items-center gap-8 mt-6">
        <button
          class="badge"
          onClick={cycleBalanceUnit}
          title="Click to cycle unit"
          style={{
            cursor: "pointer",
            background: "none",
            border: "1px solid var(--accent)",
            color: "var(--accent)",
          }}
        >
          {UNIT_LABELS[balanceUnit()]}
        </button>
        <Show when={balanceUnit() === "fiat" && btcPriceUsd() !== null}>
          <span class="text-xs text-muted">
            @ ${btcPriceUsd()!.toLocaleString()}
          </span>
        </Show>
      </div>

      {/* Action buttons */}
      <div class="flex justify-center gap-16 mt-16">
        <button class="btn btn-primary btn-sm icon-text" onClick={props.onReceive}>
          <IconArrowDown size={14} /> Receive
        </button>
        <button class="btn btn-secondary btn-sm icon-text" onClick={props.onSend}>
          <IconArrowUpRight size={14} /> Send
        </button>
        <button
          class="btn btn-ghost btn-sm"
          onClick={() => { refreshBalance(); toast.info("Balance refreshed"); }}
          disabled={loadingBalance()}
          title="Refresh balance"
          aria-label="Refresh balance"
        >
          <IconRefresh size={14} />
        </button>
      </div>

      {/* Fiat opt-out toggle */}
      <div
        class="flex justify-center items-center gap-8 mt-12"
        style={{
          "border-top": "1px solid var(--border-subtle)",
          "padding-top": "10px",
        }}
      >
        <label
          class="text-xs text-muted"
          style={{ cursor: "pointer", display: "flex", "align-items": "center", gap: "6px" }}
        >
          <input
            type="checkbox"
            checked={fiatEnabled()}
            onChange={(e) => setFiatEnabled(e.currentTarget.checked)}
            style={{ cursor: "pointer" }}
          />
          Show USD equivalent
        </label>
      </div>
    </div>
  );
}
