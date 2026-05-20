/**
 * Fiat display store — BTC/USD price fetching and balance unit preference.
 *
 * Unit preference is persisted in localStorage under `bitsov_balance_unit`.
 * Fiat display can be opted out by toggling `bitsov_fiat_enabled` to "false".
 *
 * Units:
 *   "sats"  — satoshis (default)
 *   "btc"   — whole bitcoin, 8 decimal places
 *   "fiat"  — USD equivalent via a user/operator configured BTC/USD provider
 */

import { createSignal } from "solid-js";

export type BalanceUnit = "sats" | "btc" | "fiat";

const UNIT_KEY = "bitsov_balance_unit";
const FIAT_ENABLED_KEY = "bitsov_fiat_enabled";
const FIAT_PRICE_URL_KEY = "bitsov_fiat_price_url";
const MSAT_PER_BTC = 100_000_000_000;

function readUnit(): BalanceUnit {
  const v = localStorage.getItem(UNIT_KEY);
  if (v === "sats" || v === "btc" || v === "fiat") return v;
  return "sats";
}

function readFiatEnabled(): boolean {
  return localStorage.getItem(FIAT_ENABLED_KEY) !== "false";
}

function readFiatPriceUrl(): string | null {
  const fromEnv = import.meta.env.VITE_BTC_PRICE_URL;
  if (typeof fromEnv === "string" && fromEnv.trim().length > 0) return fromEnv.trim();
  const fromStorage = localStorage.getItem(FIAT_PRICE_URL_KEY);
  if (fromStorage && fromStorage.trim().length > 0) return fromStorage.trim();
  return null;
}

const [balanceUnit, setBalanceUnitRaw] = createSignal<BalanceUnit>(readUnit());
const [fiatEnabled, setFiatEnabledRaw] = createSignal<boolean>(readFiatEnabled());
const [btcPriceUsd, setBtcPriceUsd] = createSignal<number | null>(null);
const [loadingPrice, setLoadingPrice] = createSignal(false);

/** Persist and apply a new balance unit selection. */
export function setBalanceUnit(unit: BalanceUnit): void {
  setBalanceUnitRaw(unit);
  localStorage.setItem(UNIT_KEY, unit);
}

/**
 * Cycle through available units.
 * Order: sats -> btc -> fiat -> sats (fiat skipped when opted out).
 */
export function cycleBalanceUnit(): void {
  const units: BalanceUnit[] = fiatEnabled() ? ["sats", "btc", "fiat"] : ["sats", "btc"];
  const idx = units.indexOf(balanceUnit());
  setBalanceUnit(units[(idx + 1) % units.length]);
}

/**
 * Enable or disable fiat display.
 * If fiat is active and the user opts out, falls back to sats.
 */
export function setFiatEnabled(enabled: boolean): void {
  setFiatEnabledRaw(enabled);
  localStorage.setItem(FIAT_ENABLED_KEY, enabled ? "true" : "false");
  if (!enabled && balanceUnit() === "fiat") {
    setBalanceUnit("sats");
  }
}

/**
 * Fetch the current BTC/USD price from a configured provider.
 * Fire-and-forget safe — on error or missing provider, fiat display shows "—".
 */
export async function refreshFiatPrice(): Promise<void> {
  if (loadingPrice()) return;
  const priceUrl = readFiatPriceUrl();
  if (!priceUrl) return;
  setLoadingPrice(true);
  try {
    const res = await fetch(priceUrl);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = (await res.json()) as { USD?: number };
    if (typeof data.USD === "number" && data.USD > 0) {
      setBtcPriceUsd(data.USD);
    }
  } catch {
    // Price unavailable — fiat cells display "—" until next successful fetch
  } finally {
    setLoadingPrice(false);
  }
}

/** Format millisatoshis according to the given unit (defaults to active unit). */
export function formatBalanceUnit(msat: number, unit?: BalanceUnit): string {
  const u = unit ?? balanceUnit();
  switch (u) {
    case "btc": {
      const btc = msat / MSAT_PER_BTC;
      return `${btc.toFixed(8)} BTC`;
    }
    case "fiat": {
      const price = btcPriceUsd();
      if (price === null) return "—";
      const usd = (msat / MSAT_PER_BTC) * price;
      return new Intl.NumberFormat("en-US", {
        style: "currency",
        currency: "USD",
        minimumFractionDigits: 2,
        maximumFractionDigits: 2,
      }).format(usd);
    }
    default: {
      // sats
      if (msat >= 1_000) {
        return `${Math.floor(msat / 1_000).toLocaleString()} sats`;
      }
      return `${msat} msat`;
    }
  }
}

export { balanceUnit, fiatEnabled, btcPriceUsd, loadingPrice };
