/**
 * Payments store — Lightning wallet balance, invoices, price queries.
 */

import { createSignal } from "solid-js";
import type { InvoiceResponse, PayInvoiceResponse, PriceResponse } from "../api/types";
import { api } from "./auth";

const [balance, setBalance] = createSignal<number | null>(null);
const [loadingBalance, setLoadingBalance] = createSignal(false);
const [priceCache, setPriceCache] = createSignal<Record<number, number>>({});

/** Refresh the Lightning wallet balance. */
export async function refreshBalance(): Promise<void> {
  setLoadingBalance(true);
  try {
    const res = await api.balance();
    setBalance(res.balance_msat);
  } catch {
    // Balance refresh failed — show null (UI handles gracefully)
    setBalance(null);
  } finally {
    setLoadingBalance(false);
  }
}

/** Get the price for a message kind (cached). */
export async function getPrice(kind: number): Promise<number> {
  const cached = priceCache()[kind];
  if (cached !== undefined) return cached;

  const res = await api.price(kind);
  setPriceCache((prev) => ({ ...prev, [kind]: res.price_msat }));
  return res.price_msat;
}

/** Create a Lightning invoice for receiving payment. */
export async function createInvoice(
  amountMsat: number,
  description?: string,
): Promise<InvoiceResponse> {
  return api.createInvoice({
    amount_msat: amountMsat,
    description,
  });
}

/** Check a payment's status. */
export async function checkPayment(hash: string) {
  return api.paymentStatus(hash);
}

/** Pay a BOLT11 invoice. */
export async function payInvoice(bolt11: string): Promise<PayInvoiceResponse> {
  const result = await api.payInvoice({ bolt11 });
  // Refresh balance after payment (fire-and-forget is intentional — balance display is non-critical)
  void refreshBalance();
  return result;
}

/** Format millisatoshis for display — always shows sats, never BTC. */
export function formatMsat(msat: number): string {
  if (msat >= 1_000) {
    const sats = Math.floor(msat / 1_000);
    return `${sats.toLocaleString()} sats`;
  }
  return `${msat} msat`;
}

export { balance, loadingBalance, priceCache };
