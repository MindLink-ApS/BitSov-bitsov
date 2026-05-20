/**
 * Wallet — Full Lightning wallet view.
 * Prominent balance, send/receive payments, transaction history,
 * message pricing table, and QR code generation.
 */

import { createSignal, Show, For, onMount, onCleanup, createMemo } from "solid-js";
import qrcode from "qrcode-generator";
import {
  refreshBalance,
  createInvoice,
  payInvoice,
  formatMsat,
  getPrice,
  balance,
} from "../stores/payments";
import { refreshFiatPrice } from "../stores/fiat";
import { api } from "../stores/auth";
import { toast } from "../stores/toast";
import { MessageKind, type HealthResponse, type ChannelResponse, type PaymentListEntry } from "../api/types";
import {
  IconLightning,
  IconArrowDown,
  IconArrowUpRight,
  IconCopy,
  IconClock,
  IconActivity,
  IconNetwork,
} from "./Icons";
import TransactionHistory, { type Transaction } from "./wallet/TransactionHistory";
import WalletDetails from "./WalletDetails";

/** Generate an SVG QR code for a BOLT11 invoice string. */
function generateQrSvg(data: string): string {
  const qr = qrcode(0, "M");
  qr.addData(data.toUpperCase(), "Alphanumeric");
  qr.make();
  return qr.createSvgTag({ cellSize: 4, margin: 2, scalable: true });
}

interface PriceEntry {
  label: string;
  kind: number;
  price: number | null;
}

export default function Wallet() {
  const [tab, setTab] = createSignal<"overview" | "send" | "receive">("overview");
  const [isDetailsOpen, setIsDetailsOpen] = createSignal(false);
  const [prices, setPrices] = createSignal<PriceEntry[]>([]);
  const [health, setHealth] = createSignal<HealthResponse | null>(null);
  const [channels, setChannels] = createSignal<ChannelResponse[]>([]);
  const [txHistory, setTxHistory] = createSignal<Transaction[]>([]);

  // Receive state
  const [invoiceBolt11, setInvoiceBolt11] = createSignal<string | null>(null);
  const [invoiceAmount, setInvoiceAmount] = createSignal("1000");
  const [invoiceDesc, setInvoiceDesc] = createSignal("");
  const [creatingInvoice, setCreatingInvoice] = createSignal(false);

  // Send state
  const [payBolt11, setPayBolt11] = createSignal("");
  const [paying, setPaying] = createSignal(false);
  const [payResult, setPayResult] = createSignal<{ hash: string; amount: number } | null>(null);

  async function refreshChannels() {
    try {
      const ch = await api.listChannels();
      setChannels(ch);
    } catch (e) { console.warn("Channel listing failed:", e); }
  }

  onMount(async () => {
    refreshBalance().catch((e: unknown) => {
      console.warn("Failed to refresh balance on mount:", e instanceof Error ? e.message : e);
    });
    void refreshFiatPrice();
    // Load prices
    const kinds = [
      { label: "Chat", kind: MessageKind.CHAT },
      { label: "Long-form", kind: MessageKind.LONGFORM },
      { label: "File", kind: MessageKind.FILE_REF },
      { label: "Calendar", kind: MessageKind.CALENDAR_EVENT },
      { label: "Collaboration", kind: MessageKind.CRDT_OP },
      { label: "Control", kind: MessageKind.TYPING },
    ];
    const entries: PriceEntry[] = [];
    for (const k of kinds) {
      try {
        const p = await getPrice(k.kind);
        entries.push({ label: k.label, kind: k.kind, price: p });
      } catch {
        entries.push({ label: k.label, kind: k.kind, price: null });
      }
    }
    setPrices(entries);

    // Load health for Lightning info
    try {
      const h = await api.health();
      setHealth(h);
    } catch (e) { console.warn("Health fetch failed:", e); }

    await refreshChannels();

    // Load real Lightning payment history
    try {
      const payments = await api.listPayments(50);
      setTxHistory(payments.map((p: PaymentListEntry) => ({
        id: p.payment_hash,
        direction: p.direction === "outgoing" ? "sent" as const : "received" as const,
        amount_msat: p.amount_msat,
        memo: p.memo,
        timestamp: p.timestamp,
        fee_msat: p.fee_msat,
        status: p.status,
      })));
    } catch (e) { console.warn("Payment history fetch failed:", e); }
  });

  // Auto-refresh balance and transactions every 30 seconds
  const refreshTimer = setInterval(async () => {
    refreshBalance();
    try {
      const payments = await api.listPayments(50);
      setTxHistory(payments.map((p: PaymentListEntry) => ({
        id: p.payment_hash,
        direction: p.direction === "outgoing" ? "sent" as const : "received" as const,
        amount_msat: p.amount_msat,
        memo: p.memo,
        timestamp: p.timestamp,
        fee_msat: p.fee_msat,
        status: p.status,
      })));
    } catch (e) { console.warn("Payment history refresh failed:", e); }
  }, 30_000);

  onCleanup(() => clearInterval(refreshTimer));

  // Use real Lightning payment history
  const transactions = () => txHistory();

  const totalSent = createMemo(() =>
    transactions().filter(t => t.direction === "sent").reduce((sum, t) => sum + t.amount_msat, 0)
  );
  const totalReceived = createMemo(() =>
    transactions().filter(t => t.direction === "received").reduce((sum, t) => sum + t.amount_msat, 0)
  );

  const handleCreateInvoice = async (e: Event) => {
    e.preventDefault();
    const amount = parseInt(invoiceAmount(), 10);
    if (isNaN(amount) || amount <= 0) return;
    setCreatingInvoice(true);
    try {
      const inv = await createInvoice(amount, invoiceDesc() || undefined);
      setInvoiceBolt11(inv.bolt11);
      toast.success("Invoice created");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to create invoice");
      setInvoiceBolt11(null);
    } finally {
      setCreatingInvoice(false);
    }
  };

  const handlePayInvoice = async (e: Event) => {
    e.preventDefault();
    const bolt11 = payBolt11().trim();
    if (!bolt11) return;
    setPaying(true);
    setPayResult(null);
    try {
      const result = await payInvoice(bolt11);
      setPayResult({ hash: result.payment_hash, amount: result.amount_msat });
      setPayBolt11("");
      toast.success(`Paid ${formatMsat(result.amount_msat)}`);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Payment failed");
    } finally {
      setPaying(false);
    }
  };

  return (
    <div class="page content-max">
      <div class="page-header">
        <h2 class="page-title">Wallet</h2>
      </div>

      {/* Mock Lightning warning */}
      <Show when={health()?.lightning_backend === "mock" || health()?.lightning_backend === "void"}>
        <div class="card mb-16" style={{
          "background": "var(--warning-dim)",
          "border": "1px solid var(--warning)",
          padding: "12px 16px",
          "border-radius": "var(--radius-sm)",
        }}>
          <div class="text-sm font-medium" style={{ color: "var(--warning)" }}>
            Simulated Lightning — not real Bitcoin
          </div>
          <div class="text-xs text-muted mt-4">
            This node is using a {health()?.lightning_backend} wallet. Balances and payments are simulated.
          </div>
        </div>
      </Show>

      {/* Overview — prominence on spendable balance */}
      <Show when={tab() === "overview"}>
        <div class="flex-col items-center justify-center gap-4 mb-48 animate-fade-in" style={{ padding: "60px 0", display: "flex", "text-align": "center" }}>
          <div
            class="font-bold mb-4"
            style={{
              "font-size": "64px",
              "line-height": "1",
              color: "var(--btc-400, #F7931A)",
              "text-shadow": "0 0 30px rgba(247, 147, 26, 0.25)"
            }}
          >
            {Math.floor((balance() || 0) / 1000).toLocaleString()}
          </div>
          <div class="text-secondary font-medium tracking-wide" style={{ "font-size": "18px" }}>sats</div>

          <div class="flex gap-16 mt-32">
            <button class="btn btn-primary btn-lg icon-text" onClick={() => setTab("receive")}>
              <IconArrowDown size={18} /> Receive
            </button>
            <button class="btn btn-secondary btn-lg icon-text" onClick={() => setTab("send")}>
              <IconArrowUpRight size={18} /> Send
            </button>
            <button class="btn btn-ghost btn-lg" onClick={() => setIsDetailsOpen(true)}>
              Details
            </button>
          </div>
        </div>

        {/* Transaction History — reverse chronological */}
        <div class="card mb-16">
          <div class="card-header icon-text">
            <IconClock size={14} /> Transaction History
          </div>
          <TransactionHistory transactions={transactions} />
        </div>
      </Show>

      {/* Send panel */}
      <Show when={tab() === "send"}>
        <div class="card animate-fade-in mb-16">
          <div class="card-header flex items-center justify-between">
            <span class="icon-text">
              <IconArrowUpRight size={16} /> Send Payment
            </span>
            <button class="btn btn-ghost btn-sm" onClick={() => setTab("overview")}>Close</button>
          </div>
          <form onSubmit={handlePayInvoice} class="flex-col gap-8">
            <textarea
              value={payBolt11()}
              onInput={(e) => setPayBolt11(e.currentTarget.value)}
              placeholder="Paste BOLT11 invoice (lnbc...)"
              rows={3}
              class="resize-vertical"
              style={{ "font-family": "var(--font-mono)", "font-size": "12px" }}
            />
            <div class="flex items-center gap-8">
              <button
                type="submit"
                class="btn btn-primary btn-sm"
                disabled={paying() || !payBolt11().trim()}
              >
                {paying() ? "Paying..." : "Pay Invoice"}
              </button>
              <Show when={payBolt11().trim().startsWith("lnbc")}>
                <span class="text-xs text-muted">Lightning invoice detected</span>
              </Show>
            </div>
          </form>
          <Show when={payResult()}>
            <div class="animate-fade-in pay-result-panel">
              <div class="text-xs text-accent mb-4">
                Payment Sent — {formatMsat(payResult()!.amount)}
              </div>
              <div class="mono text-xs break-all" style={{ color: "var(--text-muted)" }}>
                {payResult()!.hash}
              </div>
            </div>
          </Show>
        </div>
      </Show>

      {/* Receive panel */}
      <Show when={tab() === "receive"}>
        <div class="card animate-fade-in mb-16">
          <div class="card-header flex items-center justify-between">
            <span class="icon-text">
              <IconArrowDown size={16} /> Receive Payment
            </span>
            <button class="btn btn-ghost btn-sm" onClick={() => { setTab("overview"); setInvoiceBolt11(null); }}>Close</button>
          </div>
          <form onSubmit={handleCreateInvoice} class="flex gap-8 mb-12">
            <input
              type="number"
              value={invoiceAmount()}
              onInput={(e) => setInvoiceAmount(e.currentTarget.value)}
              placeholder="Amount (msat)"
              style={{ width: "140px" }}
            />
            <input
              type="text"
              value={invoiceDesc()}
              onInput={(e) => setInvoiceDesc(e.currentTarget.value)}
              placeholder="Description (optional)"
              class="flex-1"
            />
            <button type="submit" class="btn btn-primary btn-sm" disabled={creatingInvoice()}>
              {creatingInvoice() ? "Creating..." : "Create Invoice"}
            </button>
          </form>
          <Show when={invoiceBolt11()}>
            <div class="animate-fade-in invoice-panel">
              <div class="text-xs text-muted mb-8">BOLT11 Invoice</div>
              {/* QR Code */}
              <div class="flex justify-center mb-12">
                <div
                  class="qr-wrapper"
                  role="img"
                  aria-label="QR code for Lightning invoice"
                  innerHTML={generateQrSvg(invoiceBolt11()!)}
                />
              </div>
              {/* Invoice text + copy */}
              <div class="flex items-start gap-8">
                <div class="mono text-xs flex-1 break-all select-all">
                  {invoiceBolt11()}
                </div>
                <button
                  class="btn btn-secondary btn-sm flex-shrink-0"
                  onClick={() => {
                    navigator.clipboard.writeText(invoiceBolt11()!).then(() => {
                      toast.success("Invoice copied");
                    }).catch(() => {
                      /* Clipboard unavailable */
                    });
                  }}
                  title="Copy invoice"
                  aria-label="Copy invoice"
                >
                  <IconCopy size={14} />
                </button>
              </div>
            </div>
          </Show>
        </div>
      </Show>

      <WalletDetails
        isOpen={isDetailsOpen()}
        onClose={() => setIsDetailsOpen(false)}
        health={health()}
        channels={channels}
        prices={prices()}
        totalReceived={totalReceived()}
        totalSent={totalSent()}
        transactionCount={transactions().length}
        refreshChannels={refreshChannels}
      />
    </div>
  );
}
