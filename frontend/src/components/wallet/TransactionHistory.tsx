/**
 * TransactionHistory — scrollable list of Lightning payments with inline
 * label editing and text search.
 *
 * Labels are persisted to localStorage under the key `bitsov_tx_labels`
 * (a JSON object mapping payment_hash → user-supplied label string).
 * Labels are layered on top of the memo field: if a label exists it is
 * shown in the primary line; otherwise the memo (or a direction default)
 * is shown.
 */

import {
  createSignal,
  createMemo,
  onMount,
  Show,
  For,
} from "solid-js";
import { formatMsat } from "../../stores/payments";
import { formatDate } from "../../utils/formatting";
import { IconArrowDown, IconArrowUpRight } from "../Icons";
import TxSearch from "./TxSearch";

const LABELS_KEY = "bitsov_tx_labels";

/** A single payment entry as used throughout the wallet view. */
export interface Transaction {
  id: string;
  direction: "sent" | "received";
  amount_msat: number;
  memo: string | null;
  timestamp: number;
  fee_msat: number | null;
  status: string;
}

interface Props {
  transactions: () => Transaction[];
}

export default function TransactionHistory(props: Props) {
  const [search, setSearch] = createSignal("");
  const [labels, setLabels] = createSignal<Record<string, string>>({});
  /** tx.id currently being edited, or null */
  const [editing, setEditing] = createSignal<string | null>(null);
  const [editValue, setEditValue] = createSignal("");

  onMount(() => {
    try {
      const raw = localStorage.getItem(LABELS_KEY);
      if (raw) setLabels(JSON.parse(raw) as Record<string, string>);
    } catch {
      /* localStorage unavailable or corrupt — start empty */
    }
  });

  function persistLabels(next: Record<string, string>) {
    setLabels(next);
    try {
      localStorage.setItem(LABELS_KEY, JSON.stringify(next));
    } catch {
      /* ignore write failure */
    }
  }

  function startEdit(id: string) {
    setEditValue(labels()[id] ?? "");
    setEditing(id);
  }

  function commitEdit(id: string) {
    const value = editValue().trim();
    const next = { ...labels() };
    if (value) {
      next[id] = value;
    } else {
      delete next[id];
    }
    persistLabels(next);
    setEditing(null);
  }

  function cancelEdit() {
    setEditing(null);
  }

  const filtered = createMemo(() => {
    const q = search().toLowerCase().trim();
    if (!q) return props.transactions();
    return props.transactions().filter((tx) => {
      const memo = (tx.memo ?? "").toLowerCase();
      const label = (labels()[tx.id] ?? "").toLowerCase();
      return memo.includes(q) || label.includes(q);
    });
  });

  return (
    <div>
      <TxSearch value={search} onInput={setSearch} />

      <Show
        when={filtered().length > 0}
        fallback={
          <div
            class="text-sm text-muted text-center"
            style={{ padding: "16px 0" }}
          >
            {props.transactions().length === 0
              ? "No transactions yet"
              : "No transactions match your search"}
          </div>
        }
      >
        <div class="overflow-auto" style={{ "max-height": "360px" }}>
          <For each={filtered()}>
            {(tx) => {
              const label = () => labels()[tx.id];
              const isEditing = () => editing() === tx.id;
              const primaryText = () =>
                label() ?? tx.memo ?? (tx.direction === "received" ? "Received" : "Sent");

              return (
                <div class="wallet-tx-item">
                  {/* Left: icon + description */}
                  <div class="flex items-center gap-8" style={{ flex: "1", "min-width": "0" }}>
                    <span
                      style={{
                        color:
                          tx.direction === "received"
                            ? "var(--success)"
                            : "var(--accent)",
                        "flex-shrink": "0",
                      }}
                    >
                      {tx.direction === "received" ? (
                        <IconArrowDown size={14} />
                      ) : (
                        <IconArrowUpRight size={14} />
                      )}
                    </span>

                    <div style={{ "min-width": "0" }}>
                      {/* Primary memo / label line */}
                      <div class="text-sm" style={{ "overflow": "hidden", "text-overflow": "ellipsis", "white-space": "nowrap" }}>
                        {primaryText()}
                      </div>

                      {/* Secondary: date · fee · status */}
                      <div class="text-xs text-muted">
                        {formatDate(tx.timestamp)}
                        <Show when={tx.fee_msat != null && tx.fee_msat > 0}>
                          {" "}
                          &middot; Fee: {formatMsat(tx.fee_msat!)}
                        </Show>
                        <Show
                          when={
                            tx.status !== "settled" && tx.status !== "success"
                          }
                        >
                          {" "}
                          &middot;{" "}
                          <span class="text-warning">{tx.status}</span>
                        </Show>
                      </div>

                      {/* Label chip / inline editor */}
                      <Show
                        when={isEditing()}
                        fallback={
                          <Show
                            when={label()}
                            fallback={
                              <button
                                class="tx-label-chip tx-label-add"
                                onClick={() => startEdit(tx.id)}
                                title="Add a personal label to this transaction"
                              >
                                + Add label
                              </button>
                            }
                          >
                            <button
                              class="tx-label-chip tx-label-set"
                              onClick={() => startEdit(tx.id)}
                              title="Edit label"
                            >
                              {label()}
                            </button>
                          </Show>
                        }
                      >
                        <div class="tx-label-editor">
                          <input
                            type="text"
                            class="tx-label-input"
                            value={editValue()}
                            placeholder="Label…"
                            onInput={(e) => setEditValue(e.currentTarget.value)}
                            onKeyDown={(e) => {
                              if (e.key === "Enter") commitEdit(tx.id);
                              if (e.key === "Escape") cancelEdit();
                            }}
                            // eslint-disable-next-line jsx-a11y/no-autofocus
                            autofocus
                            aria-label="Transaction label"
                          />
                          <button
                            class="btn btn-ghost btn-sm"
                            onClick={() => commitEdit(tx.id)}
                          >
                            Save
                          </button>
                          <button
                            class="btn btn-ghost btn-sm"
                            onClick={cancelEdit}
                            aria-label="Cancel"
                          >
                            ✕
                          </button>
                        </div>
                      </Show>
                    </div>
                  </div>

                  {/* Right: amount */}
                  <div class="text-right" style={{ "flex-shrink": "0", "margin-left": "8px" }}>
                    <div
                      class={`text-sm font-medium${tx.direction === "received" ? " text-success" : ""}`}
                    >
                      {tx.direction === "received" ? "+" : "-"}
                      {formatMsat(tx.amount_msat)}
                    </div>
                  </div>
                </div>
              );
            }}
          </For>
        </div>
      </Show>
    </div>
  );
}
