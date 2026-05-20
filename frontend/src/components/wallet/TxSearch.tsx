/**
 * TxSearch — compact search box for filtering the transaction history.
 * Controlled component: parent owns the search string signal.
 */

interface TxSearchProps {
  value: () => string;
  onInput: (v: string) => void;
}

export default function TxSearch(props: TxSearchProps) {
  return (
    <div class="tx-search-wrapper">
      <svg
        class="tx-search-icon"
        width="14"
        height="14"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        stroke-width="2"
        stroke-linecap="round"
        stroke-linejoin="round"
        aria-hidden="true"
      >
        <circle cx="11" cy="11" r="8" />
        <line x1="21" y1="21" x2="16.65" y2="16.65" />
      </svg>
      <input
        type="search"
        class="tx-search-input"
        placeholder="Search by memo or label…"
        value={props.value()}
        onInput={(e) => props.onInput(e.currentTarget.value)}
        aria-label="Search transactions"
      />
    </div>
  );
}
