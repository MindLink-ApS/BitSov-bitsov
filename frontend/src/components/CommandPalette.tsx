import { createSignal, createEffect, Show } from "solid-js";
import { IconSearch } from "./Icons";

interface CommandPaletteProps {
  isOpen: boolean;
  setIsOpen: (open: boolean) => void;
}

/**
 * CommandPalette — Cmd+K center modal shell.
 * Ships the UI structure and search input. Result list is empty for now.
 * Closing via Escape or click-outside.
 */
export default function CommandPalette(props: CommandPaletteProps) {
  const [query, setQuery] = createSignal("");
  let inputRef: HTMLInputElement | undefined;

  // Focus input when palette opens
  createEffect(() => {
    if (props.isOpen && inputRef) {
      // Small timeout to ensure the modal is rendered before focusing
      setTimeout(() => inputRef?.focus(), 10);
    } else {
      setQuery("");
    }
  });

  return (
    <Show when={props.isOpen}>
      <div 
        class="cmd-palette-backdrop" 
        onClick={() => props.setIsOpen(false)}
      >
        <div 
          class="cmd-palette" 
          onClick={(e) => e.stopPropagation()}
        >
          <div class="cmd-palette-search">
            <IconSearch size={18} />
            <input
              ref={inputRef}
              type="text"
              class="cmd-palette-input"
              placeholder="Search commands (empty for now)..."
              value={query()}
              onInput={(e) => setQuery(e.currentTarget.value)}
              aria-label="Command palette search"
            />
            <kbd class="cmd-palette-kbd">ESC</kbd>
          </div>

          <div class="cmd-palette-results">
            {/* List area: empty for now per task FE5 */}
            <div class="cmd-palette-empty">
              No results found
            </div>
          </div>

          <div class="cmd-palette-footer">
            <span class="text-caption" style={{ color: "var(--text-muted)", "font-size": "11px" }}>
              <kbd>↑</kbd> <kbd>↓</kbd> to navigate
              <span style={{ "margin-left": "12px" }}><kbd>Enter</kbd> to select</span>
            </span>
          </div>
        </div>
      </div>
    </Show>
  );
}
