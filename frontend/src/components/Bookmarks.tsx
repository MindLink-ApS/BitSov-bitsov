/** Bookmarks — saved pages from the sovereign browser. */

import { createSignal, Show, For } from "solid-js";
import { useNavigate } from "@solidjs/router";
import {
  IconBookmark,
  IconDocument,
  IconTrash,
  IconLightning,
  IconGlobe,
} from "./Icons";
import { loadJSON, saveJSON } from "../utils/storage";

interface Bookmark {
  peerId: string;
  peerLabel: string;
  path: string;
  title: string;
  addedAt: number;
}

/** Load bookmarks from localStorage. */
function loadBookmarks(): Bookmark[] {
  return loadJSON<Bookmark[]>("konsensus_bookmarks", []);
}

/** Save bookmarks to localStorage. */
function saveBookmarks(bookmarks: Bookmark[]) {
  saveJSON("konsensus_bookmarks", bookmarks);
}

export default function BookmarksView() {
  const [bookmarks, setBookmarks] = createSignal<Bookmark[]>(loadBookmarks());
  const navigate = useNavigate();

  function removeBookmark(index: number) {
    const updated = bookmarks().filter((_, i) => i !== index);
    setBookmarks(updated);
    saveBookmarks(updated);
  }

  function openBookmark(bm: Bookmark) {
    // Navigate to browser view — the BrowserView will pick up the peer/path
    // from URL params or we store them for inter-component communication
    saveJSON("konsensus_browse_target", { peerId: bm.peerId, path: bm.path });
    navigate("/browser");
  }

  function truncId(id: string) {
    return id.length > 16 ? `${id.slice(0, 8)}...${id.slice(-4)}` : id;
  }

  function formatTime(ts: number): string {
    const d = new Date(ts);
    const now = new Date();
    const diff = now.getTime() - d.getTime();
    if (diff < 60_000) return "just now";
    if (diff < 3600_000) return `${Math.floor(diff / 60_000)}m ago`;
    if (diff < 86400_000) return `${Math.floor(diff / 3600_000)}h ago`;
    return d.toLocaleDateString(undefined, {
      month: "short",
      day: "numeric",
      year: "numeric",
    });
  }

  return (
    <div class="page" style={{ "max-width": "var(--content-max)" }}>
      <div class="page-header">
        <h2 class="page-title flex items-center gap-8">
          <IconBookmark size={20} /> Bookmarks
        </h2>
        <span class="text-xs text-muted">
          {bookmarks().length} saved
        </span>
      </div>

      <Show
        when={bookmarks().length > 0}
        fallback={
          <div class="card bookmarks-empty">
            <IconGlobe size={48} />
            <h3>No Bookmarks Yet</h3>
            <p>
              Browse pages on peer nodes and bookmark them for quick access.
              Bookmarks are stored locally on your device.
            </p>
          </div>
        }
      >
        <div class="bookmarks-list">
          <For each={bookmarks()}>
            {(bm, i) => (
              <div class="card bookmarks-item">
                <button
                  class="bookmarks-item-link"
                  onClick={() => openBookmark(bm)}
                  aria-label={`Open bookmark: ${bm.title}`}
                >
                  <IconDocument size={16} />
                  <div class="bookmarks-item-info">
                    <span class="bookmarks-item-title">{bm.title}</span>
                    <span class="text-xs text-muted">
                      {bm.peerLabel || truncId(bm.peerId)} {bm.path}
                    </span>
                    <span class="text-xs text-muted">
                      Saved {formatTime(bm.addedAt)}
                    </span>
                  </div>
                </button>
                <button
                  class="btn btn-ghost btn-sm"
                  onClick={() => removeBookmark(i())}
                  title="Remove bookmark"
                  aria-label={`Remove bookmark ${bm.title}`}
                >
                  <IconTrash size={14} />
                </button>
              </div>
            )}
          </For>
        </div>
      </Show>
    </div>
  );
}
