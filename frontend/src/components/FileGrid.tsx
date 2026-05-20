/**
 * Grid view for the Drive — renders FileCard and FolderCard in a CSS grid.
 */

import { createSignal, For, Show, onMount } from "solid-js";
import {
  downloadFileToDisk,
  downloadFile,
  formatFileSize,
} from "../stores/files";
import { peers } from "../stores/peers";
import { nodeId } from "../stores/auth";
import { toast } from "../stores/toast";
import { truncateId } from "../utils/formatting";
import { SendPanel } from "./FileUpload";
import type { FileResponse } from "../api/types";
import {
  IconLoader,
  IconDownload,
  IconArrowUpRight,
  IconFolder,
  IconTrash,
  mimeTypeIcon,
} from "./Icons";

// ─── Image thumbnail cache ──────────────────────────────────────

const thumbCache = new Map<string, string | null>();

async function getThumbnail(fileId: string, mimeType: string): Promise<string | null> {
  if (!mimeType.startsWith("image/")) return null;
  if (thumbCache.has(fileId)) return thumbCache.get(fileId) ?? null;
  try {
    const res = await downloadFile(fileId);
    const url = `data:${res.mime_type};base64,${res.data_b64}`;
    thumbCache.set(fileId, url);
    return url;
  } catch {
    thumbCache.set(fileId, null);
    return null;
  }
}

function peerLabel(id: string): string {
  const peer = peers.find((p) => p.node_id === id);
  return peer?.label ?? truncateId(id);
}

// ─── File Card ───────────────────────────────────────────────────

function FileCard(props: {
  file: FileResponse;
  displayName: string;
  onContextMenu: (e: MouseEvent) => void;
  onPreview: () => void;
}) {
  const [thumb, setThumb] = createSignal<string | null>(null);
  const [showSend, setShowSend] = createSignal(false);
  const [downloading, setDownloading] = createSignal(false);

  onMount(async () => {
    const t = await getThumbnail(props.file.id, props.file.mime_type);
    setThumb(t);
  });

  const handleDownload = async () => {
    setDownloading(true);
    try {
      await downloadFileToDisk(props.file.id);
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Download failed");
    } finally {
      setDownloading(false);
    }
  };

  const isMine = () => props.file.sender === nodeId();

  return (
    <div
      class="drive-card"
      onContextMenu={(e) => { e.preventDefault(); props.onContextMenu(e); }}
    >
      <div
        class="drive-card-thumb"
        onClick={props.onPreview}
        onKeyDown={(e: KeyboardEvent) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); props.onPreview(); } }}
        role="button"
        tabIndex={0}
        aria-label={`Preview ${props.displayName}`}
        style={{ cursor: "pointer" }}
        title="Preview"
      >
        <Show
          when={thumb()}
          fallback={
            <div class="drive-card-thumb-icon">
              {mimeTypeIcon(props.file.mime_type, { size: 28 })}
            </div>
          }
        >
          <img
            src={thumb()!}
            alt={props.displayName}
            class="drive-card-img"
            loading="lazy"
          />
        </Show>
      </div>
      <div class="drive-card-body">
        <div class="drive-card-name truncate" title={props.displayName}>
          {props.displayName}
        </div>
        <div class="drive-card-meta text-xs text-muted">
          {formatFileSize(props.file.size_bytes)}
          <span class="drive-card-owner">{isMine() ? "You" : peerLabel(props.file.sender)}</span>
        </div>
      </div>
      <div class="drive-card-actions">
        <button
          class="btn btn-ghost btn-sm btn-icon"
          onClick={handleDownload}
          disabled={downloading()}
          title="Download"
          aria-label={`Download ${props.displayName}`}
        >
          {downloading() ? <IconLoader size={12} /> : <IconDownload size={12} />}
        </button>
        <button
          class="btn btn-ghost btn-sm btn-icon"
          onClick={() => setShowSend(!showSend())}
          title="Send to peer"
          aria-label={`Send ${props.displayName} to peer`}
        >
          <IconArrowUpRight size={12} />
        </button>
      </div>
      <Show when={showSend()}>
        <SendPanel fileId={props.file.id} onClose={() => setShowSend(false)} />
      </Show>
    </div>
  );
}

// ─── Folder Card ─────────────────────────────────────────────────

function FolderCard(props: {
  name: string;
  onClick: () => void;
  onDelete: () => void;
}) {
  return (
    <div class="drive-card drive-card-folder" onClick={props.onClick} style={{ cursor: "pointer" }}>
      <div class="drive-card-thumb drive-card-thumb-folder">
        <IconFolder size={36} style={{ color: "var(--accent)" }} />
      </div>
      <div class="drive-card-body">
        <div class="drive-card-name truncate font-medium" title={props.name}>{props.name}</div>
        <div class="drive-card-meta text-xs text-muted">Folder</div>
      </div>
      <div class="drive-card-actions">
        <button
          class="btn btn-ghost btn-sm btn-icon"
          onClick={(e) => { e.stopPropagation(); props.onDelete(); }}
          title="Remove folder"
          aria-label={`Remove folder ${props.name}`}
        >
          <IconTrash size={12} />
        </button>
      </div>
    </div>
  );
}

// ─── FileGrid container ───────────────────────────────────────────

export interface FileGridItem {
  file: FileResponse;
  displayName: string;
}

export interface FolderGridItem {
  name: string;
  fullPath: string;
}

export function FileGrid(props: {
  files: FileGridItem[];
  folders: FolderGridItem[];
  onFolderClick: (fullPath: string) => void;
  onFolderDelete: (name: string) => void;
  onFileContextMenu: (e: MouseEvent, file: FileResponse) => void;
  onFilePreview: (file: FileResponse, displayName: string) => void;
}) {
  return (
    <div class="drive-grid">
      <For each={props.folders}>
        {(item) => (
          <FolderCard
            name={item.name}
            onClick={() => props.onFolderClick(item.fullPath)}
            onDelete={() => props.onFolderDelete(item.name)}
          />
        )}
      </For>
      <For each={props.files}>
        {(item) => (
          <FileCard
            file={item.file}
            displayName={item.displayName}
            onContextMenu={(e) => props.onFileContextMenu(e, item.file)}
            onPreview={() => props.onFilePreview(item.file, item.displayName)}
          />
        )}
      </For>
    </div>
  );
}
