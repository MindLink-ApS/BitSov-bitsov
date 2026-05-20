/**
 * List view for the Drive — renders FileRow and FolderRow with column headers.
 */

import { createSignal, For, Show } from "solid-js";
import {
  downloadFileToDisk,
  deleteFileById,
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

function peerLabel(id: string): string {
  const peer = peers.find((p) => p.node_id === id);
  return peer?.label ?? truncateId(id);
}

// ─── File Row ────────────────────────────────────────────────────

function FileRow(props: {
  file: FileResponse;
  displayName: string;
  onContextMenu: (e: MouseEvent) => void;
  onPreview: () => void;
}) {
  const [showSend, setShowSend] = createSignal(false);
  const [downloading, setDownloading] = createSignal(false);
  const [confirmDelete, setConfirmDelete] = createSignal(false);

  const isMine = () => props.file.sender === nodeId();

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

  const handleDelete = async () => {
    await deleteFileById(props.file.id);
    setConfirmDelete(false);
  };

  return (
    <div
      class="drive-row"
      onContextMenu={(e) => { e.preventDefault(); props.onContextMenu(e); }}
    >
      <span class="drive-row-icon">
        {mimeTypeIcon(props.file.mime_type, { size: 16 })}
      </span>
      <div
        class="drive-row-name truncate"
        title={props.file.filename}
        onClick={props.onPreview}
        onKeyDown={(e: KeyboardEvent) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); props.onPreview(); } }}
        role="button"
        tabIndex={0}
        aria-label={`Preview ${props.displayName}`}
        style={{ cursor: "pointer" }}
      >
        {props.displayName}
      </div>
      <span class="drive-row-meta text-xs text-muted drive-row-owner">
        {isMine() ? "You" : peerLabel(props.file.sender)}
      </span>
      <span class="drive-row-meta text-xs text-muted drive-row-type truncate">
        {props.file.mime_type}
      </span>
      <span class="drive-row-meta text-xs text-muted drive-row-size">
        {formatFileSize(props.file.size_bytes)}
      </span>
      <div class="drive-row-actions">
        <Show
          when={!confirmDelete()}
          fallback={
            <>
              <button class="btn btn-danger btn-sm" onClick={handleDelete}>Delete</button>
              <button class="btn btn-ghost btn-sm" onClick={() => setConfirmDelete(false)}>Cancel</button>
            </>
          }
        >
          <button
            class="btn btn-ghost btn-sm btn-icon"
            onClick={handleDownload}
            disabled={downloading()}
            title="Download"
            aria-label={`Download ${props.displayName}`}
          >
            {downloading() ? <IconLoader size={13} /> : <IconDownload size={13} />}
          </button>
          <button
            class="btn btn-ghost btn-sm btn-icon"
            onClick={() => setShowSend(!showSend())}
            title="Send to peer"
            aria-label={`Send ${props.displayName} to peer`}
          >
            <IconArrowUpRight size={13} />
          </button>
          <button
            class="btn btn-ghost btn-sm btn-icon"
            onClick={() => setConfirmDelete(true)}
            title="Delete"
            aria-label={`Delete ${props.displayName}`}
          >
            <IconTrash size={13} />
          </button>
        </Show>
      </div>
      <Show when={showSend()}>
        <div style={{ "grid-column": "1 / -1", padding: "0 0 8px 32px" }}>
          <SendPanel fileId={props.file.id} onClose={() => setShowSend(false)} />
        </div>
      </Show>
    </div>
  );
}

// ─── Folder Row ───────────────────────────────────────────────────

function FolderRow(props: {
  name: string;
  onClick: () => void;
  onDelete: () => void;
}) {
  return (
    <div class="drive-row drive-row-folder" onClick={props.onClick} style={{ cursor: "pointer" }}>
      <span class="drive-row-icon" style={{ color: "var(--accent)" }}>
        <IconFolder size={16} />
      </span>
      <div class="drive-row-name font-medium">{props.name}</div>
      <span class="drive-row-meta text-xs text-muted drive-row-owner" />
      <span class="drive-row-meta text-xs text-muted drive-row-type">Folder</span>
      <span class="drive-row-meta text-xs text-muted drive-row-size">—</span>
      <div class="drive-row-actions">
        <button
          class="btn btn-ghost btn-sm btn-icon"
          onClick={(e) => { e.stopPropagation(); props.onDelete(); }}
          title="Remove folder"
          aria-label={`Remove folder ${props.name}`}
        >
          <IconTrash size={13} />
        </button>
      </div>
    </div>
  );
}

// ─── FileList container ───────────────────────────────────────────

export interface FileListItem {
  file: FileResponse;
  displayName: string;
}

export interface FolderListItem {
  name: string;
  fullPath: string;
}

export function FileList(props: {
  files: FileListItem[];
  folders: FolderListItem[];
  onFolderClick: (fullPath: string) => void;
  onFolderDelete: (name: string) => void;
  onFileContextMenu: (e: MouseEvent, file: FileResponse) => void;
  onFilePreview: (file: FileResponse, displayName: string) => void;
}) {
  return (
    <>
      <div class="drive-list-header">
        <span style={{ "grid-column": "1 / 3" }} class="text-xs text-muted">Name</span>
        <span class="text-xs text-muted drive-row-owner">Owner</span>
        <span class="text-xs text-muted drive-row-type">Type</span>
        <span class="text-xs text-muted drive-row-size">Size</span>
        <span />
      </div>
      <For each={props.folders}>
        {(item) => (
          <FolderRow
            name={item.name}
            onClick={() => props.onFolderClick(item.fullPath)}
            onDelete={() => props.onFolderDelete(item.name)}
          />
        )}
      </For>
      <For each={props.files}>
        {(item) => (
          <FileRow
            file={item.file}
            displayName={item.displayName}
            onContextMenu={(e) => props.onFileContextMenu(e, item.file)}
            onPreview={() => props.onFilePreview(item.file, item.displayName)}
          />
        )}
      </For>
    </>
  );
}
