/**
 * Drive view — full file manager with folder navigation, grid/list toggle,
 * inline image previews, context menus, storage usage, and drag-and-drop upload.
 *
 * Folders are virtual/local: a folder is a path prefix stored in localStorage.
 * The backend has a flat file list; files in a folder have filenames prefixed
 * with the folder path (e.g. "Photos/sunset.jpg").
 */

import {
  createSignal,
  createMemo,
  For,
  Show,
  onMount,
  onCleanup,
  batch,
} from "solid-js";
import { createStore } from "solid-js/store";
import {
  files,
  loadingFiles,
  filesError,
  refreshFiles,
  uploadFile,
  downloadFileToDisk,
  downloadFile,
  sendFile,
  deleteFileById,
  formatFileSize,
} from "../stores/files";
import { peers, refreshPeers } from "../stores/peers";
import { formatMsat } from "../stores/payments";
import { nodeId } from "../stores/auth";
import { toast } from "../stores/toast";
import { truncateId } from "../utils/formatting";
import { loadJSON, saveJSON, loadString, saveString } from "../utils/storage";
import type { FileResponse } from "../api/types";
import {
  IconUpload,
  IconLoader,
  IconDownload,
  IconArrowUpRight,
  IconX,
  IconFolder,
  IconFolderPlus,
  IconGrid,
  IconList,
  IconPlus,
  IconTrash,
  IconChevronRight,
  IconPencil,
  IconMoreVertical,
  IconHardDrive,
  IconRefresh,
  IconPreview,
  mimeTypeIcon,
} from "./Icons";

const MAX_FILE_SIZE = 4 * 1024 * 1024;
const LS_FOLDERS_KEY = "drive_folders_v1";
const LS_VIEW_KEY = "drive_view_v1";

// ─── Folder helpers ─────────────────────────────────────────────

function loadFolders(): string[] {
  return loadJSON<string[]>(LS_FOLDERS_KEY, []);
}

function saveFolders(folders: string[]): void {
  saveJSON(LS_FOLDERS_KEY, folders);
}

function loadViewMode(): "grid" | "list" {
  const v = loadString(LS_VIEW_KEY);
  if (v === "grid" || v === "list") return v;
  return "list";
}

/** Given a current path (e.g. "Photos/Trips") and a file path prefix,
 *  return the filename relative to the current path if it belongs here.
 *  Returns null if the file is in a sub-folder or elsewhere. */
function fileInPath(filename: string, currentPath: string): string | null {
  const prefix = currentPath ? `${currentPath}/` : "";
  if (!filename.startsWith(prefix)) return null;
  const rest = filename.slice(prefix.length);
  // If rest contains a slash it's in a sub-folder — not directly in this level.
  if (rest.includes("/")) return null;
  return rest;
}

/** Get sub-folder names visible at the current path level. */
function subfoldersAt(allFolders: string[], currentPath: string): string[] {
  const prefix = currentPath ? `${currentPath}/` : "";
  const seen = new Set<string>();
  for (const f of allFolders) {
    if (!f.startsWith(prefix)) continue;
    const rest = f.slice(prefix.length);
    const segment = rest.split("/")[0];
    if (segment) seen.add(segment);
  }
  return Array.from(seen).sort();
}

function peerLabel(id: string): string {
  const peer = peers.find((p) => p.node_id === id);
  return peer?.label ?? truncateId(id);
}

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

// ─── Context Menu ───────────────────────────────────────────────

interface CtxMenuState {
  visible: boolean;
  x: number;
  y: number;
  fileId: string | null;
  filename: string;
  mimeType: string;
}

// ─── Send Panel ─────────────────────────────────────────────────

function SendPanel(props: {
  fileId: string;
  onClose: () => void;
}) {
  const [sending, setSending] = createSignal(false);
  const [target, setTarget] = createSignal("");
  const [result, setResult] = createSignal<string | null>(null);
  const [error, setError] = createSignal<string | null>(null);

  const connectedPeers = () => peers.filter((p) => p.connected && p.node_id !== nodeId());

  const handleSend = async () => {
    const t = target().trim();
    if (!t || sending()) return;
    setSending(true);
    setError(null);
    setResult(null);
    try {
      const res = await sendFile(props.fileId, t);
      const status = res.delivered ? "Delivered" : "Queued";
      setResult(`${status} (${formatMsat(res.amount_msat)})`);
      toast.success(`File ${status.toLowerCase()} to peer`);
      setTarget("");
      setTimeout(() => { setResult(null); props.onClose(); }, 2500);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Send failed";
      setError(msg);
      toast.error(msg);
    } finally {
      setSending(false);
    }
  };

  return (
    <div class="drive-send-panel animate-fade-in">
      <div class="drive-send-row">
        <Show
          when={connectedPeers().length > 0}
          fallback={
            <input
              type="text"
              placeholder="Recipient node ID (hex)"
              class="mono"
              style={{ flex: 1, "font-size": "12px" }}
              value={target()}
              onInput={(e) => setTarget(e.currentTarget.value)}
            />
          }
        >
          <label for="drive-send-peer-select" class="sr-only">Select recipient peer</label>
          <select
            id="drive-send-peer-select"
            style={{ flex: 1, "font-size": "12px" }}
            value={target()}
            onChange={(e) => setTarget(e.currentTarget.value)}
          >
            <option value="">Select peer...</option>
            <For each={connectedPeers()}>
              {(peer) => (
                <option value={peer.node_id}>
                  {peer.label ?? truncateId(peer.node_id)}
                </option>
              )}
            </For>
          </select>
        </Show>
        <button
          class="btn btn-primary btn-sm"
          onClick={handleSend}
          disabled={!target().trim() || sending()}
        >
          {sending() ? <IconLoader size={12} /> : "Send"}
        </button>
        <button class="btn btn-ghost btn-sm btn-icon" onClick={props.onClose} title="Cancel" aria-label="Cancel send">
          <IconX size={12} />
        </button>
      </div>
      <Show when={result()}>
        <p class="text-xs text-accent mt-4">{result()}</p>
      </Show>
      <Show when={error()}>
        <p class="text-xs text-error mt-4">{error()}</p>
      </Show>
    </div>
  );
}

// ─── File Card (grid mode) ──────────────────────────────────────

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
      <div class="drive-card-thumb" onClick={props.onPreview} onKeyDown={(e: KeyboardEvent) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); props.onPreview(); } }} role="button" tabIndex={0} aria-label={`Preview ${props.displayName}`} style={{ cursor: "pointer" }} title="Preview">
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

// ─── File Row (list mode) ───────────────────────────────────────

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

// ─── Folder Row (list mode) ─────────────────────────────────────

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

// ─── Folder Card (grid mode) ────────────────────────────────────

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

// ─── Upload Area ─────────────────────────────────────────────────

function UploadArea(props: { currentPath: string }) {
  const [dragging, setDragging] = createSignal(false);
  const [uploading, setUploading] = createSignal(false);
  const [uploadFileName, setUploadFileName] = createSignal("");
  const [uploadFileSize, setUploadFileSize] = createSignal(0);
  let inputRef: HTMLInputElement | undefined;

  const handleFiles = async (fileList: FileList | null) => {
    if (!fileList || fileList.length === 0) return;
    const file = fileList[0];

    if (file.size > MAX_FILE_SIZE) {
      toast.error(`File too large: ${formatFileSize(file.size)} (max 4 MB)`);
      return;
    }
    if (file.size === 0) {
      toast.error("File is empty");
      return;
    }

    setUploading(true);
    setUploadFileName(file.name);
    setUploadFileSize(file.size);
    // Prefix the filename with the current folder path
    const prefixedFile = props.currentPath
      ? new File([file], `${props.currentPath}/${file.name}`, { type: file.type })
      : file;

    try {
      await uploadFile(prefixedFile);
      toast.success(`Uploaded: ${file.name}`);
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Upload failed");
    } finally {
      setUploading(false);
      setUploadFileName("");
      setUploadFileSize(0);
      if (inputRef) inputRef.value = "";
    }
  };

  return (
    <div
      class={`upload-zone drive-upload-zone ${dragging() ? "dragging" : ""}`}
      onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
      onDragLeave={() => setDragging(false)}
      onDrop={(e) => { e.preventDefault(); setDragging(false); handleFiles(e.dataTransfer?.files ?? null); }}
      onClick={() => !uploading() && inputRef?.click()}
      style={{ cursor: uploading() ? "wait" : "pointer" }}
    >
      <input
        ref={inputRef}
        type="file"
        style={{ display: "none" }}
        onChange={(e) => handleFiles(e.currentTarget.files)}
      />
      <Show when={uploading()} fallback={
        <>
          <div style={{ display: "flex", "justify-content": "center", "margin-bottom": "8px", opacity: "0.6" }}>
            <IconUpload size={24} />
          </div>
          <div class="text-sm text-secondary">
            {props.currentPath
              ? `Drop a file here to upload into "${props.currentPath.split("/").pop()}"`
              : "Drop a file here or click to upload"
            }
          </div>
          <div class="text-xs text-muted" style={{ "margin-top": "4px" }}>Max 4 MB per file</div>
        </>
      }>
        <div style={{ display: "flex", "justify-content": "center", "margin-bottom": "8px", opacity: "0.6" }}>
          <IconLoader size={24} />
        </div>
        <div class="text-sm text-secondary">
          Uploading {uploadFileName()}
        </div>
        <div class="text-xs text-muted" style={{ "margin-top": "2px" }}>
          {formatFileSize(uploadFileSize())}
        </div>
        <div class="progress-bar" style={{ "margin-top": "8px" }}>
          <div class="progress-bar-fill progress-bar-indeterminate" />
        </div>
      </Show>
    </div>
  );
}

// ─── Context Menu Component ─────────────────────────────────────

function ContextMenu(props: {
  state: CtxMenuState;
  onClose: () => void;
  onPreview: () => void;
  onRename: () => void;
  onDelete: () => void;
  onSend: () => void;
  onDownload: () => void;
}) {
  let menuRef: HTMLDivElement | undefined;

  const handleOutsideClick = (e: MouseEvent) => {
    if (menuRef && !menuRef.contains(e.target as Node)) {
      props.onClose();
    }
  };

  onMount(() => document.addEventListener("mousedown", handleOutsideClick));
  onCleanup(() => document.removeEventListener("mousedown", handleOutsideClick));

  return (
    <div
      ref={menuRef}
      class="drive-ctx-menu animate-fade-in-scale"
      style={{ top: `${props.state.y}px`, left: `${props.state.x}px` }}
    >
      <button class="drive-ctx-item" onClick={() => { props.onPreview(); props.onClose(); }}>
        <IconPreview size={13} /> Preview
      </button>
      <button class="drive-ctx-item" onClick={() => { props.onDownload(); props.onClose(); }}>
        <IconDownload size={13} /> Download
      </button>
      <button class="drive-ctx-item" onClick={() => { props.onSend(); props.onClose(); }}>
        <IconArrowUpRight size={13} /> Send to peer
      </button>
      <button class="drive-ctx-item" onClick={() => { props.onRename(); props.onClose(); }}>
        <IconPencil size={13} /> Rename
      </button>
      <div class="drive-ctx-divider" />
      <button class="drive-ctx-item drive-ctx-item-danger" onClick={() => { props.onDelete(); props.onClose(); }}>
        <IconTrash size={13} /> Delete
      </button>
    </div>
  );
}

// ─── Storage Bar ─────────────────────────────────────────────────

function StorageBar() {
  const MAX_STORAGE = 4 * 1024 * 1024 * 100; // 400 MB soft display ceiling

  const totalBytes = createMemo(() =>
    files.reduce((sum, f) => sum + f.size_bytes, 0)
  );

  const pct = createMemo(() =>
    Math.min(100, (totalBytes() / MAX_STORAGE) * 100)
  );

  return (
    <div class="drive-storage">
      <div class="drive-storage-label">
        <span class="text-xs text-muted" style={{ display: "flex", "align-items": "center", gap: "5px" }}>
          <IconHardDrive size={12} />
          Storage
        </span>
        <span class="text-xs text-muted">
          {formatFileSize(totalBytes())} used
        </span>
      </div>
      <div class="drive-storage-bar">
        <div
          class="drive-storage-fill"
          style={{ width: `${pct()}%` }}
        />
      </div>
    </div>
  );
}

// ─── File Preview Modal ──────────────────────────────────────────

interface PreviewState {
  fileId: string;
  filename: string;
  mimeType: string;
}

function FilePreviewModal(props: {
  state: PreviewState;
  onClose: () => void;
}) {
  const [dataUrl, setDataUrl] = createSignal<string | null>(null);
  const [textContent, setTextContent] = createSignal<string | null>(null);
  const [loading, setLoading] = createSignal(true);
  const [error, setError] = createSignal<string | null>(null);

  const isImage = () => props.state.mimeType.startsWith("image/");
  const isText = () =>
    props.state.mimeType.startsWith("text/") ||
    props.state.mimeType === "application/json" ||
    props.state.mimeType === "application/xml" ||
    props.state.filename.endsWith(".md") ||
    props.state.filename.endsWith(".json") ||
    props.state.filename.endsWith(".xml") ||
    props.state.filename.endsWith(".csv");
  const isPdf = () => props.state.mimeType === "application/pdf";

  onMount(async () => {
    try {
      const res = await downloadFile(props.state.fileId);
      if (isImage() || isPdf()) {
        setDataUrl(`data:${res.mime_type};base64,${res.data_b64}`);
      } else if (isText()) {
        const binary = atob(res.data_b64);
        setTextContent(binary);
      }
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to load file");
    } finally {
      setLoading(false);
    }
  });

  const handleKeyDown = (e: KeyboardEvent) => {
    if (e.key === "Escape") props.onClose();
  };

  onMount(() => document.addEventListener("keydown", handleKeyDown));
  onCleanup(() => document.removeEventListener("keydown", handleKeyDown));

  return (
    <div class="drive-modal-overlay" onClick={props.onClose}>
      <div
        class="drive-preview-modal animate-fade-in-scale"
        onClick={(e) => e.stopPropagation()}
      >
        <div class="drive-preview-header">
          <div class="drive-preview-title truncate" title={props.state.filename}>
            <IconPreview size={14} />
            {props.state.filename}
          </div>
          <div style={{ display: "flex", gap: "6px", "align-items": "center" }}>
            <span class="text-xs text-muted">{props.state.mimeType}</span>
            <button
              class="btn btn-ghost btn-sm btn-icon"
              onClick={props.onClose}
              title="Close"
              aria-label="Close preview"
            >
              <IconX size={14} />
            </button>
          </div>
        </div>

        <div class="drive-preview-body">
          <Show when={loading()}>
            <div class="drive-preview-loading">
              <IconLoader size={24} />
              <span class="text-sm text-muted">Loading preview...</span>
            </div>
          </Show>

          <Show when={error()}>
            <div class="drive-preview-error">
              <span class="text-sm text-error">{error()}</span>
            </div>
          </Show>

          <Show when={!loading() && !error() && isImage() && dataUrl()}>
            <img
              src={dataUrl()!}
              alt={props.state.filename}
              class="drive-preview-image"
            />
          </Show>

          <Show when={!loading() && !error() && isPdf() && dataUrl()}>
            <object
              data={dataUrl()!}
              type="application/pdf"
              class="drive-preview-pdf"
              aria-label={`PDF preview: ${props.state.filename}`}
            >
              <p class="text-sm text-muted" style={{ padding: "24px" }}>
                PDF preview not available in this browser. Download the file to view.
              </p>
            </object>
          </Show>

          <Show when={!loading() && !error() && isText() && textContent() !== null}>
            <pre class="drive-preview-text">{textContent()}</pre>
          </Show>

          <Show when={!loading() && !error() && !isImage() && !isText() && !isPdf()}>
            <div class="drive-preview-unsupported">
              {mimeTypeIcon(props.state.mimeType, { size: 36 })}
              <p class="text-sm text-muted">
                Preview not available for this file type.
              </p>
              <p class="text-xs text-muted">Download the file to view it.</p>
            </div>
          </Show>
        </div>
      </div>
    </div>
  );
}

// ─── Main Drive Component ────────────────────────────────────────

export default function Drive() {
  const [currentPath, setCurrentPath] = createSignal("");
  const [folders, setFolders] = createSignal<string[]>(loadFolders());
  const [viewMode, setViewMode] = createSignal<"grid" | "list">(loadViewMode());
  const [newFolderName, setNewFolderName] = createSignal("");
  const [showNewFolder, setShowNewFolder] = createSignal(false);
  const [renameTarget, setRenameTarget] = createSignal<{ id: string; name: string } | null>(null);
  const [renameTo, setRenameTo] = createSignal("");
  const [ctxMenu, setCtxMenu] = createSignal<CtxMenuState>({
    visible: false, x: 0, y: 0, fileId: null, filename: "", mimeType: "",
  });
  const [sendTarget, setSendTarget] = createSignal<string | null>(null);
  const [previewTarget, setPreviewTarget] = createSignal<PreviewState | null>(null);

  onMount(() => {
    refreshFiles();
    refreshPeers();
  });

  // Persist view mode
  const toggleView = () => {
    const next = viewMode() === "grid" ? "list" : "grid";
    setViewMode(next);
    saveString(LS_VIEW_KEY, next);
  };

  // Breadcrumbs from currentPath
  const breadcrumbs = createMemo(() => {
    const path = currentPath();
    if (!path) return [];
    return path.split("/");
  });

  const navigateTo = (path: string) => {
    setCurrentPath(path);
    setCtxMenu((s) => ({ ...s, visible: false }));
  };

  // Files visible in the current directory level
  const visibleFiles = createMemo(() => {
    return files.filter((f) => fileInPath(f.filename, currentPath()) !== null);
  });

  // Sub-folders visible at this level
  const visibleFolders = createMemo(() => {
    return subfoldersAt(folders(), currentPath());
  });

  const createFolder = () => {
    const name = newFolderName().trim();
    if (!name || name.includes("/")) {
      toast.error("Invalid folder name");
      return;
    }
    const fullPath = currentPath() ? `${currentPath()}/${name}` : name;
    if (folders().includes(fullPath)) {
      toast.error("Folder already exists");
      return;
    }
    const updated = [...folders(), fullPath];
    setFolders(updated);
    saveFolders(updated);
    setNewFolderName("");
    setShowNewFolder(false);
    toast.success(`Folder "${name}" created`);
  };

  const deleteFolder = (name: string) => {
    const fullPath = currentPath() ? `${currentPath()}/${name}` : name;
    // Remove folder and all sub-folders
    const updated = folders().filter((f) => f !== fullPath && !f.startsWith(`${fullPath}/`));
    setFolders(updated);
    saveFolders(updated);
    toast.success(`Folder "${name}" removed`);
  };

  const openCtxMenu = (e: MouseEvent, file: FileResponse) => {
    const displayName = fileInPath(file.filename, currentPath()) ?? file.filename;
    setCtxMenu({
      visible: true,
      x: e.clientX,
      y: e.clientY,
      fileId: file.id,
      filename: displayName,
      mimeType: file.mime_type,
    });
  };

  const handleCtxDelete = async () => {
    const id = ctxMenu().fileId;
    if (!id) return;
    await deleteFileById(id);
    toast.success("File deleted");
  };

  const handleCtxDownload = async () => {
    const id = ctxMenu().fileId;
    if (!id) return;
    try {
      await downloadFileToDisk(id);
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Download failed");
    }
  };

  const handleCtxSend = () => {
    const id = ctxMenu().fileId;
    if (id) setSendTarget(id);
  };

  const handleCtxPreview = () => {
    const ctx = ctxMenu();
    if (!ctx.fileId) return;
    setPreviewTarget({
      fileId: ctx.fileId,
      filename: ctx.filename,
      mimeType: ctx.mimeType,
    });
  };

  const handleCtxRename = () => {
    const ctx = ctxMenu();
    if (!ctx.fileId) return;
    setRenameTarget({ id: ctx.fileId, name: ctx.filename });
    setRenameTo(ctx.filename);
  };

  const handleRenameSubmit = async () => {
    const target = renameTarget();
    if (!target) return;
    const newName = renameTo().trim();
    if (!newName || newName === target.name) {
      setRenameTarget(null);
      return;
    }
    // Find the file and re-upload with new name
    const file = files.find((f) => f.id === target.id);
    if (!file) { setRenameTarget(null); return; }

    const newFullName = currentPath() ? `${currentPath()}/${newName}` : newName;
    try {
      const dlRes = await downloadFile(target.id);
      const binary = atob(dlRes.data_b64);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
      const blob = new Blob([bytes], { type: dlRes.mime_type });
      const newFile = new File([blob], newFullName, { type: dlRes.mime_type });
      await uploadFile(newFile);
      await deleteFileById(target.id);
      toast.success(`Renamed to "${newName}"`);
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Rename failed");
    } finally {
      setRenameTarget(null);
    }
  };

  return (
    <div class="drive-layout">
      {/* Header */}
      <div class="drive-header">
        <div class="drive-breadcrumb">
          <button
            class={`drive-breadcrumb-seg ${!currentPath() ? "active" : ""}`}
            onClick={() => navigateTo("")}
          >
            Drive
          </button>
          <For each={breadcrumbs()}>
            {(seg, i) => (
              <>
                <span class="drive-breadcrumb-sep">
                  <IconChevronRight size={12} />
                </span>
                <button
                  class={`drive-breadcrumb-seg ${i() === breadcrumbs().length - 1 ? "active" : ""}`}
                  onClick={() => {
                    const path = breadcrumbs().slice(0, i() + 1).join("/");
                    navigateTo(path);
                  }}
                >
                  {seg}
                </button>
              </>
            )}
          </For>
        </div>
        <div class="drive-header-actions">
          <span class="text-xs text-muted" style={{ "align-self": "center" }}>
            {visibleFiles().length} file{visibleFiles().length !== 1 ? "s" : ""}
          </span>
          <button
            class="btn btn-ghost btn-sm btn-icon"
            onClick={() => setShowNewFolder(!showNewFolder())}
            title="New folder"
            aria-label="Create new folder"
          >
            <IconFolderPlus size={15} />
          </button>
          <button
            class="btn btn-ghost btn-sm btn-icon"
            onClick={toggleView}
            title={viewMode() === "grid" ? "Switch to list" : "Switch to grid"}
            aria-label={viewMode() === "grid" ? "Switch to list view" : "Switch to grid view"}
          >
            {viewMode() === "grid" ? <IconList size={15} /> : <IconGrid size={15} />}
          </button>
          <button
            class="btn btn-secondary btn-sm"
            onClick={refreshFiles}
            disabled={loadingFiles()}
            style={{ display: "flex", "align-items": "center", gap: "5px" }}
          >
            {loadingFiles() ? <IconLoader size={13} /> : <IconRefresh size={13} />}
            Refresh
          </button>
        </div>
      </div>

      {/* New folder input */}
      <Show when={showNewFolder()}>
        <div class="drive-new-folder animate-fade-in">
          <IconFolder size={14} style={{ color: "var(--accent)" }} />
          <input
            type="text"
            placeholder="Folder name"
            value={newFolderName()}
            onInput={(e) => setNewFolderName(e.currentTarget.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") createFolder();
              if (e.key === "Escape") setShowNewFolder(false);
            }}
            style={{ flex: 1, "font-size": "13px" }}
            autofocus
          />
          <button class="btn btn-primary btn-sm" onClick={createFolder}>
            Create
          </button>
          <button class="btn btn-ghost btn-sm btn-icon" onClick={() => setShowNewFolder(false)} aria-label="Cancel new folder">
            <IconX size={13} />
          </button>
        </div>
      </Show>

      {/* Rename modal */}
      <Show when={renameTarget()}>
        <div class="drive-modal-overlay" onClick={() => setRenameTarget(null)}>
          <div class="drive-modal animate-fade-in-scale" onClick={(e) => e.stopPropagation()}>
            <div class="drive-modal-title">Rename file</div>
            <input
              type="text"
              value={renameTo()}
              onInput={(e) => setRenameTo(e.currentTarget.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") handleRenameSubmit();
                if (e.key === "Escape") setRenameTarget(null);
              }}
              style={{ width: "100%", "margin-bottom": "12px" }}
              autofocus
            />
            <div style={{ display: "flex", gap: "8px", "justify-content": "flex-end" }}>
              <button class="btn btn-ghost btn-sm" onClick={() => setRenameTarget(null)}>Cancel</button>
              <button class="btn btn-primary btn-sm" onClick={handleRenameSubmit}>Rename</button>
            </div>
          </div>
        </div>
      </Show>

      {/* Inline send panel from context menu */}
      <Show when={sendTarget()}>
        <div class="drive-inline-send animate-fade-in">
          <span class="text-sm text-secondary">Send to peer:</span>
          <SendPanel fileId={sendTarget()!} onClose={() => setSendTarget(null)} />
        </div>
      </Show>

      {/* Upload zone */}
      <div style={{ padding: "12px 16px", "border-bottom": "1px solid var(--glass-border)" }}>
        <UploadArea currentPath={currentPath()} />
      </div>

      {/* Error banner */}
      <Show when={filesError()}>
        <div class="alert alert-error flex items-center gap-8" style={{ margin: "10px 16px" }}>
          <span class="flex-1">{filesError()}</span>
          <button class="btn btn-secondary btn-sm" onClick={refreshFiles}>Retry</button>
        </div>
      </Show>

      {/* File browser */}
      <div class="drive-browser">
        <Show
          when={visibleFolders().length > 0 || visibleFiles().length > 0}
          fallback={
            <div class="empty-state">
              <div class="empty-state-icon"><IconFolder size={36} /></div>
              <div class="empty-state-title">
                {currentPath() ? "This folder is empty" : "No files in Drive yet"}
              </div>
              <div class="empty-state-desc">
                {currentPath()
                  ? "Upload a file above to store it here."
                  : "Upload a file above to store it on your node, then send it to a peer with end-to-end encryption."
                }
              </div>
            </div>
          }
        >
          {/* List view */}
          <Show when={viewMode() === "list"}>
            {/* Column headers */}
            <div class="drive-list-header">
              <span style={{ "grid-column": "1 / 3" }} class="text-xs text-muted">Name</span>
              <span class="text-xs text-muted drive-row-owner">Owner</span>
              <span class="text-xs text-muted drive-row-type">Type</span>
              <span class="text-xs text-muted drive-row-size">Size</span>
              <span />
            </div>
            <For each={visibleFolders()}>
              {(name) => (
                <FolderRow
                  name={name}
                  onClick={() => navigateTo(currentPath() ? `${currentPath()}/${name}` : name)}
                  onDelete={() => deleteFolder(name)}
                />
              )}
            </For>
            <For each={visibleFiles()}>
              {(file) => (
                <FileRow
                  file={file}
                  displayName={fileInPath(file.filename, currentPath()) ?? file.filename}
                  onContextMenu={(e) => openCtxMenu(e, file)}
                  onPreview={() => setPreviewTarget({
                    fileId: file.id,
                    filename: fileInPath(file.filename, currentPath()) ?? file.filename,
                    mimeType: file.mime_type,
                  })}
                />
              )}
            </For>
          </Show>

          {/* Grid view */}
          <Show when={viewMode() === "grid"}>
            <div class="drive-grid">
              <For each={visibleFolders()}>
                {(name) => (
                  <FolderCard
                    name={name}
                    onClick={() => navigateTo(currentPath() ? `${currentPath()}/${name}` : name)}
                    onDelete={() => deleteFolder(name)}
                  />
                )}
              </For>
              <For each={visibleFiles()}>
                {(file) => (
                  <FileCard
                    file={file}
                    displayName={fileInPath(file.filename, currentPath()) ?? file.filename}
                    onContextMenu={(e) => openCtxMenu(e, file)}
                    onPreview={() => setPreviewTarget({
                      fileId: file.id,
                      filename: fileInPath(file.filename, currentPath()) ?? file.filename,
                      mimeType: file.mime_type,
                    })}
                  />
                )}
              </For>
            </div>
          </Show>
        </Show>
      </div>

      {/* Storage indicator */}
      <Show when={files.length > 0}>
        <div style={{ "border-top": "1px solid var(--glass-border)", padding: "10px 16px" }}>
          <StorageBar />
        </div>
      </Show>

      {/* File preview modal */}
      <Show when={previewTarget()}>
        {(state) => (
          <FilePreviewModal
            state={state()}
            onClose={() => setPreviewTarget(null)}
          />
        )}
      </Show>

      {/* Context menu */}
      <Show when={ctxMenu().visible}>
        <ContextMenu
          state={ctxMenu()}
          onClose={() => setCtxMenu((s) => ({ ...s, visible: false }))}
          onPreview={handleCtxPreview}
          onDelete={handleCtxDelete}
          onDownload={handleCtxDownload}
          onSend={handleCtxSend}
          onRename={handleCtxRename}
        />
      </Show>
    </div>
  );
}
