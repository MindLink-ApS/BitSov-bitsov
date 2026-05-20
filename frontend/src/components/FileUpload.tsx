/**
 * File upload zone and send-to-peer panel.
 */

import { createSignal, For, Show } from "solid-js";
import { uploadFile, sendFile, formatFileSize } from "../stores/files";
import { peers } from "../stores/peers";
import { formatMsat } from "../stores/payments";
import { nodeId } from "../stores/auth";
import { toast } from "../stores/toast";
import { truncateId } from "../utils/formatting";
import {
  IconUpload,
  IconLoader,
  IconArrowUpRight,
  IconX,
} from "./Icons";

export const MAX_FILE_SIZE = 4 * 1024 * 1024;

// ─── Send Panel ─────────────────────────────────────────────────

export function SendPanel(props: {
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

// ─── Upload Area ─────────────────────────────────────────────────

export function UploadArea(props: { currentPath: string }) {
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
