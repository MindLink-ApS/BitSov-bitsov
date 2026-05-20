/**
 * Files store — manages file uploads, listing, downloads, and sending.
 *
 * Files flow through the node's E2EE pipeline: the frontend uploads raw
 * file data (base64-encoded), the node encrypts and transmits via
 * KIND_FILE_REF envelopes. Received files are decrypted and stored.
 */

import { createSignal } from "solid-js";
import { createStore, produce } from "solid-js/store";
import type {
  FileResponse,
  UploadFileResponse,
  DownloadFileResponse,
  SendFileResponse,
} from "../api/types";
import { api } from "./auth";

const [files, setFiles] = createStore<FileResponse[]>([]);
const [loadingFiles, setLoadingFiles] = createSignal(false);
const [filesError, setFilesError] = createSignal<string | null>(null);

/** Refresh the file list from the API. */
export async function refreshFiles(): Promise<void> {
  setLoadingFiles(true);
  setFilesError(null);
  try {
    const list = await api.listFiles(100);
    setFiles(list);
  } catch (e) {
    setFilesError(e instanceof Error ? e.message : "Failed to load files");
  } finally {
    setLoadingFiles(false);
  }
}

/** Upload a file to the local node. Returns the upload response. */
export async function uploadFile(
  file: File,
): Promise<UploadFileResponse> {
  const data = await fileToBase64(file);
  const res = await api.uploadFile({
    filename: file.name,
    mime_type: file.type || "application/octet-stream",
    data_b64: data,
  });
  // Refresh the file list after upload
  await refreshFiles();
  return res;
}

/** Download a file's data from the node. */
export async function downloadFile(
  fileId: string,
): Promise<DownloadFileResponse> {
  return api.downloadFile(fileId);
}

/** Trigger a browser download for a file. */
export async function downloadFileToDisk(fileId: string): Promise<void> {
  const res = await api.downloadFile(fileId);
  const binary = atob(res.data_b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  const blob = new Blob([bytes], { type: res.mime_type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = res.filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/** Send a file to a peer via E2EE. */
export async function sendFile(
  fileId: string,
  recipient: string,
): Promise<SendFileResponse> {
  return api.sendFile(fileId, { recipient });
}

/** Delete a file from local storage. */
export async function deleteFileById(fileId: string): Promise<boolean> {
  const res = await api.deleteFile(fileId);
  if (res.deleted) {
    setFiles((list) => list.filter((f) => f.id !== fileId));
  }
  return res.deleted;
}

/** Convert a File object to a base64 string (without the data URL prefix). */
function fileToBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const result = reader.result as string;
      // Strip the "data:...;base64," prefix
      const base64 = result.split(",")[1] ?? result;
      resolve(base64);
    };
    reader.onerror = () => reject(new Error("Failed to read file"));
    reader.readAsDataURL(file);
  });
}

/** Format file size for display. */
export function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export { files, loadingFiles, filesError };
