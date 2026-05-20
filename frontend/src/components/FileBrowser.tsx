/**
 * FileBrowser — the main file/folder content area of the Drive.
 *
 * Handles folder navigation helpers, computes what's visible at the current
 * path, and delegates rendering to FileGrid (grid mode) or FileList (list mode).
 */

import { createMemo, Show } from "solid-js";
import { FileGrid } from "./FileGrid";
import { FileList } from "./FileList";
import type { FileResponse } from "../api/types";
import { IconFolder } from "./Icons";

// ─── Folder navigation helpers ──────────────────────────────────

/** Given a current path and a filename, return the name relative to that path
 *  if the file lives directly at this level. Returns null for sub-folder files. */
export function fileInPath(filename: string, currentPath: string): string | null {
  const prefix = currentPath ? `${currentPath}/` : "";
  if (!filename.startsWith(prefix)) return null;
  const rest = filename.slice(prefix.length);
  if (rest.includes("/")) return null;
  return rest;
}

/** Sub-folder names visible one level below the current path. */
export function subfoldersAt(allFolders: string[], currentPath: string): string[] {
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

// ─── FileBrowser component ───────────────────────────────────────

export function FileBrowser(props: {
  allFiles: FileResponse[];
  allFolders: string[];
  currentPath: string;
  viewMode: "grid" | "list";
  navigateTo: (path: string) => void;
  deleteFolder: (name: string) => void;
  onFileContextMenu: (e: MouseEvent, file: FileResponse) => void;
  onFilePreview: (state: { fileId: string; filename: string; mimeType: string }) => void;
}) {
  const visibleFiles = createMemo(() =>
    props.allFiles.filter((f) => fileInPath(f.filename, props.currentPath) !== null)
  );

  const visibleFolders = createMemo(() =>
    subfoldersAt(props.allFolders, props.currentPath)
  );

  const fileItems = createMemo(() =>
    visibleFiles().map((f) => ({
      file: f,
      displayName: fileInPath(f.filename, props.currentPath) ?? f.filename,
    }))
  );

  const folderItems = createMemo(() =>
    visibleFolders().map((name) => ({
      name,
      fullPath: props.currentPath ? `${props.currentPath}/${name}` : name,
    }))
  );

  return (
    <div class="drive-browser">
      <Show
        when={visibleFolders().length > 0 || visibleFiles().length > 0}
        fallback={
          <div class="empty-state">
            <div class="empty-state-icon"><IconFolder size={36} /></div>
            <div class="empty-state-title">
              {props.currentPath ? "This folder is empty" : "No files in Drive yet"}
            </div>
            <div class="empty-state-desc">
              {props.currentPath
                ? "Upload a file above to store it here."
                : "Upload a file above to store it on your node, then send it to a peer with end-to-end encryption."
              }
            </div>
          </div>
        }
      >
        <Show when={props.viewMode === "list"}>
          <FileList
            files={fileItems()}
            folders={folderItems()}
            onFolderClick={props.navigateTo}
            onFolderDelete={props.deleteFolder}
            onFileContextMenu={props.onFileContextMenu}
            onFilePreview={(file, displayName) =>
              props.onFilePreview({ fileId: file.id, filename: displayName, mimeType: file.mime_type })
            }
          />
        </Show>
        <Show when={props.viewMode === "grid"}>
          <FileGrid
            files={fileItems()}
            folders={folderItems()}
            onFolderClick={props.navigateTo}
            onFolderDelete={props.deleteFolder}
            onFileContextMenu={props.onFileContextMenu}
            onFilePreview={(file, displayName) =>
              props.onFilePreview({ fileId: file.id, filename: displayName, mimeType: file.mime_type })
            }
          />
        </Show>
      </Show>
    </div>
  );
}
