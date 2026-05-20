/**
 * Context menu for file actions (right-click menu).
 */

import { onMount, onCleanup } from "solid-js";
import {
  IconDownload,
  IconArrowUpRight,
  IconTrash,
  IconPencil,
  IconPreview,
} from "./Icons";

export interface CtxMenuState {
  visible: boolean;
  x: number;
  y: number;
  fileId: string | null;
  filename: string;
  mimeType: string;
}

export function ContextMenu(props: {
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
