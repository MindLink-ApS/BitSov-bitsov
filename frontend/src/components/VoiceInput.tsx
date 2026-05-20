/**
 * VoiceInput — push-to-talk voice capture component (AIX9).
 *
 * ## Behaviour
 * - Hold **Spacebar** (or press the mic button) to record.
 * - Release to stop; captured audio is submitted to the on-device Whisper
 *   STT endpoint and the transcript is returned via `onTranscript`.
 * - Uses `MediaRecorder` (browser-native, no external SDK).
 *
 * ## Security
 *
 * | `allowCloudStt` | Behaviour |
 * |-----------------|-----------|
 * | `false` (default) | Enabled only when `localModelReady` is true. Audio is sent to the local `/api/v1/ai/stt` endpoint — no cloud call. |
 * | `true` | Same routing (always local backend) but a warning banner is shown because the node config has the cloud-STT flag enabled. |
 *
 * Browser Web Speech API (which routes to Google) is intentionally NOT used.
 * All audio bytes go to the on-device Whisper backend.
 */

import {
  createSignal,
  createEffect,
  onCleanup,
  Show,
} from "solid-js";
import { IconMic, IconMicOff, IconWarning, IconShield } from "./Icons";

// ── Props ──────────────────────────────────────────────────────────────────

export interface VoiceInputProps {
  /** Called with the transcript text when recording stops successfully. */
  onTranscript: (text: string) => void;
  /** Whether [ai.voice] allow_cloud_stt = true in node config. Default: false. */
  allowCloudStt?: boolean;
  /** Whether the node has a Whisper model loaded. Default: false. */
  localModelReady?: boolean;
  /** Disable the control entirely (e.g. while the AI is responding). */
  disabled?: boolean;
}

// ── Constants ──────────────────────────────────────────────────────────────

const CLOUD_STT_FLAG_WARNING =
  "Note: allow_cloud_stt is enabled in your node config. " +
  "Audio is still processed by the on-device Whisper model, but this flag " +
  "permits future cloud fallback. Set allow_cloud_stt = false to disable.";

const PREFERRED_MIME_TYPES = [
  "audio/webm;codecs=opus",
  "audio/webm",
  "audio/ogg;codecs=opus",
  "audio/ogg",
  "audio/mp4",
];

function pickMimeType(): string {
  for (const mime of PREFERRED_MIME_TYPES) {
    if (typeof MediaRecorder !== "undefined" && MediaRecorder.isTypeSupported(mime)) {
      return mime;
    }
  }
  return "";
}

// ── Component ──────────────────────────────────────────────────────────────

export default function VoiceInput(props: VoiceInputProps) {
  const [recording, setRecording] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);
  const [duration, setDuration] = createSignal(0);

  let mediaRecorder: MediaRecorder | null = null;
  let chunks: Blob[] = [];
  let stream: MediaStream | null = null;
  let durationTimer: ReturnType<typeof setInterval> | null = null;

  // Voice is available when a local model is ready OR cloud STT flag is set.
  const voiceAvailable = () =>
    (props.localModelReady ?? false) || (props.allowCloudStt ?? false);

  const isDisabled = () => (props.disabled ?? false) || !voiceAvailable();

  const statusLabel = () => {
    if (props.disabled) return "Disabled";
    if (!voiceAvailable()) return "No Whisper model";
    if (recording()) return `Recording\u2026 ${duration()}s`;
    return "Hold Space to talk";
  };

  async function submitAudio(blob: Blob): Promise<string> {
    const form = new FormData();
    form.append("audio", blob, "recording.webm");
    const resp = await fetch("/api/v1/ai/stt", { method: "POST", body: form });
    if (!resp.ok) {
      const body = await resp.text().catch(() => resp.statusText);
      throw new Error(`STT error ${resp.status}: ${body}`);
    }
    const data = (await resp.json()) as { transcript?: string };
    return data.transcript?.trim() ?? "";
  }

  async function startRecording() {
    if (recording() || isDisabled()) return;
    setError(null);
    chunks = [];

    try {
      stream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
    } catch (e) {
      setError(`Microphone access denied: ${e instanceof Error ? e.message : String(e)}`);
      return;
    }

    const mimeType = pickMimeType();
    try {
      mediaRecorder = new MediaRecorder(stream, mimeType ? { mimeType } : {});
    } catch (e) {
      setError(`Recorder failed: ${e instanceof Error ? e.message : String(e)}`);
      stream.getTracks().forEach((t) => t.stop());
      stream = null;
      return;
    }

    mediaRecorder.ondataavailable = (evt) => {
      if (evt.data.size > 0) chunks.push(evt.data);
    };

    mediaRecorder.onstop = async () => {
      const blob = new Blob(chunks, { type: mimeType || "audio/webm" });
      chunks = [];
      try {
        const transcript = await submitAudio(blob);
        if (transcript) {
          props.onTranscript(transcript);
        } else {
          setError("Empty transcript — is the Whisper model loaded on the node?");
        }
      } catch (e) {
        setError(`Transcription failed: ${e instanceof Error ? e.message : String(e)}`);
      }
    };

    mediaRecorder.start(100);
    setRecording(true);
    setDuration(0);
    durationTimer = setInterval(() => setDuration((d) => d + 1), 1000);
  }

  function stopRecording() {
    if (!recording()) return;
    if (durationTimer !== null) {
      clearInterval(durationTimer);
      durationTimer = null;
    }
    setRecording(false);
    if (mediaRecorder && mediaRecorder.state !== "inactive") {
      mediaRecorder.stop();
    }
    stream?.getTracks().forEach((t) => t.stop());
    stream = null;
    mediaRecorder = null;
  }

  // Spacebar push-to-talk — only when focus is not in a text field.
  function onKeyDown(e: KeyboardEvent) {
    const target = e.target as HTMLElement;
    const inText =
      target.tagName === "TEXTAREA" ||
      target.tagName === "INPUT" ||
      target.isContentEditable;
    if (e.code === "Space" && !inText && !e.repeat) {
      e.preventDefault();
      void startRecording();
    }
  }

  function onKeyUp(e: KeyboardEvent) {
    if (e.code === "Space" && recording()) {
      e.preventDefault();
      stopRecording();
    }
  }

  createEffect(() => {
    document.addEventListener("keydown", onKeyDown);
    document.addEventListener("keyup", onKeyUp);
    onCleanup(() => {
      document.removeEventListener("keydown", onKeyDown);
      document.removeEventListener("keyup", onKeyUp);
      stopRecording();
    });
  });

  return (
    <div class="voice-input-root" aria-label="Voice input">

      {/* Cloud STT flag warning */}
      <Show when={props.allowCloudStt}>
        <div class="voice-cloud-warning" role="alert">
          <IconWarning size={12} />
          <span class="text-xs">{CLOUD_STT_FLAG_WARNING}</span>
        </div>
      </Show>

      {/* No model configured */}
      <Show when={!voiceAvailable()}>
        <div class="voice-no-model" role="status">
          <IconMicOff size={14} />
          <span class="text-xs text-muted">
            Voice unavailable — configure{" "}
            <code class="voice-config-hint">whisper_model_path</code> under{" "}
            <code class="voice-config-hint">[ai.voice]</code> to enable
            on-device transcription.
          </span>
        </div>
      </Show>

      {/* Push-to-talk */}
      <Show when={voiceAvailable()}>
        <div class="voice-ptt-area">
          <button
            class={`voice-ptt-btn${recording() ? " voice-ptt-recording" : ""}`}
            onMouseDown={() => void startRecording()}
            onMouseUp={() => stopRecording()}
            onTouchStart={(e) => { e.preventDefault(); void startRecording(); }}
            onTouchEnd={(e) => { e.preventDefault(); stopRecording(); }}
            disabled={props.disabled}
            aria-label={recording() ? "Recording — release to stop" : "Hold to record"}
            aria-pressed={recording()}
            title="Hold to record (or hold Spacebar)"
          >
            <Show when={recording()} fallback={<IconMic size={18} />}>
              <span class="voice-recording-rings" aria-hidden="true">
                <span class="voice-ring voice-ring-1" />
                <span class="voice-ring voice-ring-2" />
              </span>
              <IconMic size={18} />
            </Show>
          </button>

          <div class="voice-status-label text-xs text-muted" aria-live="polite">
            {statusLabel()}
          </div>

          <div class="voice-local-badge" title="Audio processed on-node — never leaves your machine">
            <IconShield size={10} />
            <span class="text-xs">Local</span>
          </div>
        </div>
      </Show>

      {/* Error */}
      <Show when={error()}>
        <div class="voice-error text-xs" role="alert" aria-live="assertive">
          <IconWarning size={12} />
          {error()}
        </div>
      </Show>
    </div>
  );
}
