/**
 * ErrorBoundary — catches unhandled rendering errors in child components.
 * Shows a recovery UI with error details and a retry button.
 */

import { ErrorBoundary as SolidErrorBoundary } from "solid-js";
import type { JSX } from "solid-js";
import { IconWarning, IconRefresh } from "./Icons";

interface Props {
  children: JSX.Element;
}

function ErrorFallback(props: { err: Error; reset: () => void }) {
  return (
    <div class="error-boundary-panel">
      <div class="error-boundary-icon">
        <IconWarning size={32} />
      </div>
      <h3 class="error-boundary-title">Something went wrong</h3>
      <p class="error-boundary-message">{props.err.message}</p>
      <button class="btn btn-primary btn-sm icon-text" onClick={props.reset}>
        <IconRefresh size={14} /> Try Again
      </button>
    </div>
  );
}

export default function AppErrorBoundary(props: Props) {
  return (
    <SolidErrorBoundary
      fallback={(err, reset) => (
        <ErrorFallback err={err instanceof Error ? err : new Error(String(err))} reset={reset} />
      )}
    >
      {props.children}
    </SolidErrorBoundary>
  );
}

/** Per-route error boundary — contains crashes to a single view without taking down the whole app. */
export function RouteErrorBoundary(props: Props) {
  return (
    <SolidErrorBoundary
      fallback={(err, reset) => (
        <div class="page content-max">
          <ErrorFallback err={err instanceof Error ? err : new Error(String(err))} reset={reset} />
        </div>
      )}
    >
      {props.children}
    </SolidErrorBoundary>
  );
}
