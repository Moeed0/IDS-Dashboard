// The combined JSON in a pop-up over the page, to read before downloading:
// the file as the server wrote it, keys, text and numbers in their own
// colours. Esc, the × or a click beside it closes it; Download saves the
// same text without fetching it again, Copy puts it on the clipboard.
import { useEffect, useRef, useState, type ReactNode } from "react";
import { count, save } from "./api";

// Colouring every token of a very large file would slow the page down.
export const COLOURED_UP_TO = 1_500_000;
// Above this, only the start is shown: the download has all of it.
export const SHOWN_UP_TO = 8_000_000;

const TOKEN = /("(?:[^"\\]|\\.)*")(\s*:)?|\b(true|false|null)\b|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g;

/** The JSON text with its keys, strings, numbers and true/false/null
 * wrapped in spans of their own class. */
export function coloured(text: string): ReactNode[] {
  const nodes: ReactNode[] = [];
  let last = 0;
  for (const match of text.matchAll(TOKEN)) {
    const at = match.index ?? 0;
    if (at > last) nodes.push(text.slice(last, at));
    const [whole, quoted, colon, literal] = match;
    const kind = quoted ? (colon ? "json-key" : "json-string") : literal ? "json-literal" : "json-number";
    nodes.push(
      <span key={at} className={kind}>
        {quoted ?? whole}
      </span>,
    );
    if (colon) nodes.push(colon);
    last = at + whole.length;
  }
  if (last < text.length) nodes.push(text.slice(last));
  return nodes;
}

function size(bytes: number): string {
  return bytes < 1024 * 1024 ? `${count(Math.ceil(bytes / 1024))} KB` : `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

export function JsonPopup({
  filename,
  text,
  holds,
  onClose,
}: {
  filename: string;
  text: string;
  /** What the file holds, in words. */
  holds: string;
  onClose: () => void;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const [copied, setCopied] = useState("");
  useEffect(() => {
    const element = dialog.current;
    if (element && !element.open) element.showModal();
    return () => element?.close();
  }, []);
  useEffect(() => {
    if (!copied) return;
    const timer = window.setTimeout(() => setCopied(""), 3_000);
    return () => window.clearTimeout(timer);
  }, [copied]);

  const bytes = new Blob([text]).size;
  const shown = text.length > SHOWN_UP_TO ? text.slice(0, SHOWN_UP_TO) : text;

  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      setCopied("Copied");
    } catch {
      setCopied("The browser didn't allow copying");
    }
  }

  return (
    <dialog
      ref={dialog}
      className="json-popup"
      aria-label={filename}
      onClose={onClose}
      // A click on the dimmed page beside the box (the dialog itself, not its content) closes it.
      onClick={(event) => {
        if (event.target === event.currentTarget) dialog.current?.close();
      }}
    >
      <div className="json-popup-head">
        <div className="json-popup-title">
          <strong title={filename}>{filename}</strong>
          <span className="muted">
            {holds} · {size(bytes)}
          </span>
        </div>
        {copied && <span className="muted">{copied}</span>}
        <button type="button" onClick={copy}>
          Copy
        </button>
        <button type="button" className="primary" onClick={() => save(new Blob([text], { type: "application/json" }), filename)}>
          Download
        </button>
        <button type="button" className="note-close" aria-label="Close" title="Close (Esc)" onClick={() => dialog.current?.close()}>
          ×
        </button>
      </div>
      {shown !== text && (
        <p className="json-popup-cut">
          Showing the first {size(SHOWN_UP_TO)} of {size(bytes)}; Download has the whole file.
        </p>
      )}
      <pre className="json-popup-body">{shown.length <= COLOURED_UP_TO ? coloured(shown) : shown}</pre>
    </dialog>
  );
}
