// The alerts the Alert Explorer's filters choose, as one combined JSON file
// (see docs/combined-json-format.md): two buttons, to download it or send it
// to the LLM PC, whose hover text says what the file would hold. Only the
// outcome of a click is written out.
import { useEffect, useState } from "react";
import {
  NAMES,
  Unauthorized,
  count,
  downloadSelection,
  errorText,
  sendSelection,
  useApi,
  type Options,
  type Params,
  type SelectionInfo,
} from "./api";
import { stamp } from "./time";

// As often as the lists' newest alerts.
const INFO_REFRESH_MS = 10_000;

/** What the file would hold, in words: "40 alerts (Snort 20 · Suricata 20)". */
export function holding(options: Options, info: SelectionInfo): string {
  const engines = options.engines.map((engine) => `${NAMES[engine]} ${count(info.alerts[engine] ?? 0)}`);
  const cut = info.complete_end_ms !== null ? `, up to ${stamp(info.complete_end_ms)}, where both engines' alerts are stored` : "";
  return `${count(info.total)} alerts${engines.length > 1 ? ` (${engines.join(" · ")})` : ""}${cut}`;
}

export function CombinedExport({
  options,
  params,
  onUnauthorized,
}: {
  options: Options;
  params: Params;
  onUnauthorized: () => void;
}) {
  const { data: info, error } = useApi<SelectionInfo>("/export/selection", params, onUnauthorized, INFO_REFRESH_MS);
  const [busy, setBusy] = useState<"download" | "send" | null>(null);
  const [result, setResult] = useState<{ text: string; failed: boolean } | null>(null);
  // Other filters choose other alerts: the last result was about those.
  const chosen = JSON.stringify(params);
  useEffect(() => setResult(null), [chosen]);

  async function run(kind: "download" | "send") {
    setBusy(kind);
    setResult(null);
    try {
      if (kind === "download") {
        setResult({ text: `Saved ${await downloadSelection(params)}`, failed: false });
      } else {
        const sent = await sendSelection(params);
        const alerts = Object.values(sent.alerts).reduce((sum, value) => sum + (value ?? 0), 0);
        setResult({
          text: `Sent ${count(alerts)} alerts (${count(Math.ceil(sent.bytes / 1024))} KB) to ${sent.to} as ${sent.filename}`,
          failed: false,
        });
      }
    } catch (reason) {
      if (reason instanceof Unauthorized) onUnauthorized();
      else setResult({ text: errorText(reason), failed: true });
    } finally {
      setBusy(null);
    }
  }

  const tooMany = info !== null && info.total > info.max_alerts;
  const ready = info !== null && info.total > 0 && !tooMany && busy === null;
  const why =
    error ||
    (info === null
      ? ""
      : info.total === 0
        ? "No alerts match the filters"
        : tooMany
          ? `One file holds at most ${count(info.max_alerts)} alerts: show only the newest few, or narrow the filters`
          : "");
  const downloadHint = why || (info ? `Download ${holding(options, info)}, as combined JSON` : "");
  const sendHint = !options.send_to
    ? "Send is off: put the LLM PC's address in IDS_LLM_URL in .env, then restart the dashboard"
    : why || (info ? `Send ${holding(options, info)} to the LLM PC at ${options.send_to}` : "");

  return (
    <>
      {/* A disabled button shows no hover text in every browser: its box does. */}
      <span title={downloadHint}>
        <button type="button" className="primary" disabled={!ready} onClick={() => run("download")}>
          {busy === "download" ? "Preparing…" : "Download JSON"}
        </button>
      </span>
      <span title={sendHint}>
        <button type="button" disabled={!ready || !options.send_to} onClick={() => run("send")}>
          {busy === "send" ? "Sending…" : "Send"}
        </button>
      </span>
      {result && (
        <span className={`outcome ${result.failed ? "error" : "sent"}`} title={result.text}>
          {result.text}
        </span>
      )}
    </>
  );
}
