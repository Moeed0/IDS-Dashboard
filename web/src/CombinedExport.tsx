// One JSON file with every alert of the engines this machine runs in a time
// window (see docs/combined-json-format.md).
import { useEffect, useState } from "react";
import { Tile } from "./Overview";
import {
  NAMES,
  Unauthorized,
  buildExport,
  count,
  errorText,
  useApi,
  type BuiltExport,
  type ExportWindow,
  type Options,
} from "./api";
import { fromPktInput, stamp, toPktInput } from "./time";

type Built = BuiltExport & { url: string; settings: string };

export function CombinedExport({ options, onUnauthorized }: { options: Options; onUnauthorized: () => void }) {
  const [length, setLength] = useState(options.default_export_length);
  const [anchor, setAnchor] = useState<"latest" | "chosen">("latest");
  const [chosen, setChosen] = useState("");
  const endMs = anchor === "chosen" ? fromPktInput(chosen) : undefined;
  // The window ends where every engine's alerts are stored at the latest.
  const { data: exportWindow, error } = useApi<ExportWindow>(
    "/export/window",
    { length, end_ms: endMs },
    onUnauthorized,
    30_000,
  );

  // A chosen end starts at the latest complete time.
  useEffect(() => {
    if (anchor === "chosen" && !chosen && exportWindow) setChosen(toPktInput(exportWindow.complete_end_ms));
  }, [anchor, chosen, exportWindow]);

  const [built, setBuilt] = useState<Built | null>(null);
  const [building, setBuilding] = useState(false);
  const [buildError, setBuildError] = useState("");
  const settings = JSON.stringify([length, anchor, endMs]);
  // The file stays downloadable until the next one replaces it.
  useEffect(() => () => {
    if (built) URL.revokeObjectURL(built.url);
  }, [built]);

  async function build() {
    setBuilding(true);
    setBuildError("");
    try {
      const result = await buildExport(length, endMs);
      setBuilt({ ...result, url: URL.createObjectURL(result.blob), settings });
    } catch (reason) {
      if (reason instanceof Unauthorized) onUnauthorized();
      else setBuildError(errorText(reason));
    } finally {
      setBuilding(false);
    }
  }

  const shown = built?.settings === settings ? built : null;
  // More alerts than one export may hold: building them could run the IDS
  // machine out of memory.
  const tooMany =
    exportWindow?.stored_alerts !== undefined &&
    exportWindow.max_alerts !== undefined &&
    exportWindow.stored_alerts > exportWindow.max_alerts;
  const engines = options.engines;
  const total = shown ? engines.reduce((sum, engine) => sum + shown.alerts[engine], 0) : 0;

  return (
    <section className="export">
      <h2>Download: combined JSON</h2>
      {/* Said outright: the list's filters above read as if they applied here too. */}
      <p className="muted">
        One file with every alert in the time window chosen here. The list's time range and search above don't
        change it.
      </p>
      <div className="filters">
        <label>
          Length
          <select value={length} onChange={(event) => setLength(event.target.value)}>
            {options.export_lengths.map((choice) => (
              <option key={choice}>{choice}</option>
            ))}
          </select>
        </label>
        <fieldset>
          <legend>Ends at</legend>
          <label className="choice">
            <input type="radio" checked={anchor === "latest"} onChange={() => setAnchor("latest")} />
            Latest complete time
          </label>
          <label className="choice">
            <input type="radio" checked={anchor === "chosen"} onChange={() => setAnchor("chosen")} />
            Chosen time
          </label>
        </fieldset>
        {anchor === "chosen" && (
          <label>
            End (PKT)
            <input type="datetime-local" step={60} value={chosen} onChange={(event) => setChosen(event.target.value)} />
          </label>
        )}
      </div>
      {error && <p className="error">{error}</p>}
      {exportWindow && (
        <p>
          <strong>The file covers</strong> {stamp(exportWindow.start_ms)} → {stamp(exportWindow.end_ms)} PKT
          {exportWindow.moved_back && " · moved back to the latest complete time"}
          {exportWindow.stored_alerts !== undefined && ` · ${count(exportWindow.stored_alerts)} alerts in the database`}
          {exportWindow.from_archive && ", older ones from the archive"}
        </p>
      )}
      {tooMany && exportWindow?.max_alerts !== undefined && (
        <p className="error">
          Too many alerts for one export: it holds at most {count(exportWindow.max_alerts)}. Choose a shorter length.
        </p>
      )}
      <button type="button" className="primary" disabled={building || !exportWindow || tooMany} onClick={build}>
        {building ? "Building…" : "Build combined JSON"}
      </button>
      {buildError && <p className="error">{buildError}</p>}
      {shown && !total && <p className="muted">No alerts in this window.</p>}
      {shown && total > 0 && (
        <>
          <h3>In this file</h3>
          <div className="tiles">
            <Tile label="Alerts" value={count(total)} />
            {engines.length > 1 &&
              engines.map((engine) => <Tile key={engine} label={NAMES[engine]} value={count(shown.alerts[engine])} />)}
            <Tile label="Packets" value={count(shown.packets)} />
            {engines.length > 1 && <Tile label="Both engines" value={count(shown.bothEnginePackets)} />}
          </div>
          <p>
            <a className="button primary" href={shown.url} download={shown.filename}>
              Download combined JSON
            </a>{" "}
            <span className="muted">{shown.filename}</span>
          </p>
        </>
      )}
    </section>
  );
}
