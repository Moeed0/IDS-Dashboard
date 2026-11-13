import { useCallback, useEffect, useState } from "react";
import { AlertExplorer } from "./AlertExplorer";
import { Overview } from "./Overview";
import { StatusNote, StatusPanel, StatusStrip } from "./StatusPanel";
import { Unauthorized, engineNames, errorText, getJson, setToken, useApi, type Options, type Status } from "./api";
import type { SearchRequest } from "./AlertExplorer";

type Page = "overview" | "alerts";
const PAGES: { key: Page; label: string }[] = [
  { key: "overview", label: "Overview" },
  { key: "alerts", label: "Alert Explorer" },
];

export default function App() {
  const [page, setPage] = useState<Page>("overview");
  // A rule clicked on the Overview, for the Alert Explorer's search.
  const [searchRequest, setSearchRequest] = useState<SearchRequest | null>(null);
  const searchAlerts = useCallback((text: string) => {
    setSearchRequest({ text, at: Date.now() });
    setPage("alerts");
  }, []);
  // Asked for only when the API answers 401: with IDS_API_REQUIRE_TOKEN=false
  // it lets every browser in.
  const [needsToken, setNeedsToken] = useState(false);
  const [options, setOptions] = useState<Options | null>(null);
  const [error, setError] = useState("");
  const onUnauthorized = useCallback(() => setNeedsToken(true), []);

  useEffect(() => {
    if (needsToken) return;
    const controller = new AbortController();
    getJson<Options>("/options", {}, controller.signal)
      .then((loaded) => {
        setOptions(loaded);
        setError("");
      })
      .catch((reason: unknown) => {
        if (reason instanceof Unauthorized) setNeedsToken(true);
        else if (!(reason instanceof DOMException && reason.name === "AbortError")) setError(errorText(reason));
      });
    return () => controller.abort();
  }, [needsToken]);

  if (needsToken) return <TokenForm onSaved={() => setNeedsToken(false)} />;
  // Nothing until the API first answers, so the token box does not follow a
  // flash of the screens.
  if (!options && !error) return null;

  return (
    <div className="app">
      <header>
        <h1>{options ? `${engineNames(options.engines)} IDS` : "IDS"}</h1>
        <nav>
          {PAGES.map((item) => (
            <button
              key={item.key}
              type="button"
              className={item.key === page ? "current" : undefined}
              onClick={() => setPage(item.key)}
            >
              {item.label}
            </button>
          ))}
        </nav>
        <span className="header-note muted">Times are PKT (UTC+05:00)</span>
      </header>
      {options ? (
        <Screens
          page={page}
          options={options}
          onUnauthorized={onUnauthorized}
          onSearch={searchAlerts}
          searchRequest={searchRequest}
        />
      ) : (
        <div className="layout">
          <main>{error && <p className="error">{error}</p>}</main>
        </div>
      )}
    </div>
  );
}

/** The screen: the Overview with the status strip over it and the panel
 * beside it, and the Alert Explorer over the whole width, where only a
 * problem is said (in a line over it). All show what /status says. */
function Screens({
  page,
  options,
  onUnauthorized,
  onSearch,
  searchRequest,
}: {
  page: Page;
  options: Options;
  onUnauthorized: () => void;
  onSearch: (text: string) => void;
  searchRequest: SearchRequest | null;
}) {
  const status = useApi<Status>("/status", {}, onUnauthorized, 10_000);
  return (
    <div className={page === "overview" ? "layout" : "layout whole"}>
      <main>
        {page === "overview" && (
          <>
            <StatusStrip status={status} />
            <Overview options={options} onUnauthorized={onUnauthorized} onSearch={onSearch} />
          </>
        )}
        {page === "alerts" && (
          <>
            <StatusNote status={status} />
            <AlertExplorer options={options} onUnauthorized={onUnauthorized} searchRequest={searchRequest} />
          </>
        )}
      </main>
      {page === "overview" && <StatusPanel status={status} />}
    </div>
  );
}

function TokenForm({ onSaved }: { onSaved: () => void }) {
  const [value, setValue] = useState("");
  return (
    <form
      className="token"
      onSubmit={(event) => {
        event.preventDefault();
        setToken(value.trim());
        onSaved();
      }}
    >
      <h1>Snort + Suricata IDS</h1>
      <label>
        API token
        {/* Shown as typed, and not changed by the keyboard: it is typed by hand. */}
        <input
          type="text"
          autoCapitalize="none"
          autoComplete="off"
          autoCorrect="off"
          spellCheck={false}
          placeholder="xxxx-xxxx-xxxx-xxxx"
          value={value}
          onChange={(event) => setValue(event.target.value)}
          autoFocus
        />
      </label>
      <button type="submit" className="primary" disabled={!value.trim()}>
        Save
      </button>
      <p className="muted">IDS_API_TOKEN in .env on the IDS machine.</p>
    </form>
  );
}
