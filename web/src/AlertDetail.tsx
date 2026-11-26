// One alert, whole, in a panel down the right side of the Alert Explorer:
// what the list cuts short, the other alerts on its packet, its rule (why it
// fired, its text and what is known about it) and the engines' own output
// for the packet, as the combined JSON gives them, and each alert's record as
// its engine wrote it (GET /alerts/{id}).
import { useEffect, useState, type ReactNode } from "react";
import { SeverityCircles } from "./AlertExplorer";
import { NAMES, ruleName, useApi, type AlertDetails, type AlertRow, type RawRecord } from "./api";
import { stamp } from "./time";

/** "why_triggered" as a heading: "Why triggered". */
function heading(key: string): string {
  const words = key.replace(/_/g, " ");
  return words.charAt(0).toUpperCase() + words.slice(1);
}

/** A value of the combined JSON: text as text, a list of texts as a list,
 * anything else as indented JSON. */
function Value({ value }: { value: unknown }) {
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return <p>{String(value)}</p>;
  if (Array.isArray(value) && value.every((item) => typeof item === "string")) {
    return (
      <ul>
        {value.map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ul>
    );
  }
  return <pre>{JSON.stringify(value, null, 2)}</pre>;
}

/** The rule's entry among the file's rules: "snort_signature:116:444:1". */
export function ruleEntry(rules: AlertDetails["rules"], alert: AlertRow): Record<string, unknown> | null {
  const name = `${alert.engine}_signature:${alert.gid ?? 1}:${alert.sid}:${alert.rev}`;
  return rules?.[name] ?? null;
}

/** Where each engine writes its records on the IDS. */
const LOGS: Record<string, string> = {
  snort: "/var/log/snort/alert_json.txt",
  suricata: "/var/log/suricata/eve.json",
  snort_tls: "/var/log/snort/file_connector_tls_transmit",
};

/** The records, one engine's after another's, as indented JSON or as the one
 * line the engine wrote. */
export function RawOutput({ records, current }: { records: RawRecord[]; current: number }) {
  const [oneLine, setOneLine] = useState(false);
  const [copied, setCopied] = useState<number | null>(null);
  const text = (raw: RawRecord) =>
    typeof raw.record === "string" ? raw.record : JSON.stringify(raw.record, null, oneLine ? undefined : 2);
  const copy = (raw: RawRecord) => {
    navigator.clipboard?.writeText(text(raw)).then(
      () => setCopied(raw.id),
      () => setCopied(null),
    );
  };
  return (
    <section>
      <div className="raw-head">
        <h3>Raw output</h3>
        <label>
          <input type="checkbox" checked={oneLine} onChange={(event) => setOneLine(event.target.checked)} /> one line
        </label>
      </div>
      <p className="muted">
        Each alert on this packet as its engine wrote it, and Snort&apos;s record of the TLS connection it was on, every
        field and value, with the keys in alphabetical order.
      </p>
      {records.map((raw) => (
        <div key={raw.id} className="raw-record">
          <h4>
            {NAMES[raw.engine] ?? raw.engine}
            {raw.source === "snort_tls"
              ? " · the TLS connection"
              : raw.id === current
                ? " · this alert"
                : raw.uid
                  ? ` · ${raw.uid}`
                  : ""}
            <span className="muted"> · {LOGS[raw.source ?? raw.engine] ?? ""}</span>
            <button type="button" className="link" onClick={() => copy(raw)}>
              {copied === raw.id ? "copied" : "copy"}
            </button>
          </h4>
          <pre className={oneLine ? "raw one-line" : "raw"}>{text(raw)}</pre>
        </div>
      ))}
    </section>
  );
}

function Fact({ name, children }: { name: string; children: ReactNode }) {
  return (
    <>
      <dt>{name}</dt>
      <dd>{children}</dd>
    </>
  );
}

export function AlertDetail({
  id,
  onOpen,
  onRule,
  onClose,
  onUnauthorized,
}: {
  id: number;
  /** Another alert of the packet, clicked. */
  onOpen: (id: number) => void;
  /** Its rule, for the Rule filter. */
  onRule: (rule: string) => void;
  onClose: () => void;
  onUnauthorized: () => void;
}) {
  const { data, error } = useApi<AlertDetails>(`/alerts/${id}`, {}, onUnauthorized);
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  // The last alert stays while the next one clicked is fetched.
  const alert = data?.alert;
  const rule = alert ? ruleEntry(data.rules, alert) : null;
  const { why_triggered: why, rule_text: text, ids_output: always, ...known } = rule ?? {};
  // A TLS or QUIC connection's program and service, each name once: a
  // service named the same as the program shows only its site.
  const connection = data?.connection;
  const serviceShown =
    !!connection?.service && connection.service.toLowerCase() !== (connection.program?.name ?? "").toLowerCase();

  return (
    <aside className="drawer" aria-label="Alert">
      <div className="drawer-head">
        {alert ? (
          <h2>
            <SeverityCircles severity={alert.severity} /> {alert.message}
          </h2>
        ) : (
          <h2 className="muted">{error ? "" : "Loading…"}</h2>
        )}
        <button type="button" title="Close (Esc)" aria-label="Close" onClick={onClose}>
          ✕
        </button>
      </div>
      {error && <p className="error">{error}</p>}
      {alert && (
        <>
          <dl className="facts">
            <Fact name="Time">{stamp(alert.time_ms)} PKT</Fact>
            <Fact name="Engine">{NAMES[alert.engine] ?? alert.engine}</Fact>
            <Fact name="Rule">
              {ruleName(alert)}{" "}
              <button type="button" className="link" onClick={() => onRule(ruleName(alert))}>
                show its alerts
              </button>
            </Fact>
            {alert.class && <Fact name="Class">{alert.class}</Fact>}
            {alert.protocol && <Fact name="Protocol">{[alert.protocol, alert.service].filter(Boolean).join(" · ")}</Fact>}
            {alert.app && (
              <Fact name="App">
                {alert.app} <span className="muted">as OpenAppID named it</span>
              </Fact>
            )}
            {connection?.program && (
              <Fact name="Program">
                {connection.program.name}{" "}
                <span className={connection.program.malware ? "malware" : "muted"}>
                  {connection.program.malware ? "known malware, " : ""}from {connection.program.source}
                </span>
              </Fact>
            )}
            {connection?.site && (
              <Fact name={serviceShown ? "Service" : "Site"}>
                {serviceShown ? (
                  <>
                    {connection.service}
                    {connection.by_address && "?"} <span className="muted">{connection.site}</span>
                  </>
                ) : (
                  `${connection.site}${connection.by_address ? "?" : ""}`
                )}
                {connection.seen_by && connection.seen_by.length > 1 && (
                  <span className="muted"> ✓ both engines</span>
                )}
                {connection.seen_by?.length === 1 && connection.seen_by[0] === "snort" && (
                  <span className="muted"> from Snort&apos;s record of this connection</span>
                )}
                {connection.snort_site && (
                  <div className="differs">
                    Snort recorded {connection.snort_service ? `${connection.snort_service} ` : ""}
                    {connection.snort_site} for this connection
                  </div>
                )}
                {connection.by_address && (
                  <div className="muted">
                    Probably: no TLS details on this alert, but {connection.server} was reached as this site in a
                    TLS handshake. One address can serve several sites.
                  </div>
                )}
              </Fact>
            )}
            {connection?.owner && !connection.site && (
              <Fact name="Network">
                {connection.owner.name}?{" "}
                <span className="muted">
                  AS{connection.owner.asn}
                  {connection.owner.country && ` · ${connection.owner.country}`} · {connection.owner.description}
                </span>
                <div className="muted">
                  Probably: nothing in this traffic names it, so this is who owns {connection.server}, the network the
                  server runs on, not necessarily the app.
                </div>
              </Fact>
            )}
            {connection?.encryption && (
              <Fact name="Encryption">
                {[connection.encryption.version, connection.encryption.cipher, connection.encryption.curve]
                  .filter(Boolean)
                  .join(" · ")}
              </Fact>
            )}
            {connection?.certificate && (
              <Fact name="Certificate">
                {connection.certificate.subject}
                {connection.certificate.issuer && (
                  <div className="muted">issued by {connection.certificate.issuer}</div>
                )}
              </Fact>
            )}
            {alert.src && <Fact name="Source">{alert.src}</Fact>}
            {alert.dst && <Fact name="Destination">{alert.dst}</Fact>}
            <Fact name="Alert ID">{alert.uid}</Fact>
            <Fact name="Packet ID">
              {alert.packet}
              {alert.both && <span className="muted"> · both engines alerted on it</span>}
            </Fact>
          </dl>

          {data.same_packet.length > 0 && (
            <section>
              <h3>Also on this packet</h3>
              <ul className="mates">
                {data.same_packet.map((other) => (
                  <li key={other.id}>
                    <button type="button" className="link" title="Open this alert" onClick={() => onOpen(other.id)}>
                      {NAMES[other.engine] ?? other.engine} {ruleName(other)}
                    </button>{" "}
                    {other.message}
                  </li>
                ))}
              </ul>
            </section>
          )}

          {rule && (
            <section>
              <h3>The rule</h3>
              {typeof why === "string" && <p>{why}</p>}
              {typeof text === "string" && <pre className="rule-text">{text}</pre>}
              {Object.entries(known).map(([key, value]) => (
                <div key={key}>
                  <h4>{heading(key)}</h4>
                  <Value value={value} />
                </div>
              ))}
              {always !== undefined && (
                <div>
                  <h4>On every alert of this rule</h4>
                  <Value value={always} />
                </div>
              )}
            </section>
          )}

          {(["cves", "attack_techniques"] as const).map(
            (key) =>
              data[key] && (
                <section key={key}>
                  <h3>{key === "cves" ? "CVEs" : "ATT&CK techniques"}</h3>
                  <Value value={data[key]} />
                </section>
              ),
          )}

          {data.packets && (
            <section>
              <h3>The packet, as the combined JSON gives it</h3>
              <Value value={data.packets[0]} />
            </section>
          )}

          {data.raw && data.raw.length > 0 && <RawOutput records={data.raw} current={alert.id} />}
        </>
      )}
    </aside>
  );
}
