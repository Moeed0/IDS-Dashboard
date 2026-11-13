// One alert, whole, in a panel down the right side of the Alert Explorer:
// what the list cuts short, the other alerts on its packet, its rule (why it
// fired, its text and what is known about it) and the engines' own output
// for the packet, as the combined JSON gives them (GET /alerts/{id}).
import { useEffect, type ReactNode } from "react";
import { SeverityCircles } from "./AlertExplorer";
import { NAMES, ruleName, useApi, type AlertDetails, type AlertRow } from "./api";
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

/** The rule's entry among the file's rules: "snort:116:444", or with ":rev5"
 * after it when two revisions fired. */
export function ruleEntry(rules: AlertDetails["rules"], alert: AlertRow): Record<string, unknown> | null {
  const name = `${alert.engine}:${alert.rule}`;
  const key = Object.keys(rules ?? {}).find((candidate) => candidate === name || candidate === `${name}:rev${alert.rev}`);
  return key ? (rules?.[key] ?? null) : null;
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
            {alert.label && (
              <Fact name="Label">
                {alert.label === "attack" ? (
                  <span className="tag attack">Lab attack</span>
                ) : (
                  "Background"
                )}{" "}
                <span className="muted">
                  {alert.label === "attack" ? "from or to a lab attacker" : "no lab attacker on either side"}
                </span>
              </Fact>
            )}
            <Fact name="Rule">
              {ruleName(alert)}{" "}
              <button type="button" className="link" onClick={() => onRule(ruleName(alert))}>
                show its alerts
              </button>
            </Fact>
            {alert.class && <Fact name="Class">{alert.class}</Fact>}
            {alert.protocol && <Fact name="Protocol">{[alert.protocol, alert.service].filter(Boolean).join(" · ")}</Fact>}
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
        </>
      )}
    </aside>
  );
}
