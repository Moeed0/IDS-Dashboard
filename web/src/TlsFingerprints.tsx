// The TLS fingerprints each device has used (/tls-fingerprints): which
// program opened its encrypted connections, never what was sent inside.
// Suricata gives each handshake's JA4 and JA3. The program is named from the
// threat-intel database when it knows the fingerprint (or from a name given
// with scripts/tls_fingerprints.py --label), and each site under the service
// it belongs to. Each name is written once.
import { useState } from "react";
import { count, useApi, useNow, type PacketOnlyFingerprint, type TlsFingerprint } from "./api";
import { clock } from "./time";

// Handshakes are stored within seconds; a minute is enough for this list.
const REFRESH_MS = 60_000;
// How many of a service's sites are written out.
const SITES_SHOWN = 3;

/** The program (when known) and the sites under their services, each name
 * once: a service named the same as the program shows only its sites. */
export function Services({ row }: { row: TlsFingerprint }) {
  const groups = row.services ?? [{ name: null, sites: row.sites }];
  const known = row.app ? null : row.known_app;
  const program = row.app || known?.name || "";
  const same = (name: string | null) => !!name && name.toLowerCase() === program.trim().toLowerCase();
  return (
    <ul className="services">
      {program && (
        <li>
          <strong>{program}</strong>{" "}
          <span className={known?.malware ? "malware" : "muted"}>
            {known ? `${known.malware ? "known malware, " : ""}from ${known.source}` : "named in the lab"}
          </span>
        </li>
      )}
      {!row.sites.length && !program && <li className="muted">none named</li>}
      {groups.map((group) => (
        <li key={group.name ?? ""}>
          {group.name && !same(group.name) && <strong>{group.name} </strong>}
          <span className={group.name ? "muted" : undefined}>
            {group.sites.slice(0, SITES_SHOWN).join(", ")}
            {group.sites.length > SITES_SHOWN && ` (+${group.sites.length - SITES_SHOWN})`}
          </span>
        </li>
      ))}
    </ul>
  );
}

/** A JA4 with a place to break after each part (t13d1516h2_ 8daaf6152771_
 * 02713d6af862), so a narrow column takes it whole parts at a time. */
function Breakable({ text }: { text: string }) {
  const parts = text.split(/(?<=[_:])/);
  return (
    <span className="fingerprint">
      {parts.map((part, index) => (
        <span key={index}>
          {part}
          {index < parts.length - 1 && <wbr />}
        </span>
      ))}
    </span>
  );
}

export function TlsFingerprints({ onUnauthorized }: { onUnauthorized: () => void }) {
  const { data, error } = useApi<{ fingerprints: TlsFingerprint[]; packet_only?: PacketOnlyFingerprint[] }>(
    "/tls-fingerprints",
    {},
    onUnauthorized,
    REFRESH_MS,
  );
  const now = useNow();
  const [device, setDevice] = useState("");

  const rows = data?.fingerprints ?? [];
  const devices = [...new Set(rows.map((row) => row.device))].sort();
  const shown = device ? rows.filter((row) => row.device === device) : rows;

  return (
    <section className="fingerprints">
      <h2>TLS fingerprints</h2>
      <p className="muted">
        Which program each device used for its encrypted connections (JA4 and JA3, from Suricata), and the services
        and sites it went to. Never what was sent inside. Programs and services are named from the threat-intel
        database when it knows them. A fingerprint new on the network or new for a device, or on the known-bad
        lists, raises a Suricata alert. &quot;✓ from the packets&quot;: that many of its handshakes were worked out
        again here from the Client Hello in Suricata&apos;s saved packets (the connections it alerted on) and gave
        the same JA4.
      </p>
      {(data?.packet_only?.length ?? 0) > 0 && (
        <div className="differs">
          In the packets but not in Suricata&apos;s records:
          <ul>
            {data?.packet_only?.map((item) => (
              <li key={`${item.device} ${item.ja4}`}>
                {item.device} <code>{item.ja4}</code>
                {item.site && ` · ${item.site}`} · {count(item.connections)}× · {clock(item.last_seen_ms, now)}
              </li>
            ))}
          </ul>
        </div>
      )}
      {error && <p className="error">{error}</p>}
      {data && !rows.length && <p className="muted">None yet: no device has opened a TLS or QUIC connection since this started.</p>}
      {devices.length > 1 && (
        <label>
          Device{" "}
          <select value={device} onChange={(event) => setDevice(event.target.value)}>
            <option value="">All ({devices.length})</option>
            {devices.map((name) => (
              <option key={name} value={name}>
                {name}
              </option>
            ))}
          </select>
        </label>
      )}
      {shown.length > 0 && (
        <div className="table-wrap">
          <table className="fingerprint-table">
            <thead>
              <tr>
                <th>Device</th>
                <th>Fingerprint</th>
                <th className="number">Connections</th>
                <th>Names and sites</th>
                <th>First seen</th>
                <th>Last seen</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((row) => {
                const key = `${row.device} ${row.fingerprint}`;
                // The JA3s, less the one the fingerprint already is.
                const ja3 = row.ja3.filter((hash) => row.fingerprint !== `ja3:${hash}`);
                return (
                  <tr key={key}>
                    <td>
                      {row.device}
                      {row.devices > 1 && (
                        <div className="muted">
                          also on {row.devices - 1} other device{row.devices > 2 ? "s" : ""}
                        </div>
                      )}
                    </td>
                    <td className="mono">
                      <Breakable text={row.fingerprint} />
                      {ja3.length > 0 && (
                        <div className="muted">
                          JA3 {ja3[0]}
                          {ja3.length > 1 && ` (+${ja3.length - 1})`}
                        </div>
                      )}
                      <div className="muted">
                        {row.protocols.join(", ").toUpperCase()}
                        {row.alpn.length > 0 && ` · ${row.alpn[0]}`}
                      </div>
                    </td>
                    <td className="number">
                      {count(row.connections)}
                      {(row.checked ?? 0) > 0 && (
                        <div className="muted" title="Worked out again from the Client Hello in Suricata's saved packets: the same JA4">
                          ✓ {count(row.checked ?? 0)} from the packets
                        </div>
                      )}
                    </td>
                    <td className="names">
                      <Services row={row} />
                    </td>
                    <td>{clock(row.first_seen_ms, now)}</td>
                    <td>{clock(row.last_seen_ms, now)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
