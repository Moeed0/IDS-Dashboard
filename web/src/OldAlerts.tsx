// The alerts that have left the database: the archive's 10-day zips and the
// day files waiting for theirs, to download (see README.md, "Old alerts"),
// under the Alert Explorer's "Old alerts" fold.
import { useState } from "react";
import { Unauthorized, count, downloadArchiveFile, errorText, useApi, type ArchiveList } from "./api";

// The archive changes once a minute at most, and a zip once in days.
const ARCHIVE_REFRESH_MS = 5 * 60 * 1000;

/** 9.4 MB */
function size(bytes: number): string {
  if (bytes >= 1e9) return `${(bytes / 1e9).toFixed(1)} GB`;
  if (bytes >= 1e6) return `${(bytes / 1e6).toFixed(1)} MB`;
  return `${count(Math.ceil(bytes / 1e3))} KB`;
}

export function OldAlerts({ onUnauthorized }: { onUnauthorized: () => void }) {
  const { data, error } = useApi<ArchiveList>("/archive", {}, onUnauthorized, ARCHIVE_REFRESH_MS);
  const [saving, setSaving] = useState("");
  const [saveError, setSaveError] = useState("");

  // No archive on this machine (IDS_ALERT_ARCHIVE_DAYS=0).
  if (data && data.keep_days === undefined) {
    return <p className="muted">None: this machine deletes the alerts past the database's limit.</p>;
  }

  async function save(name: string) {
    setSaving(name);
    setSaveError("");
    try {
      await downloadArchiveFile(name);
    } catch (reason) {
      if (reason instanceof Unauthorized) onUnauthorized();
      else setSaveError(errorText(reason));
    } finally {
      setSaving("");
    }
  }

  const files = data
    ? [
        ...data.zips.map((zip) => ({ name: zip.name, days: `${zip.first_day} – ${zip.last_day}`, bytes: zip.bytes, note: "" })),
        ...data.days.map((day) => ({ name: day.name, days: day.day, bytes: day.bytes, note: "waiting for its zip" })),
      ]
    : [];

  return (
    <>
      {data && (
        <p className="muted">
          The alerts past the database's limit, kept {data.keep_days} days, a zip for each {data.zip_days}.
        </p>
      )}
      {error && <p className="error">{error}</p>}
      {data && !files.length && (
        <p className="muted">None yet. Alerts move here once the database is past its limit.</p>
      )}
      {files.length > 0 && (
        <div className="table-wrap">
          <table className="archive">
            <thead>
              <tr>
                <th>Days (PKT)</th>
                <th>File</th>
                <th className="number">Size</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {files.map((file) => (
                <tr key={file.name}>
                  <td>{file.days}</td>
                  <td>
                    {file.name}
                    {file.note && <span className="muted"> · {file.note}</span>}
                  </td>
                  <td className="number">{size(file.bytes)}</td>
                  <td>
                    <button type="button" disabled={saving !== ""} onClick={() => save(file.name)}>
                      {saving === file.name ? "Saving…" : "Download"}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {saveError && <p className="error">{saveError}</p>}
    </>
  );
}
