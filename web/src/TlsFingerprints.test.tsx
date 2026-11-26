import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { Services } from "./TlsFingerprints";
import type { TlsFingerprint } from "./api";

function row(services: TlsFingerprint["services"], known: TlsFingerprint["known_app"] = null): TlsFingerprint {
  return {
    device: "192.168.50.120", fingerprint: "t13d1516h2_8daaf6152771_02713d6af862", ja4: null, protocols: ["tls"],
    first_seen_ms: 0, last_seen_ms: 0, connections: 1, sites: services.flatMap((group) => group.sites),
    ja3: [], ja3s: [], alpn: [], app: null, note: null, devices: 1, known_app: known, services,
  };
}

describe("Services", () => {
  it("writes the program and each service once, with its sites, the sites of no service last", () => {
    const html = renderToStaticMarkup(
      <Services
        row={row(
          [
            { name: "Youtube", sites: ["i.ytimg.com", "www.youtube.com", "a.googlevideo.com", "b.googlevideo.com"] },
            { name: null, sites: ["lab.local"] },
          ],
          { name: "Chromium Browser", source: "FoxIO's JA4+ mapping", malware: false },
        )}
      />,
    );

    expect(html.match(/Chromium Browser/g)).toHaveLength(1);
    expect(html.match(/Youtube/g)).toHaveLength(1);
    expect(html).toContain("from FoxIO&#x27;s JA4+ mapping");
    expect(html).toContain("i.ytimg.com, www.youtube.com, a.googlevideo.com (+1)");
    expect(html.indexOf("Chromium Browser")).toBeLessThan(html.indexOf("Youtube"));
    expect(html.indexOf("Youtube")).toBeLessThan(html.indexOf("lab.local"));
  });

  it("leaves out a service named the same as the program", () => {
    const html = renderToStaticMarkup(
      <Services row={{ ...row([{ name: "WhatsApp", sites: ["web.whatsapp.com"] }]), app: "whatsapp" }} />,
    );

    expect(html.match(/whatsapp/gi)).toHaveLength(2);
    expect(html).toContain("web.whatsapp.com");
    expect(html).toContain("named in the lab");
  });

  it("shows nothing but the sites when no name is known", () => {
    const html = renderToStaticMarkup(<Services row={row([{ name: null, sites: ["i.golootlo.pk"] }])} />);

    expect(html).not.toContain("<strong>");
    expect(html).toContain("i.golootlo.pk");
  });
});
