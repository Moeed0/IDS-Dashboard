import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { coloured } from "./JsonPopup";

describe("coloured", () => {
  it("wraps keys, strings, numbers and literals, and keeps the text as it was", () => {
    const text = '{\n  "severity": "Low",\n  "port": 53,\n  "ok": true,\n  "x": null\n}';
    const html = renderToStaticMarkup(<pre>{coloured(text)}</pre>);
    expect(html).toContain('<span class="json-key">&quot;severity&quot;</span>: <span class="json-string">&quot;Low&quot;</span>');
    expect(html).toContain('<span class="json-number">53</span>');
    expect(html).toContain('<span class="json-literal">true</span>');
    expect(html).toContain('<span class="json-literal">null</span>');
    const plain = html.replace(/<[^>]+>/g, "").replace(/&quot;/g, '"');
    expect(plain).toBe(text);
  });

  it("does not colour digits inside a string", () => {
    const html = renderToStaticMarkup(<pre>{coloured('{"rule": "1:2001119:6"}')}</pre>);
    expect(html).not.toContain("json-number");
  });
});
