// A section that shows only its heading until it is opened, and stays as it
// was left in this browser. What it holds is only drawn (and only asks the
// API) while it is open.
import type { ReactNode } from "react";
import { useRemembered } from "./api";

export function Fold({ id, title, note, children }: { id: string; title: string; note?: string; children: ReactNode }) {
  const [open, setOpen] = useRemembered(`ids-fold-${id}`, false, [true, false]);
  return (
    <section className="fold">
      <h2 className="fold-head">
        <button type="button" aria-expanded={open} onClick={() => setOpen(!open)}>
          <span className="chevron" aria-hidden="true">
            {open ? "▾" : "▸"}
          </span>
          {title}
        </button>
        {note && <span className="muted">{note}</span>}
      </h2>
      {open && children}
    </section>
  );
}
