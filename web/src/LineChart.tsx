// A line chart of counts per time step, one line per series: 2px lines, the
// series named at their ends, and a crosshair with the values. Given a
// domain it shows that span of time instead of the series' own, so a chart
// whose domain follows the clock moves with it.
import { useState, type PointerEvent } from "react";
import { count } from "./api";
import { PKT_OFFSET_MS, hourLabel, stamp } from "./time";

export interface Series {
  name: string;
  /** Counts at startMs, startMs + stepMs, …; a shorter line ends earlier. */
  values: number[];
  color: string;
}

const WIDTH = 960;
const MARGIN = { top: 12, right: 84, bottom: 30, left: 48 };
const PLOT_WIDTH = WIDTH - MARGIN.left - MARGIN.right;
// Only one chart is on a screen.
const CLIP_ID = "chart-plot";

/**
 * The count between grid lines: the smallest 1, 2, 2.5 or 5 times a power of
 * ten for which `spaces` of them reach `value`. It is a whole number (25 but
 * not 2.5), so every grid line is a whole count.
 */
function gridStep(value: number, spaces: number): number {
  const needed = Math.max(1, value / spaces);
  const magnitude = 10 ** Math.floor(Math.log10(needed));
  for (const step of [1, 2, 2.5, 5]) {
    if (Number.isInteger(step * magnitude) && step * magnitude >= needed) return step * magnitude;
  }
  return 10 * magnitude;
}

export function LineChart({
  startMs,
  stepMs,
  series,
  yLabel,
  height = 300,
  domain,
  tickEveryMs = 3 * 60 * 60 * 1000,
  tickLabel = hourLabel,
}: {
  startMs: number;
  stepMs: number;
  series: Series[];
  /** What the values count, for screen readers. */
  yLabel: string;
  /** For a drawing 960 wide; it scales with the page's width. */
  height?: number;
  /** The span of time shown, [from, to]; points outside it are cut off. */
  domain?: [number, number];
  /** A time label at each multiple of this, in PKT. */
  tickEveryMs?: number;
  tickLabel?: (ms: number) => string;
}) {
  // Where the pointer is across the plot, from 0 to 1.
  const [hover, setHover] = useState<number | null>(null);
  const steps = Math.max(0, ...series.map((line) => line.values.length));
  if (!steps && !domain) return null;

  const timeAt = (index: number) => startMs + index * stepMs;
  const [from, to] = domain ?? [startMs, timeAt(Math.max(0, steps - 1))];
  const plotHeight = height - MARGIN.top - MARGIN.bottom;
  // At most 3 grid lines on a small chart and 5 on a tall one; the top line
  // is the first at or above the highest count.
  const highest = Math.max(1, ...series.flatMap((line) => line.values));
  const spacing = gridStep(highest, plotHeight < 180 ? 2 : 4);
  const spaces = Math.ceil(highest / spacing);
  const top = spaces * spacing;
  const gridLines = Array.from({ length: spaces + 1 }, (_, index) => index * spacing);
  const x = (ms: number) => MARGIN.left + (to > from ? ((ms - from) / (to - from)) * PLOT_WIDTH : PLOT_WIDTH / 2);
  const y = (value: number) => MARGIN.top + plotHeight - (value / top) * plotHeight;
  const ticks: number[] = [];
  const firstTick = Math.ceil((from + PKT_OFFSET_MS) / tickEveryMs) * tickEveryMs - PKT_OFFSET_MS;
  for (let ms = firstTick; ms <= to; ms += tickEveryMs) ticks.push(ms);
  // Each line's name at its end, while that is in view: the higher line's
  // above it, the lower one's below.
  const ends = series
    .filter((line) => line.values.length && timeAt(line.values.length - 1) >= from)
    .map((line) => ({
      name: line.name,
      ms: timeAt(line.values.length - 1),
      value: line.values[line.values.length - 1],
    }))
    .sort((a, b) => a.value - b.value);
  // The step under the pointer, while it is in view, and the lines that reach it.
  const pointed =
    hover !== null && steps
      ? Math.max(0, Math.min(steps - 1, Math.round((from + hover * (to - from) - startMs) / stepMs)))
      : null;
  const hovered = pointed !== null && timeAt(pointed) >= from && timeAt(pointed) <= to ? pointed : null;
  const reached = hovered === null ? [] : series.filter((line) => hovered < line.values.length);

  function onPointerMove(event: PointerEvent<SVGRectElement>) {
    const box = event.currentTarget.getBoundingClientRect();
    setHover(Math.max(0, Math.min(1, (event.clientX - box.left) / box.width)));
  }

  return (
    <figure className="chart">
      <svg
        viewBox={`0 0 ${WIDTH} ${height}`}
        role="img"
        aria-label={`${yLabel}: ${series.map((line) => line.name).join(" and ")}`}
      >
        {domain && (
          <defs>
            <clipPath id={CLIP_ID}>
              <rect x={MARGIN.left} y={0} width={PLOT_WIDTH} height={height} />
            </clipPath>
          </defs>
        )}
        {gridLines.map((value) => (
          <g key={value}>
            <line className="grid" x1={MARGIN.left} x2={MARGIN.left + PLOT_WIDTH} y1={y(value)} y2={y(value)} />
            <text className="axis" x={MARGIN.left - 8} y={y(value)} textAnchor="end" dominantBaseline="middle">
              {count(value)}
            </text>
          </g>
        ))}
        {ticks.map((ms) => (
          <text key={ms} className="axis" x={x(ms)} y={height - MARGIN.bottom + 20} textAnchor="middle">
            {tickLabel(ms)}
          </text>
        ))}
        <g clipPath={domain ? `url(#${CLIP_ID})` : undefined}>
          {series.map((line) => (
            <path
              key={line.name}
              d={line.values.map((value, index) => `${index ? "L" : "M"}${x(timeAt(index))},${y(value)}`).join("")}
              fill="none"
              strokeWidth={2}
              strokeLinejoin="round"
              style={{ stroke: line.color }}
            />
          ))}
        </g>
        {ends.map((end, position) => (
          <text
            key={end.name}
            className="end-label"
            x={x(end.ms) + 6}
            y={y(end.value) + (position === ends.length - 1 ? -6 : 12)}
          >
            {end.name}
          </text>
        ))}
        {hovered !== null && (
          <>
            <line
              className="crosshair"
              x1={x(timeAt(hovered))}
              x2={x(timeAt(hovered))}
              y1={MARGIN.top}
              y2={MARGIN.top + plotHeight}
            />
            {reached.map((line) => (
              <circle
                key={line.name}
                className="dot"
                cx={x(timeAt(hovered))}
                cy={y(line.values[hovered])}
                r={4}
                style={{ fill: line.color }}
              />
            ))}
          </>
        )}
        <rect
          x={MARGIN.left}
          y={MARGIN.top}
          width={PLOT_WIDTH}
          height={plotHeight}
          fill="transparent"
          onPointerMove={onPointerMove}
          onPointerLeave={() => setHover(null)}
        />
      </svg>
      {hovered !== null && (
        <div
          className="tooltip"
          style={{
            left: `${(x(timeAt(hovered)) / WIDTH) * 100}%`,
            transform: x(timeAt(hovered)) > WIDTH * 0.7 ? "translateX(calc(-100% - 12px))" : "translateX(12px)",
          }}
        >
          <strong>{stamp(timeAt(hovered))}</strong>
          {reached.map((line) => (
            <span key={line.name}>
              <i style={{ background: line.color }} />
              {line.name} {count(line.values[hovered])}
            </span>
          ))}
        </div>
      )}
    </figure>
  );
}
