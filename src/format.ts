// Display helpers. Pure functions, so they can be tested without a browser.

const UNKNOWN = "—";

const pad2 = (n: number): string => String(n).padStart(2, "0");

export function formatBytes(bytes: number | null): string {
  if (bytes === null) return UNKNOWN;
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(1)} ${units[unit]}`;
}

/** Two most significant units: "45s", "12m 05s", "1h 02m", "1d 03h". */
export function formatDuration(seconds: number | null): string {
  if (seconds === null) return UNKNOWN;
  const d = Math.floor(seconds / 86_400);
  const h = Math.floor((seconds % 86_400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.floor(seconds % 60);
  if (d > 0) return `${d}d ${pad2(h)}h`;
  if (h > 0) return `${h}h ${pad2(m)}m`;
  if (m > 0) return `${m}m ${pad2(s)}s`;
  return `${s}s`;
}

/** How long the access point has not heard from a client. */
export function formatIdle(inactiveMs: number | null): string {
  if (inactiveMs === null) return UNKNOWN;
  if (inactiveMs < 2000) return "active";
  return formatDuration(Math.floor(inactiveMs / 1000));
}

export function formatSignal(dbm: number | null): string {
  return dbm === null ? UNKNOWN : `${dbm} dBm`;
}

/** A hostname is optional; never invent one. */
export function displayName(client: { hostname: string | null }): string {
  return client.hostname ?? "Unknown device";
}

/** Local HH:MM:SS for a unix-millisecond timestamp. */
export function formatClock(unixMs: number): string {
  const t = new Date(unixMs);
  return `${pad2(t.getHours())}:${pad2(t.getMinutes())}:${pad2(t.getSeconds())}`;
}
