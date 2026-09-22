// Display helpers. Pure functions, so they can be tested without a browser.

import type { BandwidthLimit, EnforcementState } from "./types";

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

export type ClientStatus = "unknown" | "blocked" | "connecting" | "deniedMax" | "connected";

/**
 * The single source of truth for what a client row shows, and the only place that combines
 * discovery's raw connection state with both enforcement policies. Priority, most to least
 * immediate: individual block always wins (never "just" denied by the limit — that would
 * wrongly imply raising the limit could fix it); then whether the client has even finished
 * associating; then the max-clients limit; otherwise the client is fully usable.
 */
export function clientStatus(
  client: { mac: string; state: "connected" | "connecting" },
  enforcement: EnforcementState | null,
): ClientStatus {
  if (enforcement === null) return "unknown";
  if (enforcement.blocked.includes(client.mac)) return "blocked";
  if (client.state === "connecting") return "connecting";
  if (enforcement.admission !== null && !enforcement.admission.admitted.includes(client.mac)) return "deniedMax";
  return "connected";
}

/** A client's configured bandwidth limits, looked up from the flat kernel-reported list.
 *  `null` means "not known yet" (enforcement hasn't been read at all) — distinct from a client
 *  present in `enforcement` with no entry, which means "known to be fully unrestricted". Never
 *  invent a limit that was not actually read from the kernel. */
export function bandwidthFor(
  mac: string,
  enforcement: EnforcementState | null,
): { downloadKbit: number | null; uploadKbit: number | null } | null {
  if (enforcement === null) return null;
  const entry = enforcement.bandwidth.find((b) => b.mac === mac);
  return { downloadKbit: entry?.downloadKbit ?? null, uploadKbit: entry?.uploadKbit ?? null };
}

/** A kbit/s value as Mbps for display, trimmed of trailing zeros (`512` → "0.512 Mbps"); `null`
 *  (no limit in that direction) reads as "unlimited". */
export function formatRate(kbit: number | null): string {
  if (kbit === null) return "unlimited";
  return `${Number((kbit / 1000).toFixed(3))} Mbps`;
}

/** Same value, without a hard-coded fallback string — for feeding into an editable input's
 *  placeholder/value, where the caller decides what "no limit" should look like. */
export function formatRateInput(kbit: number | null): string {
  return kbit === null ? "" : `${Number((kbit / 1000).toFixed(3))}`;
}

/** Parses a Mbps-denominated text field into kbit/s. Empty means "unrestricted" (clears the
 *  limit); anything else must be a finite positive number, decimals allowed (e.g. "0.512" for
 *  512 Kbps) — mirrors `main.ts`'s `parseMaxInput` for the same "leave it alone rather than
 *  send something nonsensical" reasoning. */
export function parseRateInput(text: string): { valid: true; kbit: number | null } | { valid: false } {
  const trimmed = text.trim();
  if (trimmed === "") return { valid: true, kbit: null };
  const n = Number(trimmed);
  return Number.isFinite(n) && n > 0 ? { valid: true, kbit: Math.round(n * 1000) } : { valid: false };
}

/** Whether a client currently has any bandwidth restriction at all, in either direction — used
 *  to decide whether its row gets a visual marker, the same way `clientStatus` decides a whole
 *  row's class. */
export function isBandwidthLimited(limit: BandwidthLimit | { downloadKbit: number | null; uploadKbit: number | null } | null): boolean {
  return limit !== null && (limit.downloadKbit !== null || limit.uploadKbit !== null);
}

/** One line summarising both directions, for a "limited" badge's tooltip — e.g. "Download 5
 *  Mbps, Upload unlimited". */
export function describeLimit(limit: { downloadKbit: number | null; uploadKbit: number | null }): string {
  return `Download ${formatRate(limit.downloadKbit)}, Upload ${formatRate(limit.uploadKbit)}`;
}
