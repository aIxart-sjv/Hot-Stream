// Run with `npm test` (Node's built-in runner; Node strips the types itself).
import assert from "node:assert/strict";
import { test } from "node:test";

import {
  bandwidthFor,
  clientStatus,
  describeLimit,
  displayName,
  formatBytes,
  formatClock,
  formatDuration,
  formatIdle,
  formatRate,
  formatRateInput,
  formatSignal,
  isBandwidthLimited,
  parseRateInput,
} from "../src/format.ts";
import type { EnforcementState } from "../src/types.ts";

test("formatBytes shows plain bytes below 1 KiB and binary units above", () => {
  assert.equal(formatBytes(0), "0 B");
  assert.equal(formatBytes(1023), "1023 B");
  assert.equal(formatBytes(1536), "1.5 KB");
  assert.equal(formatBytes(3_095_553), "3.0 MB");
  assert.equal(formatBytes(5 * 1024 ** 3), "5.0 GB");
});

test("formatBytes shows a dash for an unknown value", () => {
  assert.equal(formatBytes(null), "—");
});

test("formatDuration uses the two most significant units", () => {
  assert.equal(formatDuration(0), "0s");
  assert.equal(formatDuration(45), "45s");
  assert.equal(formatDuration(725), "12m 05s");
  assert.equal(formatDuration(3725), "1h 02m");
  assert.equal(formatDuration(97_200), "1d 03h");
  assert.equal(formatDuration(null), "—");
});

test("formatIdle calls a client that just spoke 'active' and otherwise says how long it is quiet", () => {
  assert.equal(formatIdle(13), "active");
  assert.equal(formatIdle(1999), "active");
  assert.equal(formatIdle(2000), "2s");
  assert.equal(formatIdle(125_000), "2m 05s");
  assert.equal(formatIdle(null), "—");
});

test("formatSignal appends the unit and shows a dash when unknown", () => {
  assert.equal(formatSignal(-29), "-29 dBm");
  assert.equal(formatSignal(null), "—");
});

test("displayName prefers the hostname and never invents one", () => {
  assert.equal(displayName({ hostname: "I2304" }), "I2304");
  assert.equal(displayName({ hostname: null }), "Unknown device");
});

test("formatClock renders a unix-ms timestamp as local HH:MM:SS", () => {
  const ms = new Date(2026, 8, 21, 7, 5, 9).getTime();
  assert.equal(formatClock(ms), "07:05:09");
});

// ---- clientStatus: the single source of truth for what a client's row shows ----------------

const MAC = "ce:da:1e:90:d4:aa";
const client = (state: "connected" | "connecting" = "connected") => ({ mac: MAC, state });
const enforcement = (over: Partial<EnforcementState> = {}): EnforcementState => ({
  iface: "wlo1",
  blocked: [],
  admission: null,
  bandwidth: [],
  ...over,
});

test("clientStatus is 'unknown' until enforcement state has been read at least once", () => {
  assert.equal(clientStatus(client(), null), "unknown");
});

test("clientStatus is 'blocked' when the MAC is individually blocked, regardless of anything else", () => {
  assert.equal(clientStatus(client(), enforcement({ blocked: [MAC] })), "blocked");
});

test("clientStatus is 'connecting' for a client still mid-handshake", () => {
  assert.equal(clientStatus(client("connecting"), enforcement()), "connecting");
});

test("clientStatus is 'connected' when no limit is configured and the client is not blocked", () => {
  assert.equal(clientStatus(client(), enforcement()), "connected");
});

test("clientStatus is 'deniedMax' when a limit is configured and the MAC is not in the admitted set", () => {
  const e = enforcement({ admission: { max: 1, admitted: ["be:49:b6:59:5e:1d"] } });
  assert.equal(clientStatus(client(), e), "deniedMax");
});

test("clientStatus is 'connected' when a limit is configured and the MAC IS admitted", () => {
  const e = enforcement({ admission: { max: 2, admitted: [MAC, "be:49:b6:59:5e:1d"] } });
  assert.equal(clientStatus(client(), e), "connected");
});

/// Block always wins over admission — the two policies are independent, and a blocked client
/// must never read as merely "denied by the limit" (which would imply raising the limit, or
/// being higher in admission order, could fix it).
test("clientStatus is 'blocked', never 'deniedMax', when both apply to the same client", () => {
  const e = enforcement({ blocked: [MAC], admission: { max: 1, admitted: [] } });
  assert.equal(clientStatus(client(), e), "blocked");
});

test("a connecting client that would also be denied by the limit still shows as 'connecting'", () => {
  // It isn't usable either way yet, but the reason shown should be the more immediate one.
  const e = enforcement({ admission: { max: 0, admitted: [] } });
  assert.equal(clientStatus(client("connecting"), e), "connecting");
});

// ---- bandwidthFor / formatRate / formatRateInput / parseRateInput / isBandwidthLimited -----

test("bandwidthFor is null (unknown) until enforcement state has been read at least once", () => {
  assert.equal(bandwidthFor(MAC, null), null);
});

test("bandwidthFor reports both directions unrestricted for a client absent from the list", () => {
  const e = enforcement({ bandwidth: [] });
  assert.deepEqual(bandwidthFor(MAC, e), { downloadKbit: null, uploadKbit: null });
});

test("bandwidthFor reports a present client's configured limits, independently per direction", () => {
  const e = enforcement({ bandwidth: [{ mac: MAC, downloadKbit: 5000, uploadKbit: null }] });
  assert.deepEqual(bandwidthFor(MAC, e), { downloadKbit: 5000, uploadKbit: null });
});

test("bandwidthFor never confuses one client's limits with another's", () => {
  const other = "be:49:b6:59:5e:1d";
  const e = enforcement({ bandwidth: [{ mac: other, downloadKbit: 1000, uploadKbit: 2000 }] });
  assert.deepEqual(bandwidthFor(MAC, e), { downloadKbit: null, uploadKbit: null });
});

test("formatRate shows 'unlimited' for null and Mbps otherwise, trimmed of trailing zeros", () => {
  assert.equal(formatRate(null), "unlimited");
  assert.equal(formatRate(5000), "5 Mbps");
  assert.equal(formatRate(512), "0.512 Mbps");
  assert.equal(formatRate(1), "0.001 Mbps");
});

test("formatRateInput is the bare number for an editable field, empty for no limit", () => {
  assert.equal(formatRateInput(null), "");
  assert.equal(formatRateInput(5000), "5");
  assert.equal(formatRateInput(512), "0.512");
});

test("parseRateInput treats an empty field as clearing the limit", () => {
  assert.deepEqual(parseRateInput(""), { valid: true, kbit: null });
  assert.deepEqual(parseRateInput("   "), { valid: true, kbit: null });
});

test("parseRateInput converts a positive Mbps value to rounded kbit", () => {
  assert.deepEqual(parseRateInput("5"), { valid: true, kbit: 5000 });
  assert.deepEqual(parseRateInput("0.512"), { valid: true, kbit: 512 });
});

test("parseRateInput rejects zero, negative and non-numeric input rather than sending nonsense", () => {
  assert.deepEqual(parseRateInput("0"), { valid: false });
  assert.deepEqual(parseRateInput("-5"), { valid: false });
  assert.deepEqual(parseRateInput("abc"), { valid: false });
});

test("isBandwidthLimited is false when unknown, false when both directions are unrestricted, true otherwise", () => {
  assert.equal(isBandwidthLimited(null), false);
  assert.equal(isBandwidthLimited({ downloadKbit: null, uploadKbit: null }), false);
  assert.equal(isBandwidthLimited({ downloadKbit: 5000, uploadKbit: null }), true);
  assert.equal(isBandwidthLimited({ downloadKbit: null, uploadKbit: 1000 }), true);
});

test("describeLimit summarises both directions on one line", () => {
  assert.equal(describeLimit({ downloadKbit: 5000, uploadKbit: null }), "Download 5 Mbps, Upload unlimited");
  assert.equal(describeLimit({ downloadKbit: null, uploadKbit: 512 }), "Download unlimited, Upload 0.512 Mbps");
});
