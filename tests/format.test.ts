// Run with `npm test` (Node's built-in runner; Node strips the types itself).
import assert from "node:assert/strict";
import { test } from "node:test";

import {
  displayName,
  formatBytes,
  formatClock,
  formatDuration,
  formatIdle,
  formatSignal,
} from "../src/format.ts";

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
