import { invoke } from "@tauri-apps/api/core";

import {
  bandwidthFor,
  clientStatus,
  describeLimit,
  displayName,
  formatBytes,
  formatClock,
  formatDuration,
  formatIdle,
  formatRateInput,
  formatSignal,
  isBandwidthLimited,
  parseRateInput,
} from "./format";
import type { Client, EnforcementState, HotspotState } from "./types";

const REFRESH_MS = 2000;

const EMPTY_BANDWIDTH_ENTRY = { download: "", downloadTouched: false, upload: "", uploadTouched: false };

interface View {
  /** Last successful reading; kept on screen (marked stale) while readings fail. */
  state: HotspotState | null;
  /** Why the most recent hotspot reading failed, if it did. */
  error: string | null;
  /** Last successful kernel read of block + admission state. Never assume anything about a
   *  client from anywhere else — this field, straight from the helper, is the only source of
   *  truth for both policies. */
  enforcement: EnforcementState | null;
  /** Why the most recent enforcement reading failed (e.g. the helper isn't installed yet). */
  enforcementError: string | null;
  /** MACs with a block/unblock request currently in flight. */
  pending: Set<string>;
  /** Set while a maximum-devices change (explicit or automatic reconciliation) is in flight. */
  admissionPending: boolean;
  /** The most recent block/unblock/admission-change failure, shown until the next action or
   *  successful poll. */
  actionError: string | null;
  /** What the "Maximum devices" field currently shows, kept separate from the kernel-reported
   *  value so typing in it doesn't get overwritten mid-edit by the next poll. */
  maxInputText: string;
  /** True from the moment the user types into the field until the next successful apply.
   *  While true, the poll loop never touches `maxInputText`, full stop — checking whether the
   *  *current* text still parses as a valid number is not enough: real-hotspot testing showed
   *  that a perfectly valid in-progress number (e.g. typing "2" of an intended "20") still gets
   *  silently overwritten by the kernel's stale value on the next 2-second poll, which lands
   *  mid-keystroke often enough to make the field feel unusable. */
  maxInputTouched: boolean;
  /** What each client's download/upload limit fields currently show, keyed by MAC, plus
   *  whether each field has been typed into since its last successful apply — same "touched"
   *  reasoning as `maxInputTouched`, tracked per field since download and upload are set
   *  independently. */
  bandwidthInputText: Record<string, { download: string; downloadTouched: boolean; upload: string; uploadTouched: boolean }>;
  /** MACs with a bandwidth-limit change currently in flight. */
  bandwidthPending: Set<string>;
}

// Everything dynamic goes through textContent: hostnames are chosen by the clients
// themselves and must never be interpreted as markup.
function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props: { class?: string; text?: string; title?: string } = {},
  ...children: (Node | string)[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (props.class) node.className = props.class;
  if (props.text !== undefined) node.textContent = props.text;
  if (props.title) node.title = props.title;
  node.append(...children);
  return node;
}

function headerRow(state: HotspotState | null): HTMLElement {
  const status =
    state === null
      ? el("span", { class: "pill", text: "…" })
      : state.hotspot
        ? el("span", { class: "pill on", text: "● HOTSPOT ON" })
        : el("span", { class: "pill off", text: "○ HOTSPOT OFF" });
  return el("header", {}, el("h1", { text: "HOT-STREAM" }), status);
}

function hotspotInfo(state: HotspotState): HTMLElement | null {
  const h = state.hotspot;
  if (!h) return null;
  const parts = [
    `Interface ${h.interface}`,
    `SSID ${h.ssid ?? "unknown"}`,
    h.channel !== null
      ? `Channel ${h.channel}${h.frequencyMhz !== null ? ` (${h.frequencyMhz} MHz)` : ""}`
      : null,
    h.gatewayIp ? `Gateway ${h.gatewayIp}` : null,
  ].filter((p): p is string => p !== null);
  return el("p", { class: "info", text: parts.join("  ·  ") });
}

/** The "Maximum devices" input + Apply button + a summary of the kernel's current admission
 *  state. Minimum UI for M3: one row, no separate "clear" control (an empty field + Apply
 *  clears the limit — the placeholder says so). */
function admissionControls(
  view: View,
  onInput: (text: string) => void,
  onApply: () => void,
): HTMLElement {
  const admission = view.enforcement?.admission ?? null;
  const input = el("input", { class: "max-input", title: "Empty = unlimited" });
  input.type = "number";
  input.min = "1";
  input.step = "1";
  input.placeholder = "unlimited";
  input.value = view.maxInputText;
  input.disabled = view.admissionPending;
  input.addEventListener("input", () => onInput(input.value));

  const applyBtn = el("button", { class: "apply-max", text: view.admissionPending ? "Applying…" : "Apply" });
  applyBtn.disabled = view.admissionPending;
  applyBtn.addEventListener("click", onApply);

  const summary = admission
    ? el("span", { class: "muted", text: `Admitted ${admission.admitted.length}/${admission.max}` })
    : el("span", { class: "muted", text: "No limit configured" });

  return el(
    "div",
    { class: "admission" },
    el("label", { text: "Maximum devices:" }),
    input,
    applyBtn,
    summary,
  );
}

const STATUS_LABEL: Record<ReturnType<typeof clientStatus>, string> = {
  unknown: "…",
  blocked: "blocked",
  connecting: "connecting",
  deniedMax: "denied (max)",
  connected: "connected",
};

function actionCell(
  client: Client,
  view: View,
  onToggle: (mac: string, block: boolean) => void,
): HTMLTableCellElement {
  const status = clientStatus(client, view.enforcement);
  const blocked = status === "blocked";
  const pending = view.pending.has(client.mac);
  const unavailable = view.enforcement === null;
  const button = el("button", {
    class: blocked ? "unblock" : "block",
    text: pending ? (blocked ? "Unblocking…" : "Blocking…") : blocked ? "Unblock" : "Block",
  });
  button.disabled = pending || unavailable;
  if (unavailable) {
    button.title = view.enforcementError
      ? "Blocking is unavailable — see the notice above."
      : "Reading enforcement state…";
  }
  button.addEventListener("click", () => onToggle(client.mac, !blocked));
  return el("td", { class: "action" }, button);
}

/** Two small Mbps inputs (download / upload) + one Apply button + the current configured
 *  values. Minimum UI for M4, same shape as `admissionControls`: no separate "clear" control —
 *  an empty field + Apply clears that direction's limit. */
function bandwidthCell(
  c: Client,
  view: View,
  onInput: (mac: string, direction: "download" | "upload", text: string) => void,
  onApply: (mac: string) => void,
): HTMLTableCellElement {
  const limit = bandwidthFor(c.mac, view.enforcement);
  const text = view.bandwidthInputText[c.mac] ?? EMPTY_BANDWIDTH_ENTRY;
  const pending = view.bandwidthPending.has(c.mac);
  const unavailable = view.enforcement === null;

  const unavailableTitle = view.enforcementError
    ? "Bandwidth limits are unavailable — see the notice above."
    : "Reading enforcement state…";

  const field = (direction: "download" | "upload", value: string, label: string): HTMLInputElement => {
    const input = el("input", {
      class: "rate-input",
      title: unavailable ? unavailableTitle : `${label}, Mbps — empty = unlimited`,
    });
    input.type = "number";
    input.min = "0";
    input.step = "any";
    input.placeholder = "∞";
    input.value = value;
    input.disabled = pending || unavailable;
    input.addEventListener("input", () => onInput(c.mac, direction, input.value));
    return input;
  };

  const applyBtn = el("button", { class: "apply-rate", text: pending ? "…" : "Set" });
  applyBtn.disabled = pending || unavailable;
  if (unavailable) applyBtn.title = unavailableTitle;
  applyBtn.addEventListener("click", () => onApply(c.mac));

  const children: (Node | string)[] = [
    el("span", { class: "rate-label", text: "↓" }),
    field("download", text.download, "Download"),
    el("span", { class: "rate-label", text: "↑" }),
    field("upload", text.upload, "Upload"),
    applyBtn,
  ];
  if (limit === null) {
    children.push(el("span", { class: "muted", text: " …" }));
  } else if (!isBandwidthLimited(limit)) {
    children.push(el("span", { class: "muted", text: " unlimited" }));
  }

  return el("td", { class: "bandwidth" }, ...children);
}

function clientRow(
  c: Client,
  view: View,
  onToggle: (mac: string, block: boolean) => void,
  onBandwidthInput: (mac: string, direction: "download" | "upload", text: string) => void,
  onApplyBandwidth: (mac: string) => void,
): HTMLTableRowElement {
  const mac = el("td", { class: "mono" }, c.mac);
  if (c.locallyAdministered) {
    mac.append(
      " ",
      el("span", {
        class: "badge",
        text: "private",
        title: "Locally administered MAC address (typically a phone's private/random address)",
      }),
    );
  }
  const status = clientStatus(c, view.enforcement);
  const limit = bandwidthFor(c.mac, view.enforcement);
  const limited = isBandwidthLimited(limit);
  const stateCell = el("td", { text: STATUS_LABEL[status] });
  if (limited && limit) {
    stateCell.append(" ", el("span", { class: "badge limited", text: "limited", title: describeLimit(limit) }));
  }
  return el(
    "tr",
    { class: limited ? `${status} limited` : status },
    el("td", { class: c.hostname ? "" : "muted", text: displayName(c) }),
    mac,
    el("td", { class: "mono", text: c.ip ?? "—", title: c.ip ? "" : "No live neighbour-table entry for this device yet" }),
    stateCell,
    el("td", { text: formatSignal(c.signalDbm) }),
    el("td", { text: formatDuration(c.connectedSecs) }),
    el("td", { text: formatIdle(c.inactiveMs), title: "Time since the access point last heard from this device" }),
    el("td", { class: "num", text: formatBytes(c.downloadedBytes), title: "Received by the device (sent by this laptop)" }),
    el("td", { class: "num", text: formatBytes(c.uploadedBytes), title: "Sent by the device (received by this laptop)" }),
    bandwidthCell(c, view, onBandwidthInput, onApplyBandwidth),
    actionCell(c, view, onToggle),
  );
}

function clientTable(
  clients: Client[],
  view: View,
  stale: boolean,
  onToggle: (mac: string, block: boolean) => void,
  onBandwidthInput: (mac: string, direction: "download" | "upload", text: string) => void,
  onApplyBandwidth: (mac: string) => void,
): HTMLElement {
  const heads = ["Device", "MAC", "IP", "State", "Signal", "Connected", "Idle", "↓ Down", "↑ Up", "Limit (Mbps)", ""];
  return el(
    "table",
    { class: stale ? "stale" : "" },
    el("thead", {}, el("tr", {}, ...heads.map((h) => el("th", { text: h })))),
    el("tbody", {}, ...clients.map((c) => clientRow(c, view, onToggle, onBandwidthInput, onApplyBandwidth))),
  );
}

function render(
  root: HTMLElement,
  view: View,
  onToggle: (mac: string, block: boolean) => void,
  onMaxInput: (text: string) => void,
  onApplyMax: () => void,
  onBandwidthInput: (mac: string, direction: "download" | "upload", text: string) => void,
  onApplyBandwidth: (mac: string) => void,
): void {
  const { state, error } = view;
  const nodes: (Node | null)[] = [headerRow(state)];

  if (error) {
    const since = state ? ` Showing the last good reading from ${formatClock(state.sampledAtMs)}.` : "";
    const alert = el("div", { class: "alert", text: `Could not read hotspot state: ${error}.${since}` });
    alert.setAttribute("role", "alert");
    nodes.push(alert);
  }
  for (const w of state?.warnings ?? []) nodes.push(el("div", { class: "warn", text: w }));
  if (view.enforcementError) {
    nodes.push(el("div", { class: "warn", text: `Blocking is unavailable: ${view.enforcementError}` }));
  }
  if (view.actionError) {
    const note = el("div", { class: "warn", text: view.actionError });
    note.setAttribute("role", "alert");
    nodes.push(note);
  }

  if (state === null) {
    if (!error) nodes.push(el("p", { class: "muted", text: "Reading hotspot state…" }));
  } else if (!state.hotspot) {
    nodes.push(
      el("p", { class: "empty", text: "The hotspot is not running." }),
      el("p", {
        class: "muted",
        text: "No Wi-Fi interface is in access-point mode. Start the hotspot to see the devices using it.",
      }),
    );
  } else {
    const connected = state.clients.filter((c) => c.state === "connected").length;
    const blockedCount = state.clients.filter((c) => clientStatus(c, view.enforcement) === "blocked").length;
    const usableCount = state.clients.filter((c) => clientStatus(c, view.enforcement) === "connected").length;
    const detail = [view.enforcement && `${usableCount} usable`, blockedCount > 0 && `${blockedCount} blocked`]
      .filter((p): p is string => Boolean(p))
      .join(", ");
    const heading = `Connected devices: ${connected}${detail ? ` (${detail})` : ""}`;
    nodes.push(hotspotInfo(state), el("h2", { text: heading }), admissionControls(view, onMaxInput, onApplyMax));
    nodes.push(
      state.clients.length === 0
        ? el("p", { class: "muted", text: "No devices are connected to the hotspot." })
        : clientTable(state.clients, view, error !== null, onToggle, onBandwidthInput, onApplyBandwidth),
    );
  }

  if (state) nodes.push(el("footer", { text: `Updated ${formatClock(state.sampledAtMs)}` }));
  root.replaceChildren(...nodes.filter((n): n is Node => n !== null));
}

/** Are `desired` and `current` the same set of MACs? (order-insensitive; both are already
 *  duplicate-free — `current` from the kernel, `desired` from a `slice` of the client list.) */
function sameMacSet(desired: string[], current: string[]): boolean {
  return desired.length === current.length && desired.every((m) => current.includes(m));
}

async function refreshLoop(root: HTMLElement): Promise<never> {
  const view: View = {
    state: null,
    error: null,
    enforcement: null,
    enforcementError: null,
    pending: new Set(),
    admissionPending: false,
    actionError: null,
    maxInputText: "",
    maxInputTouched: false,
    bandwidthInputText: {},
    bandwidthPending: new Set(),
  };

  const rerender = () => render(root, view, onToggle, onMaxInput, onApplyMax, onBandwidthInput, onApplyBandwidth);

  const onToggle = async (mac: string, block: boolean): Promise<void> => {
    const iface = view.state?.hotspot?.interface;
    if (!iface) return; // no hotspot to scope the rule to right now
    view.pending.add(mac);
    view.actionError = null;
    rerender();
    try {
      view.enforcement = await invoke<EnforcementState>(block ? "block_client" : "unblock_client", { iface, mac });
      view.enforcementError = null;
    } catch (e) {
      view.actionError = `Could not ${block ? "block" : "unblock"} ${mac}: ${String(e)}`;
    } finally {
      view.pending.delete(mac);
      rerender();
    }
  };

  const onMaxInput = (text: string): void => {
    view.maxInputText = text;
    view.maxInputTouched = true;
    rerender();
  };

  /** Parses the input field: empty = clear the limit, otherwise a positive integer. Anything
   *  else (negative, zero, not a number) is treated as "leave it alone" — the Apply button
   *  simply does nothing rather than silently sending a nonsensical value. */
  const parseMaxInput = (): { valid: true; max: number | null } | { valid: false } => {
    const text = view.maxInputText.trim();
    if (text === "") return { valid: true, max: null };
    const n = Number(text);
    return Number.isInteger(n) && n >= 1 ? { valid: true, max: n } : { valid: false };
  };

  /** `manual`: whether *this* call is the direct result of the user clicking Apply, as opposed
   *  to the automatic reconciliation below (same `max`, just re-syncing admitted members after
   *  clients joined/left). Only a manual apply releases `maxInputText` back to kernel-driven
   *  sync — otherwise, a reconciliation racing an in-progress edit of a *different* number
   *  would stomp it with the (unchanged) old max, reintroducing the same clobbering bug this
   *  whole `touched` mechanism exists to prevent. */
  const applyAdmission = async (max: number | null, macsOldestFirst: string[], iface: string, manual: boolean): Promise<void> => {
    view.admissionPending = true;
    rerender();
    try {
      view.enforcement = await invoke<EnforcementState>("set_admission", {
        iface,
        max,
        connectedMacsOldestFirst: macsOldestFirst,
      });
      view.enforcementError = null;
      if (manual) {
        view.maxInputText = max === null ? "" : String(max);
        view.maxInputTouched = false;
      }
    } catch (e) {
      view.actionError = `Could not set the maximum: ${String(e)}`;
    } finally {
      view.admissionPending = false;
      rerender();
    }
  };

  const onApplyMax = (): void => {
    const iface = view.state?.hotspot?.interface;
    const parsed = parseMaxInput();
    if (!iface || !parsed.valid) return;
    void applyAdmission(parsed.max, view.state?.clients.map((c) => c.mac) ?? [], iface, true);
  };

  const onBandwidthInput = (mac: string, direction: "download" | "upload", text: string): void => {
    const current = view.bandwidthInputText[mac] ?? EMPTY_BANDWIDTH_ENTRY;
    view.bandwidthInputText[mac] =
      direction === "download" ? { ...current, download: text, downloadTouched: true } : { ...current, upload: text, uploadTouched: true };
    rerender();
  };

  const applyBandwidth = async (mac: string, iface: string, downloadKbit: number | null, uploadKbit: number | null): Promise<void> => {
    view.bandwidthPending.add(mac);
    view.actionError = null;
    rerender();
    try {
      view.enforcement = await invoke<EnforcementState>("set_bandwidth", { iface, mac, downloadKbit, uploadKbit });
      view.enforcementError = null;
      // Bandwidth limits have no automatic-reconciliation counterpart (unlike admission) — every
      // apply is user-initiated, so it's always safe to release these fields back to
      // kernel-driven sync immediately, showing the just-applied values with no flicker.
      const limit = bandwidthFor(mac, view.enforcement);
      view.bandwidthInputText[mac] = {
        download: formatRateInput(limit?.downloadKbit ?? null),
        downloadTouched: false,
        upload: formatRateInput(limit?.uploadKbit ?? null),
        uploadTouched: false,
      };
    } catch (e) {
      view.actionError = `Could not set the bandwidth limit for ${mac}: ${String(e)}`;
    } finally {
      view.bandwidthPending.delete(mac);
      rerender();
    }
  };

  const onApplyBandwidth = (mac: string): void => {
    const iface = view.state?.hotspot?.interface;
    const text = view.bandwidthInputText[mac] ?? EMPTY_BANDWIDTH_ENTRY;
    const download = parseRateInput(text.download);
    const upload = parseRateInput(text.upload);
    if (!iface || !download.valid || !upload.valid) return;
    void applyBandwidth(mac, iface, download.kbit, upload.kbit);
  };

  for (;;) {
    try {
      view.state = await invoke<HotspotState>("get_hotspot_state");
      view.error = null;
    } catch (e) {
      view.error = String(e);
    }
    try {
      view.enforcement = await invoke<EnforcementState>("get_enforcement_state", {
        iface: view.state?.hotspot?.interface ?? null,
      });
      view.enforcementError = null;
      // Keep each input field showing the kernel's own value, but *only* while the user hasn't
      // typed into it since the last successful apply — see `bandwidthInputText`'s doc comment
      // for why "does the current text still parse" turned out not to be a strong enough guard.
      // Re-keyed to the current client list so a disconnected device's leftover edit doesn't
      // linger forever.
      const nextBandwidthText: View["bandwidthInputText"] = {};
      for (const c of view.state?.clients ?? []) {
        const limit = bandwidthFor(c.mac, view.enforcement);
        const existing = view.bandwidthInputText[c.mac] ?? EMPTY_BANDWIDTH_ENTRY;
        nextBandwidthText[c.mac] = {
          download: existing.downloadTouched ? existing.download : formatRateInput(limit?.downloadKbit ?? null),
          downloadTouched: existing.downloadTouched,
          upload: existing.uploadTouched ? existing.upload : formatRateInput(limit?.uploadKbit ?? null),
          uploadTouched: existing.uploadTouched,
        };
      }
      view.bandwidthInputText = nextBandwidthText;
      // Same rule as above, for the "Maximum devices" field.
      if (!view.maxInputTouched) view.maxInputText = view.enforcement.admission ? String(view.enforcement.admission.max) : "";
    } catch (e) {
      view.enforcementError = String(e);
    }

    // Automatic reconciliation: a limit is configured and clients may have joined/left since
    // it was last applied — bring the admitted set back in line with the current client list,
    // same limit, without waiting for the user to touch anything. Skipped when nothing would
    // actually change, so a steady-state hotspot isn't rewriting kernel rules every 2 seconds.
    const admission = view.enforcement?.admission;
    const iface = view.state?.hotspot?.interface;
    if (admission && iface && view.state && !view.admissionPending) {
      const macsOldestFirst = view.state.clients.map((c) => c.mac);
      const desired = macsOldestFirst.slice(0, admission.max);
      if (!sameMacSet(desired, admission.admitted)) {
        await applyAdmission(admission.max, macsOldestFirst, iface, false);
      }
    }

    rerender();
    await new Promise((resolve) => setTimeout(resolve, REFRESH_MS));
  }
}

const root = document.getElementById("app");
if (!root) throw new Error("#app element missing from index.html");
void refreshLoop(root);
