import { invoke } from "@tauri-apps/api/core";

import {
  displayName,
  formatBytes,
  formatClock,
  formatDuration,
  formatIdle,
  formatSignal,
} from "./format";
import type { BlockedState, Client, HotspotState } from "./types";

const REFRESH_MS = 2000;

interface View {
  /** Last successful reading; kept on screen (marked stale) while readings fail. */
  state: HotspotState | null;
  /** Why the most recent hotspot reading failed, if it did. */
  error: string | null;
  /** Last successful kernel read of the blocked set. Never assume anything is blocked or not
   *  from anywhere else — this field, straight from the helper, is the only source of truth. */
  enforcement: BlockedState | null;
  /** Why the most recent enforcement reading failed (e.g. the helper isn't installed yet). */
  enforcementError: string | null;
  /** MACs with a block/unblock request currently in flight. */
  pending: Set<string>;
  /** The most recent block/unblock failure, shown until the next action or successful poll. */
  actionError: string | null;
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

/** Whether `mac` is blocked, per the kernel — `undefined` while that isn't known yet. */
function isBlocked(enforcement: BlockedState | null, mac: string): boolean | undefined {
  return enforcement ? enforcement.blocked.includes(mac) : undefined;
}

function actionCell(
  client: Client,
  view: View,
  onToggle: (mac: string, block: boolean) => void,
): HTMLTableCellElement {
  const blocked = isBlocked(view.enforcement, client.mac);
  const pending = view.pending.has(client.mac);
  const button = el("button", {
    class: blocked ? "unblock" : "block",
    text: pending ? (blocked ? "Unblocking…" : "Blocking…") : blocked ? "Unblock" : "Block",
  });
  button.disabled = pending || blocked === undefined;
  if (blocked === undefined) {
    button.title = view.enforcementError
      ? "Blocking is unavailable — see the notice above."
      : "Reading enforcement state…";
  }
  button.addEventListener("click", () => onToggle(client.mac, blocked !== true));
  return el("td", { class: "action" }, button);
}

function clientRow(
  c: Client,
  view: View,
  onToggle: (mac: string, block: boolean) => void,
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
  const blocked = isBlocked(view.enforcement, c.mac);
  const stateText = blocked ? "blocked" : c.state;
  return el(
    "tr",
    { class: blocked ? "blocked" : c.state },
    el("td", { class: c.hostname ? "" : "muted", text: displayName(c) }),
    mac,
    el("td", { class: "mono", text: c.ip ?? "—", title: c.ip ? "" : "No live neighbour-table entry for this device yet" }),
    el("td", { text: stateText }),
    el("td", { text: formatSignal(c.signalDbm) }),
    el("td", { text: formatDuration(c.connectedSecs) }),
    el("td", { text: formatIdle(c.inactiveMs), title: "Time since the access point last heard from this device" }),
    el("td", { class: "num", text: formatBytes(c.downloadedBytes), title: "Received by the device (sent by this laptop)" }),
    el("td", { class: "num", text: formatBytes(c.uploadedBytes), title: "Sent by the device (received by this laptop)" }),
    actionCell(c, view, onToggle),
  );
}

function clientTable(
  clients: Client[],
  view: View,
  stale: boolean,
  onToggle: (mac: string, block: boolean) => void,
): HTMLElement {
  const heads = ["Device", "MAC", "IP", "State", "Signal", "Connected", "Idle", "↓ Down", "↑ Up", ""];
  return el(
    "table",
    { class: stale ? "stale" : "" },
    el("thead", {}, el("tr", {}, ...heads.map((h) => el("th", { text: h })))),
    el("tbody", {}, ...clients.map((c) => clientRow(c, view, onToggle))),
  );
}

function render(root: HTMLElement, view: View, onToggle: (mac: string, block: boolean) => void): void {
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
    const blockedCount = view.enforcement
      ? state.clients.filter((c) => isBlocked(view.enforcement, c.mac)).length
      : 0;
    const heading = blockedCount > 0 ? `Connected devices: ${connected} (${blockedCount} blocked)` : `Connected devices: ${connected}`;
    nodes.push(hotspotInfo(state), el("h2", { text: heading }));
    nodes.push(
      state.clients.length === 0
        ? el("p", { class: "muted", text: "No devices are connected to the hotspot." })
        : clientTable(state.clients, view, error !== null, onToggle),
    );
  }

  if (state) nodes.push(el("footer", { text: `Updated ${formatClock(state.sampledAtMs)}` }));
  root.replaceChildren(...nodes.filter((n): n is Node => n !== null));
}

async function refreshLoop(root: HTMLElement): Promise<never> {
  const view: View = {
    state: null,
    error: null,
    enforcement: null,
    enforcementError: null,
    pending: new Set(),
    actionError: null,
  };

  const rerender = () => render(root, view, onToggle);

  const onToggle = async (mac: string, block: boolean): Promise<void> => {
    view.pending.add(mac);
    view.actionError = null;
    rerender();
    try {
      view.enforcement = await invoke<BlockedState>(block ? "block_client" : "unblock_client", { mac });
      view.enforcementError = null;
    } catch (e) {
      view.actionError = `Could not ${block ? "block" : "unblock"} ${mac}: ${String(e)}`;
    } finally {
      view.pending.delete(mac);
      rerender();
    }
  };

  for (;;) {
    try {
      view.state = await invoke<HotspotState>("get_hotspot_state");
      view.error = null;
    } catch (e) {
      view.error = String(e);
    }
    try {
      view.enforcement = await invoke<BlockedState>("get_enforcement_state");
      view.enforcementError = null;
    } catch (e) {
      view.enforcementError = String(e);
    }
    rerender();
    await new Promise((resolve) => setTimeout(resolve, REFRESH_MS));
  }
}

const root = document.getElementById("app");
if (!root) throw new Error("#app element missing from index.html");
void refreshLoop(root);
