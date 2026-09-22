// Mirrors src-tauri/src/model.rs. The Rust side has a test that pins these exact JSON names.

export type ClientState = "connected" | "connecting";

export interface Client {
  /** Lower-case colon-separated MAC. This is the client's identity. */
  mac: string;
  state: ClientState;
  /** Optional: absent while the neighbour table has no live entry for this MAC. */
  ip: string | null;
  /** Optional, chosen by the client itself: display as text only. */
  hostname: string | null;
  /** Locally-administered bit set: typically a private/random MAC. */
  locallyAdministered: boolean;
  signalDbm: number | null;
  connectedSecs: number | null;
  /** Time since the access point last heard from this client. */
  inactiveMs: number | null;
  /** Bytes the laptop received from the client. */
  uploadedBytes: number | null;
  /** Bytes the laptop sent to the client. */
  downloadedBytes: number | null;
}

export interface Hotspot {
  interface: string;
  ssid: string | null;
  channel: number | null;
  frequencyMhz: number | null;
  gatewayIp: string | null;
}

export interface HotspotState {
  /** null when no interface is currently serving as an access point. */
  hotspot: Hotspot | null;
  clients: Client[];
  warnings: string[];
  sampledAtMs: number;
}

// Mirrors src-tauri/src/enforce/mod.rs::BlockedState. Deliberately separate from HotspotState:
// discovery (above) and enforcement are independent concerns, merged only when rendering.
export interface BlockedState {
  /** Every currently-blocked MAC, straight from the kernel — never from a cached wish. */
  blocked: string[];
}
