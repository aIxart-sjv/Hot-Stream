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

// Mirrors src-tauri/src/enforce/mod.rs::EnforcementState. Deliberately separate from
// HotspotState: discovery (above) and enforcement are independent concerns, merged only when
// rendering.
export interface EnforcementState {
  /** The interface the block/admission policies are currently scoped to, per the kernel.
   *  `null` when nothing has ever been configured. */
  iface: string | null;
  /** Every currently-blocked MAC, straight from the kernel — never from a cached wish. */
  blocked: string[];
  /** `null` when no maximum-clients limit is configured at all (not the same as admitting
   *  nobody — that would be a `max` of some positive number with an empty `admitted` list). */
  admission: Admission | null;
  /** Every client with at least one direction currently bandwidth-limited, straight from the
   *  kernel. Absence from this list means fully unrestricted, not "unknown" — see `format.ts`'s
   *  `bandwidthFor`. Only ever populated when the read that produced this state was given the
   *  hotspot's current interface (see `enforce::shaping` on the Rust side for why). */
  bandwidth: BandwidthLimit[];
}

export interface Admission {
  max: number;
  /** Every currently-admitted MAC, straight from the kernel. */
  admitted: string[];
}

export interface BandwidthLimit {
  mac: string;
  /** Kilobits/second. `null` means that direction is unrestricted for this client. */
  downloadKbit: number | null;
  uploadKbit: number | null;
}
