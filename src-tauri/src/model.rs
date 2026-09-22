//! Types shared by discovery, the (future) enforcement layer and the UI.
//!
//! Identity rule: a client *is* its MAC address. IP address and hostname are optional
//! attributes that can be missing or stale; they never decide whether a client is connected.

use serde::Serialize;

/// Lower-case, colon-separated MAC address, e.g. `ce:da:1e:90:d4:aa`.
pub type Mac = String;

/// Canonical form of a MAC address (`aa:bb:cc:dd:ee:ff`, lower-case), or `None` if `raw`
/// is not exactly six colon-separated two-digit hex octets.
pub fn normalize_mac(raw: &str) -> Option<Mac> {
    let mut octets = raw.split(':');
    let mut out = String::with_capacity(17);
    for i in 0..6 {
        let octet = octets.next()?;
        if octet.len() != 2 || !octet.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        if i > 0 {
            out.push(':');
        }
        out.push_str(&octet.to_ascii_lowercase());
    }
    if octets.next().is_some() {
        return None;
    }
    Some(out)
}

/// True when the "locally administered" bit is set, i.e. the address was not burned in by a
/// manufacturer. Phones use such addresses when "private/random MAC" is enabled.
pub fn is_locally_administered(mac: &str) -> bool {
    normalize_mac(mac)
        .and_then(|m| u8::from_str_radix(&m[..2], 16).ok())
        .is_some_and(|first_octet| first_octet & 0x02 != 0)
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HotspotState {
    /// `None` when no interface is currently serving as an access point.
    pub hotspot: Option<Hotspot>,
    pub clients: Vec<Client>,
    /// Non-fatal oddities the user should know about (e.g. several AP interfaces).
    pub warnings: Vec<String>,
    /// Unix time in milliseconds at which this snapshot was taken.
    pub sampled_at_ms: u64,
}

impl HotspotState {
    pub fn not_running(sampled_at_ms: u64) -> Self {
        Self { hotspot: None, clients: Vec::new(), warnings: Vec::new(), sampled_at_ms }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Hotspot {
    pub interface: String,
    pub ssid: Option<String>,
    pub channel: Option<u32>,
    pub frequency_mhz: Option<u32>,
    /// The laptop's own IPv4 address on the hotspot subnet (the clients' gateway).
    pub gateway_ip: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ClientState {
    /// Associated and authorised: allowed to pass traffic.
    Connected,
    /// Associated but not (yet) authorised, e.g. mid WPA handshake.
    Connecting,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Client {
    pub mac: Mac,
    pub state: ClientState,
    pub ip: Option<String>,
    pub hostname: Option<String>,
    /// MAC has the locally-administered bit set (typically a private/random address).
    pub locally_administered: bool,
    pub signal_dbm: Option<i32>,
    pub connected_secs: Option<u64>,
    /// Time since the access point last heard from this client.
    pub inactive_ms: Option<u64>,
    /// Bytes the laptop received FROM the client (the client's upload; `iw` "rx bytes").
    pub uploaded_bytes: Option<u64>,
    /// Bytes the laptop sent TO the client (the client's download; `iw` "tx bytes").
    pub downloaded_bytes: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_mac_lowercases_a_valid_address() {
        assert_eq!(normalize_mac("CE:DA:1E:90:D4:AA").as_deref(), Some("ce:da:1e:90:d4:aa"));
    }

    #[test]
    fn normalize_mac_rejects_anything_that_is_not_six_two_digit_octets() {
        for bad in [
            "",
            "ce:da:1e:90:d4",
            "ce:da:1e:90:d4:aa:bb",
            "zz:da:1e:90:d4:aa",
            "ce:da:1e:90:d4:a",
            "ceda1e90d4aa",
            "ce-da-1e-90-d4-aa",
        ] {
            assert_eq!(normalize_mac(bad), None, "{bad:?} must be rejected");
        }
    }

    #[test]
    fn locally_administered_bit_is_read_from_the_first_octet() {
        assert!(is_locally_administered("ce:da:1e:90:d4:aa")); // 0xce has bit 0x02 set
        assert!(is_locally_administered("02:00:00:00:00:01"));
        assert!(!is_locally_administered("e8:b0:c5:16:67:e1")); // 0xe8 does not
        assert!(!is_locally_administered("not a mac"));
    }

    #[test]
    fn not_running_state_has_no_hotspot_and_no_clients() {
        let s = HotspotState::not_running(1234);
        assert_eq!(s.hotspot, None);
        assert!(s.clients.is_empty());
        assert!(s.warnings.is_empty());
        assert_eq!(s.sampled_at_ms, 1234);
    }

    /// The TypeScript side (`src/types.ts`) reads exactly these names.
    #[test]
    fn json_contract_with_the_ui_is_camel_case_and_lowercase_enums() {
        let state = HotspotState {
            hotspot: Some(Hotspot {
                interface: "wlo1".into(),
                ssid: Some("HotStreamTest".into()),
                channel: Some(13),
                frequency_mhz: Some(2472),
                gateway_ip: Some("10.42.0.1".into()),
            }),
            clients: vec![Client {
                mac: "ce:da:1e:90:d4:aa".into(),
                state: ClientState::Connected,
                ip: None,
                hostname: Some("phone".into()),
                locally_administered: true,
                signal_dbm: Some(-40),
                connected_secs: Some(60),
                inactive_ms: Some(5),
                uploaded_bytes: Some(1),
                downloaded_bytes: Some(2),
            }],
            warnings: vec![],
            sampled_at_ms: 99,
        };
        let v = serde_json::to_value(&state).unwrap();
        assert_eq!(v["sampledAtMs"], 99);
        assert_eq!(v["hotspot"]["interface"], "wlo1");
        assert_eq!(v["hotspot"]["frequencyMhz"], 2472);
        assert_eq!(v["hotspot"]["gatewayIp"], "10.42.0.1");
        let c = &v["clients"][0];
        assert_eq!(c["state"], "connected");
        assert_eq!(c["locallyAdministered"], true);
        assert_eq!(c["signalDbm"], -40);
        assert_eq!(c["connectedSecs"], 60);
        assert_eq!(c["inactiveMs"], 5);
        assert_eq!(c["uploadedBytes"], 1);
        assert_eq!(c["downloadedBytes"], 2);
        assert!(c["ip"].is_null(), "an unknown IP must serialise as null, not be dropped");
        assert_eq!(serde_json::to_value(ClientState::Connecting).unwrap(), "connecting");
    }
}
