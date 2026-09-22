//! nl80211 data via `iw`: which wireless interfaces exist, which one is an access point, and
//! which stations (clients) are associated with it. The station list is the only source this
//! application trusts for "who is connected".

use std::str::FromStr;

use crate::model::{normalize_mac, Mac};

use super::error::DiscoveryError;
use super::exec;

#[derive(Debug, Clone, PartialEq)]
pub struct WirelessInterface {
    pub name: String,
    /// `iw`'s interface type: `AP`, `managed`, `P2P-client`, ...
    pub kind: String,
    pub ssid: Option<String>,
    pub channel: Option<u32>,
    pub frequency_mhz: Option<u32>,
}

impl WirelessInterface {
    pub fn is_ap(&self) -> bool {
        self.kind == "AP"
    }
}

/// One associated station as reported by the access point's nl80211 stack. Byte counters are
/// from the access point's point of view (`rx` = received from the station).
#[derive(Debug, Clone, PartialEq)]
pub struct Station {
    pub mac: Mac,
    pub authorized: bool,
    pub inactive_ms: Option<u64>,
    pub rx_bytes: Option<u64>,
    pub tx_bytes: Option<u64>,
    pub signal_dbm: Option<i32>,
    pub connected_secs: Option<u64>,
}

/// Decode `iw`'s SSID escaping (`\xNN` for every byte that is not plain printable ASCII).
pub fn unescape_ssid(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let hex = |b: u8| (b as char).to_digit(16);
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && bytes.get(i + 1) == Some(&b'x') {
            let decoded = bytes.get(i + 2).zip(bytes.get(i + 3)).and_then(|(&h, &l)| Some(hex(h)? * 16 + hex(l)?));
            if let Some(byte) = decoded {
                out.push(byte as u8);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse the output of `iw dev`.
pub fn parse_interfaces(out: &str) -> Vec<WirelessInterface> {
    let mut interfaces = Vec::new();
    let mut current: Option<WirelessInterface> = None;
    for line in out.lines() {
        let line = line.trim();
        if let Some(name) = line.strip_prefix("Interface ") {
            interfaces.extend(current.take());
            current = Some(WirelessInterface {
                name: name.trim().to_string(),
                kind: String::new(),
                ssid: None,
                channel: None,
                frequency_mhz: None,
            });
        } else if line.starts_with("phy#") || line.starts_with("Unnamed/non-netdev interface") {
            // A new phy, or a device without a netdev (e.g. P2P-device): the previous
            // interface's block is over and these lines belong to nobody we track.
            interfaces.extend(current.take());
        } else if let Some(iface) = current.as_mut() {
            if let Some(ssid) = line.strip_prefix("ssid ") {
                iface.ssid = Some(unescape_ssid(ssid));
            } else if let Some(kind) = line.strip_prefix("type ") {
                iface.kind = kind.trim().to_string();
            } else if let Some(channel) = line.strip_prefix("channel ") {
                // "13 (2472 MHz), width: 20 MHz, center1: 2472 MHz"
                iface.channel = first_number(channel);
                iface.frequency_mhz = channel
                    .split_once('(')
                    .and_then(|(_, rest)| first_number(rest));
            }
        }
    }
    interfaces.extend(current);
    interfaces
}

/// Parse the output of `iw dev <if> station dump`.
pub fn parse_station_dump(out: &str) -> Vec<Station> {
    let mut stations = Vec::new();
    let mut current: Option<Station> = None;
    for line in out.lines() {
        if let Some(header) = line.strip_prefix("Station ") {
            stations.extend(current.take());
            // "<mac> (on <ifname>)"; a header we cannot read swallows its own fields.
            current = header.split_whitespace().next().and_then(normalize_mac).map(|mac| Station {
                mac,
                authorized: false,
                inactive_ms: None,
                rx_bytes: None,
                tx_bytes: None,
                signal_dbm: None,
                connected_secs: None,
            });
            continue;
        }
        let Some(station) = current.as_mut() else { continue };
        let Some((key, value)) = line.split_once(':') else { continue };
        let value = value.trim();
        match key.trim() {
            "authorized" => station.authorized = value == "yes",
            "inactive time" => station.inactive_ms = first_number(value),
            "rx bytes" => station.rx_bytes = first_number(value),
            "tx bytes" => station.tx_bytes = first_number(value),
            "signal" => station.signal_dbm = first_number(value),
            "connected time" => station.connected_secs = first_number(value),
            _ => {}
        }
    }
    stations.extend(current);
    stations
}

/// The first whitespace-separated token of `s`, parsed as a number.
fn first_number<T: FromStr>(s: &str) -> Option<T> {
    s.split_whitespace().next()?.parse().ok()
}

/// Run `iw dev`.
pub fn interfaces() -> Result<Vec<WirelessInterface>, DiscoveryError> {
    Ok(parse_interfaces(&exec::run("iw", &["dev"], exec::DEFAULT_TIMEOUT)?))
}

/// Run `iw dev <ifname> station dump`. Only ever call this for an interface in AP mode: on a
/// managed interface `iw` lists the *upstream* access point as a "station".
pub fn station_dump(ifname: &str) -> Result<Vec<Station>, DiscoveryError> {
    let out = exec::run("iw", &["dev", ifname, "station", "dump"], exec::DEFAULT_TIMEOUT)?;
    Ok(parse_station_dump(&out))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Captured from a real laptop (MACs/SSIDs anonymised, structure and whitespace untouched).
    const IW_DEV_AP: &str = include_str!("../../tests/fixtures/iw_dev_ap.txt");
    const IW_DEV_MANAGED: &str = include_str!("../../tests/fixtures/iw_dev_managed.txt");
    const STATION_ONE: &str = include_str!("../../tests/fixtures/iw_station_dump_one.txt");
    const STATION_TWO: &str = include_str!("../../tests/fixtures/iw_station_dump_two_clients.txt");

    #[test]
    fn an_ap_mode_interface_is_parsed_with_ssid_and_channel() {
        let v = parse_interfaces(IW_DEV_AP);
        // The "Unnamed/non-netdev interface" (P2P-device) block must not become an interface.
        assert_eq!(
            v,
            vec![WirelessInterface {
                name: "wlo1".into(),
                kind: "AP".into(),
                ssid: Some("HotStreamTest".into()),
                channel: Some(13),
                frequency_mhz: Some(2472),
            }]
        );
        assert!(v[0].is_ap());
    }

    #[test]
    fn a_managed_interface_is_parsed_but_is_not_an_access_point() {
        let v = parse_interfaces(IW_DEV_MANAGED);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].kind, "managed");
        assert_eq!(v[0].ssid.as_deref(), Some("UpstreamNet"));
        assert_eq!(v[0].channel, Some(11));
        assert_eq!(v[0].frequency_mhz, Some(2462));
        assert!(!v[0].is_ap());
    }

    #[test]
    fn an_interface_without_ssid_or_channel_still_parses() {
        let v = parse_interfaces("phy#1\n\tInterface wlan1\n\t\tifindex 5\n\t\ttype AP\n");
        assert_eq!(
            v,
            vec![WirelessInterface {
                name: "wlan1".into(),
                kind: "AP".into(),
                ssid: None,
                channel: None,
                frequency_mhz: None
            }]
        );
    }

    #[test]
    fn several_interfaces_across_phys_are_all_returned_in_order() {
        let out = "phy#0\n\tInterface wlan0\n\t\ttype managed\nphy#1\n\tInterface wlan1\n\t\ttype AP\n";
        let names: Vec<_> = parse_interfaces(out).into_iter().map(|i| i.name).collect();
        assert_eq!(names, ["wlan0", "wlan1"]);
    }

    #[test]
    fn empty_iw_output_has_no_interfaces() {
        assert!(parse_interfaces("").is_empty());
    }

    #[test]
    fn ssid_escapes_are_decoded_to_utf8() {
        assert_eq!(unescape_ssid(r"Caf\xc3\xa9 Wi-Fi"), "Café Wi-Fi");
        assert_eq!(unescape_ssid(r"\x20padded\x20"), " padded ");
        assert_eq!(unescape_ssid(r"back\x5cslash"), "back\\slash");
        assert_eq!(unescape_ssid(r"bad\xffbyte"), "bad\u{fffd}byte");
        assert_eq!(unescape_ssid(r"stray\backslash"), r"stray\backslash");
        assert_eq!(unescape_ssid(r"cut\x4"), r"cut\x4");
    }

    #[test]
    fn the_ssid_in_iw_dev_output_is_unescaped() {
        let v = parse_interfaces("phy#0\n\tInterface wlo1\n\t\tssid Caf\\xc3\\xa9\n\t\ttype AP\n");
        assert_eq!(v[0].ssid.as_deref(), Some("Café"));
    }

    #[test]
    fn a_real_station_block_is_parsed() {
        let v = parse_station_dump(STATION_ONE);
        assert_eq!(
            v,
            vec![Station {
                mac: "02:00:00:00:00:01".into(),
                authorized: true,
                inactive_ms: Some(13),
                rx_bytes: Some(3095553),
                tx_bytes: Some(2706528),
                signal_dbm: Some(-29),
                connected_secs: Some(752),
            }]
        );
    }

    #[test]
    fn two_stations_are_split_correctly_and_one_may_still_be_in_its_handshake() {
        let v = parse_station_dump(STATION_TWO);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].mac, "02:00:00:00:00:01");
        assert!(v[0].authorized);
        assert_eq!(v[1].mac, "02:00:00:00:00:02");
        assert!(!v[1].authorized);
        assert_eq!(v[1].rx_bytes, Some(1200));
        assert_eq!(v[1].tx_bytes, Some(800));
        assert_eq!(v[1].signal_dbm, Some(-61));
        assert_eq!(v[1].connected_secs, Some(3));
        assert_eq!(v[1].inactive_ms, Some(40));
        // Fields of the second block must not leak into the first.
        assert_eq!(v[0].rx_bytes, Some(3095553));
    }

    #[test]
    fn a_station_missing_optional_fields_reports_none_for_them() {
        let v = parse_station_dump("Station 02:00:00:00:00:03 (on wlo1)\n\tauthorized:\tyes\n");
        assert_eq!(
            v,
            vec![Station {
                mac: "02:00:00:00:00:03".into(),
                authorized: true,
                inactive_ms: None,
                rx_bytes: None,
                tx_bytes: None,
                signal_dbm: None,
                connected_secs: None,
            }]
        );
    }

    #[test]
    fn an_access_point_with_no_clients_yields_an_empty_list() {
        assert!(parse_station_dump("").is_empty());
        assert!(parse_station_dump("\n").is_empty());
    }

    #[test]
    fn a_header_with_an_invalid_mac_is_skipped_and_its_fields_do_not_leak() {
        let out = "Station nonsense (on wlo1)\n\tauthorized:\tyes\n\trx bytes:\t999\n\
                   Station 02:00:00:00:00:01 (on wlo1)\n\tauthorized:\tno\n";
        let v = parse_station_dump(out);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].mac, "02:00:00:00:00:01");
        assert!(!v[0].authorized);
        assert_eq!(v[0].rx_bytes, None);
    }

    #[test]
    fn station_macs_are_normalised_to_lowercase() {
        let v = parse_station_dump("Station CE:DA:1E:90:D4:AA (on wlo1)\n\tauthorized:\tyes\n");
        assert_eq!(v[0].mac, "ce:da:1e:90:d4:aa");
    }
}
