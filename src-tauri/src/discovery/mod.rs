//! Hotspot and client discovery: a pure function of what the system says *right now*.
//!
//! Every call re-reads the system; nothing is cached between calls, so the result can never
//! drift from reality (CLAUDE.md: "reconcile with actual system state").
//!
//! * hotspot  = an interface that nl80211 reports in AP mode (`iw dev`)
//! * clients  = the stations associated with it (`iw dev <if> station dump`), keyed by MAC
//! * IP       = decoration from the neighbour table (`ip -j neigh`), optional
//! * hostname = decoration from a PTR query to the hotspot's own DNS server, optional

pub mod dns;
pub mod error;
pub mod exec;
pub mod ip;
pub mod iw;

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::model::{is_locally_administered, Client, ClientState, Hotspot, HotspotState, Mac};

pub use error::DiscoveryError;

/// dnsmasq on the local subnet answers in well under a millisecond; this only bounds the
/// wait when nothing answers (e.g. the hotspot is not served by dnsmasq).
const DNS_TIMEOUT: Duration = Duration::from_millis(400);
const DNS_PORT: u16 = 53;

/// Read the current hotspot state from the system.
pub fn snapshot() -> Result<HotspotState, DiscoveryError> {
    let sampled_at_ms = now_ms();
    let interfaces = iw::interfaces()?;
    let (hotspot_if, mut warnings) = pick_hotspot(&interfaces);
    let Some(ap) = hotspot_if else {
        return Ok(HotspotState { warnings, ..HotspotState::not_running(sampled_at_ms) });
    };

    // The interface can disappear between `iw dev` and the calls below (the hotspot was just
    // stopped). That is a state change, not an error.
    let vanished = |warnings: Vec<String>| {
        Ok(HotspotState { warnings, ..HotspotState::not_running(sampled_at_ms) })
    };

    // The station list is essential: if it cannot be read, say so instead of guessing.
    let stations = match iw::station_dump(&ap.name) {
        Ok(stations) => stations,
        Err(e) if e.is_no_such_device() => return vanished(warnings),
        Err(e) => return Err(e),
    };

    // IP addresses and hostnames only decorate stations. Losing them degrades the display
    // but never changes who is connected; tell the user rather than silently omitting them.
    let gateway = match ip::ipv4_address(&ap.name) {
        Ok(gateway) => gateway,
        Err(e) if e.is_no_such_device() => return vanished(warnings),
        Err(e) => {
            warnings.push(format!("hotspot address unavailable, hostnames disabled: {e}"));
            None
        }
    };
    let ips = match ip::neighbours(&ap.name) {
        Ok(neighbours) => ip::ipv4_by_mac(&neighbours),
        Err(e) if e.is_no_such_device() => return vanished(warnings),
        Err(e) => {
            warnings.push(format!("IP addresses unavailable: {e}"));
            HashMap::new()
        }
    };

    let hostnames = match gateway {
        Some(gateway) => {
            let targets: Vec<(Mac, Ipv4Addr)> = stations
                .iter()
                .filter_map(|s| ips.get(&s.mac).map(|ip| (s.mac.clone(), *ip)))
                .collect();
            resolve_hostnames(SocketAddr::new(gateway.into(), DNS_PORT), &targets)
        }
        None => HashMap::new(),
    };

    Ok(HotspotState {
        hotspot: Some(Hotspot {
            interface: ap.name.clone(),
            ssid: ap.ssid.clone(),
            channel: ap.channel,
            frequency_mhz: ap.frequency_mhz,
            gateway_ip: gateway.map(|g| g.to_string()),
        }),
        clients: assemble_clients(&stations, &ips, &hostnames),
        warnings,
        sampled_at_ms,
    })
}

/// The interface currently serving as the hotspot, plus warnings about anything odd.
///
/// Only interfaces in AP mode qualify. This matters: on a managed (client) interface `iw ...
/// station dump` lists the laptop's *upstream* access point as a "station".
pub(crate) fn pick_hotspot(
    interfaces: &[iw::WirelessInterface],
) -> (Option<&iw::WirelessInterface>, Vec<String>) {
    let mut aps: Vec<&iw::WirelessInterface> = interfaces.iter().filter(|i| i.is_ap()).collect();
    aps.sort_by(|a, b| a.name.cmp(&b.name));
    let warnings = if aps.len() > 1 {
        let names: Vec<&str> = aps.iter().map(|i| i.name.as_str()).collect();
        vec![format!(
            "{} interfaces are in access-point mode ({}); showing {}.",
            aps.len(),
            names.join(", "),
            names[0]
        )]
    } else {
        Vec::new()
    };
    (aps.first().copied(), warnings)
}

/// Combine the authoritative station list with the optional IP / hostname decorations.
pub(crate) fn assemble_clients(
    stations: &[iw::Station],
    ips: &HashMap<Mac, Ipv4Addr>,
    hostnames: &HashMap<Mac, String>,
) -> Vec<Client> {
    let mut clients: Vec<Client> = stations
        .iter()
        .map(|s| Client {
            mac: s.mac.clone(),
            state: if s.authorized { ClientState::Connected } else { ClientState::Connecting },
            ip: ips.get(&s.mac).map(|ip| ip.to_string()),
            hostname: hostnames.get(&s.mac).cloned(),
            locally_administered: is_locally_administered(&s.mac),
            signal_dbm: s.signal_dbm,
            connected_secs: s.connected_secs,
            inactive_ms: s.inactive_ms,
            // `iw` counts from the access point's side: rx = from the client, tx = to it.
            uploaded_bytes: s.rx_bytes,
            downloaded_bytes: s.tx_bytes,
        })
        .collect();
    // Longest-connected first (the order a "maximum devices" limit will admit clients in),
    // then by MAC so the list never shuffles between refreshes.
    clients.sort_by(|a, b| {
        b.connected_secs.cmp(&a.connected_secs).then_with(|| a.mac.cmp(&b.mac))
    });
    clients
}

/// Ask `server` for the hostname of every `(mac, ip)` target, concurrently. Targets that get
/// no usable answer are simply absent from the result.
pub(crate) fn resolve_hostnames(server: SocketAddr, targets: &[(Mac, Ipv4Addr)]) -> HashMap<Mac, String> {
    thread::scope(|scope| {
        let lookups: Vec<_> = targets
            .iter()
            .map(|(mac, ip)| (mac, scope.spawn(move || dns::lookup_ptr(server, *ip, DNS_TIMEOUT))))
            .collect();
        lookups
            .into_iter()
            .filter_map(|(mac, lookup)| Some((mac.clone(), lookup.join().ok()??)))
            .collect()
    })
}

/// Unix time in milliseconds.
fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ClientState;
    use std::net::UdpSocket;
    use std::time::Duration;

    fn st(mac: &str, authorized: bool, connected: Option<u64>) -> iw::Station {
        iw::Station {
            mac: mac.into(),
            authorized,
            inactive_ms: Some(10),
            rx_bytes: Some(100),
            tx_bytes: Some(200),
            signal_dbm: Some(-50),
            connected_secs: connected,
        }
    }

    fn ap(name: &str) -> iw::WirelessInterface {
        iw::WirelessInterface {
            name: name.into(),
            kind: "AP".into(),
            ssid: None,
            channel: None,
            frequency_mhz: None,
        }
    }

    fn no_ips() -> HashMap<Mac, Ipv4Addr> {
        HashMap::new()
    }

    fn no_names() -> HashMap<Mac, String> {
        HashMap::new()
    }

    // ---- which interface is the hotspot -----------------------------------------------------

    /// Regression for CLAUDE.md §3A ("do not present the laptop's own Wi-Fi connection as a
    /// hotspot client"). Real capture: wlo1 is a *client* of another network. Dumping its
    /// stations would list the upstream access point, so it must not be treated as a hotspot.
    #[test]
    fn a_laptop_that_is_only_a_wifi_client_has_no_hotspot() {
        let ifaces = iw::parse_interfaces(include_str!("../../tests/fixtures/iw_dev_managed.txt"));
        assert_eq!(ifaces.len(), 1, "fixture sanity: one managed interface");
        let (hotspot, warnings) = pick_hotspot(&ifaces);
        assert!(hotspot.is_none());
        assert!(warnings.is_empty());
    }

    #[test]
    fn an_ap_mode_interface_is_the_hotspot() {
        let ifaces = iw::parse_interfaces(include_str!("../../tests/fixtures/iw_dev_ap.txt"));
        let (hotspot, warnings) = pick_hotspot(&ifaces);
        assert_eq!(hotspot.unwrap().name, "wlo1");
        assert!(warnings.is_empty());
    }

    #[test]
    fn with_several_ap_interfaces_the_first_by_name_is_used_and_a_warning_says_so() {
        let ifaces = vec![ap("wlan1"), ap("wlan0")];
        let (hotspot, warnings) = pick_hotspot(&ifaces);
        assert_eq!(hotspot.unwrap().name, "wlan0");
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("wlan0") && warnings[0].contains("wlan1"), "{warnings:?}");
    }

    #[test]
    fn no_interfaces_means_no_hotspot() {
        assert!(pick_hotspot(&[]).0.is_none());
    }

    // ---- assembling clients -----------------------------------------------------------------

    #[test]
    fn an_empty_station_list_gives_no_clients() {
        assert!(assemble_clients(&[], &no_ips(), &no_names()).is_empty());
    }

    #[test]
    fn authorised_stations_are_connected_and_the_rest_are_connecting() {
        let c = assemble_clients(
            &[st("02:00:00:00:00:01", true, Some(9)), st("02:00:00:00:00:02", false, Some(1))],
            &no_ips(),
            &no_names(),
        );
        assert_eq!(c[0].state, ClientState::Connected);
        assert_eq!(c[1].state, ClientState::Connecting);
    }

    #[test]
    fn a_client_without_a_neighbour_entry_is_still_listed_with_an_unknown_ip() {
        let c = assemble_clients(&[st("02:00:00:00:00:01", true, Some(9))], &no_ips(), &no_names());
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].mac, "02:00:00:00:00:01");
        assert_eq!(c[0].ip, None);
        assert_eq!(c[0].hostname, None);
    }

    #[test]
    fn ip_and_hostname_are_attached_by_mac_only() {
        let ips = HashMap::from([("02:00:00:00:00:01".to_string(), Ipv4Addr::new(10, 42, 0, 160))]);
        let names = HashMap::from([("02:00:00:00:00:01".to_string(), "I2304".to_string())]);
        let c = assemble_clients(
            &[st("02:00:00:00:00:01", true, Some(9)), st("02:00:00:00:00:02", true, Some(8))],
            &ips,
            &names,
        );
        assert_eq!(c[0].ip.as_deref(), Some("10.42.0.160"));
        assert_eq!(c[0].hostname.as_deref(), Some("I2304"));
        assert_eq!(c[1].ip, None);
        assert_eq!(c[1].hostname, None);
    }

    #[test]
    fn clients_are_ordered_by_longest_connection_first_then_by_mac() {
        let c = assemble_clients(
            &[
                st("02:00:00:00:00:0c", true, Some(10)),
                st("02:00:00:00:00:0b", true, Some(100)),
                st("02:00:00:00:00:0d", true, None),
                st("02:00:00:00:00:0a", true, Some(100)),
            ],
            &no_ips(),
            &no_names(),
        );
        let macs: Vec<_> = c.iter().map(|c| c.mac.rsplit(':').next().unwrap()).collect();
        assert_eq!(macs, ["0a", "0b", "0c", "0d"]);
    }

    #[test]
    fn traffic_counters_are_mapped_from_the_access_point_perspective() {
        let c = assemble_clients(&[st("02:00:00:00:00:01", true, Some(1))], &no_ips(), &no_names());
        assert_eq!(c[0].uploaded_bytes, Some(100)); // AP rx = client upload
        assert_eq!(c[0].downloaded_bytes, Some(200)); // AP tx = client download
        assert_eq!(c[0].signal_dbm, Some(-50));
        assert_eq!(c[0].inactive_ms, Some(10));
        assert_eq!(c[0].connected_secs, Some(1));
    }

    #[test]
    fn the_locally_administered_flag_comes_from_the_mac() {
        let c = assemble_clients(
            &[st("ce:da:1e:90:d4:aa", true, Some(2)), st("e8:b0:c5:16:67:e1", true, Some(1))],
            &no_ips(),
            &no_names(),
        );
        assert!(c[0].locally_administered);
        assert!(!c[1].locally_administered);
    }

    // ---- hostname resolution ----------------------------------------------------------------

    /// Loopback DNS server answering PTR queries for 10.42.0.160 -> "I2304" and
    /// 10.42.0.206 -> "Mac"; it stays silent for everything else. Serves `n` queries.
    fn serve_names(n: usize) -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let addr = sock.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            for _ in 0..n {
                let Ok((len, peer)) = sock.recv_from(&mut buf) else { return };
                let first_label = &buf[13..16.min(len)]; // "160" / "206" / ...
                let name: &[u8] = match first_label {
                    b"160" => &[5, b'I', b'2', b'3', b'0', b'4', 0],
                    b"206" => &[3, b'M', b'a', b'c', 0],
                    _ => continue,
                };
                let mut r = vec![buf[0], buf[1], 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
                r.extend_from_slice(&buf[12..len]); // echo the question
                r.extend_from_slice(&[0xc0, 0x0c, 0, 12, 0, 1, 0, 0, 0, 0, 0, name.len() as u8]);
                r.extend_from_slice(name);
                let _ = sock.send_to(&r, peer);
            }
        });
        addr
    }

    #[test]
    fn hostnames_are_resolved_per_client_and_mapped_back_by_mac() {
        let server = serve_names(3);
        let targets = vec![
            ("02:00:00:00:00:01".to_string(), Ipv4Addr::new(10, 42, 0, 160)),
            ("02:00:00:00:00:02".to_string(), Ipv4Addr::new(10, 42, 0, 206)),
            ("02:00:00:00:00:03".to_string(), Ipv4Addr::new(10, 42, 0, 77)), // server stays silent
        ];
        let names = resolve_hostnames(server, &targets);
        assert_eq!(names.len(), 2, "{names:?}");
        assert_eq!(names["02:00:00:00:00:01"], "I2304");
        assert_eq!(names["02:00:00:00:00:02"], "Mac");
    }

    #[test]
    fn the_snapshot_timestamp_is_unix_time_in_milliseconds() {
        // 2024-01-01 in ms, and not absurdly far in the future.
        let t = now_ms();
        assert!(t > 1_704_067_200_000 && t < 4_102_444_800_000, "{t}");
    }

    #[test]
    fn resolving_no_targets_touches_nothing() {
        assert!(resolve_hostnames("127.0.0.1:9".parse().unwrap(), &[]).is_empty());
    }
}
