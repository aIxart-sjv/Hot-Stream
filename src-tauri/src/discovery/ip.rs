//! IP-layer data via `ip -j`: the neighbour (ARP/NDP) table used to attach an IP address to a
//! station's MAC, and the laptop's own address on the hotspot subnet.
//!
//! The neighbour table lags reality (entries decay REACHABLE -> INCOMPLETE -> FAILED after a
//! client leaves), so it may only ever *decorate* a station from `iw`, never define who is
//! connected.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

use serde::Deserialize;

use crate::model::{normalize_mac, Mac};

use super::error::DiscoveryError;
use super::exec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeighState {
    Reachable,
    Delay,
    Probe,
    Stale,
    Permanent,
    Incomplete,
    Failed,
    Other,
}

impl NeighState {
    /// Lower is more trustworthy; `None` for states that prove nothing about the address.
    fn rank(self) -> Option<u8> {
        match self {
            NeighState::Reachable => Some(0),
            NeighState::Delay => Some(1),
            NeighState::Probe => Some(2),
            NeighState::Stale => Some(3),
            NeighState::Permanent => Some(4),
            NeighState::Incomplete | NeighState::Failed | NeighState::Other => None,
        }
    }

    fn from_names(names: &[String]) -> Self {
        names
            .iter()
            .find_map(|name| match name.as_str() {
                "REACHABLE" => Some(NeighState::Reachable),
                "DELAY" => Some(NeighState::Delay),
                "PROBE" => Some(NeighState::Probe),
                "STALE" => Some(NeighState::Stale),
                "PERMANENT" => Some(NeighState::Permanent),
                "INCOMPLETE" => Some(NeighState::Incomplete),
                "FAILED" => Some(NeighState::Failed),
                _ => None,
            })
            .unwrap_or(NeighState::Other)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Neighbour {
    pub ip: IpAddr,
    pub mac: Option<Mac>,
    pub state: NeighState,
    /// Seconds since the entry was last confirmed reachable (only with `ip -s`).
    pub confirmed_secs: Option<u64>,
}

#[derive(Deserialize)]
struct RawNeighbour {
    dst: String,
    #[serde(default)]
    lladdr: Option<String>,
    #[serde(default)]
    state: Vec<String>,
    #[serde(default)]
    confirmed: Option<u64>,
}

fn parse_error(what: &'static str, e: serde_json::Error) -> DiscoveryError {
    DiscoveryError::Parse { what, detail: e.to_string() }
}

/// Parse `ip [-s] -j neigh show ...`.
pub fn parse_neighbours(json: &str) -> Result<Vec<Neighbour>, DiscoveryError> {
    if json.trim().is_empty() {
        return Ok(Vec::new());
    }
    let raw: Vec<RawNeighbour> =
        serde_json::from_str(json).map_err(|e| parse_error("`ip neigh` output", e))?;
    Ok(raw
        .into_iter()
        .filter_map(|r| {
            Some(Neighbour {
                ip: r.dst.parse().ok()?,
                mac: r.lladdr.as_deref().and_then(normalize_mac),
                state: NeighState::from_names(&r.state),
                confirmed_secs: r.confirmed,
            })
        })
        .collect())
}

/// One IPv4 address per MAC, taken only from entries that still prove the address is in use.
/// If a MAC has several usable IPv4 entries, the most trustworthy one wins.
pub fn ipv4_by_mac(neighbours: &[Neighbour]) -> HashMap<Mac, Ipv4Addr> {
    // mac -> ((state rank, seconds since confirmed), address); lower key wins, first wins ties.
    let mut best: HashMap<Mac, ((u8, u64), Ipv4Addr)> = HashMap::new();
    for n in neighbours {
        let (IpAddr::V4(ip), Some(mac), Some(rank)) = (n.ip, n.mac.as_ref(), n.state.rank()) else {
            continue;
        };
        let key = (rank, n.confirmed_secs.unwrap_or(u64::MAX));
        if best.get(mac).is_none_or(|(current, _)| key < *current) {
            best.insert(mac.clone(), (key, ip));
        }
    }
    best.into_iter().map(|(mac, (_, ip))| (mac, ip)).collect()
}

#[derive(Deserialize)]
struct RawAddrInterface {
    #[serde(default)]
    addr_info: Vec<RawAddrInfo>,
}

#[derive(Deserialize)]
struct RawAddrInfo {
    family: String,
    local: String,
}

/// Parse `ip -j -4 addr show dev <if>`: the first IPv4 address, if any.
pub fn parse_ipv4_address(json: &str) -> Result<Option<Ipv4Addr>, DiscoveryError> {
    if json.trim().is_empty() {
        return Ok(None);
    }
    let interfaces: Vec<RawAddrInterface> =
        serde_json::from_str(json).map_err(|e| parse_error("`ip addr` output", e))?;
    Ok(interfaces
        .iter()
        .flat_map(|i| &i.addr_info)
        .filter(|a| a.family == "inet")
        .find_map(|a| a.local.parse().ok()))
}

/// Run `ip -s -j neigh show dev <ifname>`.
pub fn neighbours(ifname: &str) -> Result<Vec<Neighbour>, DiscoveryError> {
    let out = exec::run("ip", &["-s", "-j", "neigh", "show", "dev", ifname], exec::DEFAULT_TIMEOUT)?;
    parse_neighbours(&out)
}

/// Run `ip -j -4 addr show dev <ifname>`.
pub fn ipv4_address(ifname: &str) -> Result<Option<Ipv4Addr>, DiscoveryError> {
    let out = exec::run("ip", &["-j", "-4", "addr", "show", "dev", ifname], exec::DEFAULT_TIMEOUT)?;
    parse_ipv4_address(&out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real captures (anonymised).
    const NEIGH_REAL: &str = include_str!("../../tests/fixtures/ip_neigh_s_real.json");
    const ADDR_REAL: &str = include_str!("../../tests/fixtures/ip_addr_real.json");

    fn n(ip: &str, mac: Option<&str>, state: NeighState, confirmed: Option<u64>) -> Neighbour {
        Neighbour {
            ip: ip.parse().unwrap(),
            mac: mac.map(str::to_string),
            state,
            confirmed_secs: confirmed,
        }
    }

    const A: &str = "02:00:00:00:00:01";

    #[test]
    fn a_real_capture_with_ipv4_and_ipv6_entries_is_parsed() {
        let v = parse_neighbours(NEIGH_REAL).unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0], n("10.42.0.99", Some(A), NeighState::Reachable, Some(18)));
        assert_eq!(v[1].ip, "fe80::ff:fe00:1".parse::<IpAddr>().unwrap());
        assert_eq!(v[1].mac.as_deref(), Some(A));
    }

    #[test]
    fn dead_entries_have_no_mac_whether_the_key_is_missing_or_null() {
        let json = r#"[{"dst":"10.42.0.52","dev":"wlo1","state":["FAILED"]},
                       {"dst":"10.42.0.53","dev":"wlo1","lladdr":null,"state":["INCOMPLETE"]}]"#;
        let v = parse_neighbours(json).unwrap();
        assert_eq!(v[0], n("10.42.0.52", None, NeighState::Failed, None));
        assert_eq!(v[1], n("10.42.0.53", None, NeighState::Incomplete, None));
    }

    #[test]
    fn an_unknown_state_does_not_break_parsing() {
        let json = r#"[{"dst":"10.42.0.7","lladdr":"02:00:00:00:00:07","state":["NOARP"]}]"#;
        assert_eq!(parse_neighbours(json).unwrap()[0].state, NeighState::Other);
    }

    #[test]
    fn macs_are_normalised_to_lowercase() {
        let json = r#"[{"dst":"10.42.0.7","lladdr":"CE:DA:1E:90:D4:AA","state":["REACHABLE"]}]"#;
        assert_eq!(parse_neighbours(json).unwrap()[0].mac.as_deref(), Some("ce:da:1e:90:d4:aa"));
    }

    #[test]
    fn invalid_json_is_a_parse_error() {
        assert!(matches!(parse_neighbours("not json"), Err(DiscoveryError::Parse { .. })));
    }

    #[test]
    fn an_empty_table_parses_to_nothing() {
        assert!(parse_neighbours("[]").unwrap().is_empty());
        assert!(parse_neighbours("").unwrap().is_empty()); // `ip -j` prints nothing for an empty table
    }

    #[test]
    fn ipv4_by_mac_ignores_ipv6_and_entries_that_prove_nothing() {
        let v = vec![
            n("fe80::1", Some(A), NeighState::Reachable, Some(1)),
            n("10.42.0.52", None, NeighState::Failed, None),
            n("10.42.0.53", Some(A), NeighState::Incomplete, None),
            n("10.42.0.54", Some(A), NeighState::Failed, None),
            n("10.42.0.55", Some(A), NeighState::Other, None),
        ];
        assert!(ipv4_by_mac(&v).is_empty());
    }

    #[test]
    fn ipv4_by_mac_prefers_a_reachable_entry_over_a_stale_one() {
        let v = vec![
            n("10.42.0.10", Some(A), NeighState::Stale, Some(5)),
            n("10.42.0.11", Some(A), NeighState::Reachable, Some(900)),
        ];
        assert_eq!(ipv4_by_mac(&v)[A], "10.42.0.11".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn ipv4_by_mac_uses_the_most_recently_confirmed_entry_among_equals() {
        let v = vec![
            n("10.42.0.10", Some(A), NeighState::Stale, Some(500)),
            n("10.42.0.11", Some(A), NeighState::Stale, Some(20)),
            n("10.42.0.12", Some(A), NeighState::Stale, None), // unknown age counts as oldest
        ];
        assert_eq!(ipv4_by_mac(&v)[A], "10.42.0.11".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn ipv4_by_mac_keeps_different_macs_separate() {
        let b = "02:00:00:00:00:02";
        let v = vec![
            n("10.42.0.10", Some(A), NeighState::Reachable, None),
            n("10.42.0.20", Some(b), NeighState::Stale, None),
        ];
        let m = ipv4_by_mac(&v);
        assert_eq!(m.len(), 2);
        assert_eq!(m[b], "10.42.0.20".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn the_gateway_address_is_read_from_a_real_capture() {
        assert_eq!(parse_ipv4_address(ADDR_REAL).unwrap(), Some("10.42.0.1".parse().unwrap()));
    }

    #[test]
    fn an_interface_without_ipv4_has_no_gateway_address() {
        let v6_only = r#"[{"ifname":"wlo1","addr_info":[{"family":"inet6","local":"fe80::1","prefixlen":64}]}]"#;
        assert_eq!(parse_ipv4_address(v6_only).unwrap(), None);
        assert_eq!(parse_ipv4_address("[]").unwrap(), None);
    }
}
