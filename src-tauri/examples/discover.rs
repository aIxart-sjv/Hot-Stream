//! Developer tool (not part of the app): print what Hot-Stream's discovery sees right now.
//!
//!     cargo run --example discover              one JSON snapshot
//!     cargo run --example discover -- --watch   one line whenever the hotspot/clients change
//!
//! It calls the same `snapshot()` the UI calls, so it shows exactly what the UI is served.

use std::process::Command;
use std::thread::sleep;
use std::time::Duration;

use hot_stream_lib::discovery::snapshot;
use hot_stream_lib::model::HotspotState;

fn summary(state: &HotspotState) -> String {
    let Some(h) = &state.hotspot else { return "hotspot: not running".into() };
    let clients: Vec<String> = state
        .clients
        .iter()
        .map(|c| {
            format!(
                "{}({}, {}, {:?})",
                c.mac,
                c.ip.as_deref().unwrap_or("no-ip"),
                c.hostname.as_deref().unwrap_or("no-name"),
                c.state
            )
        })
        .collect();
    format!("hotspot {} '{}': {} client(s) [{}]", h.interface, h.ssid.as_deref().unwrap_or("?"), clients.len(), clients.join(" "))
}

fn local_time() -> String {
    let out = Command::new("date").arg("+%T").output().ok();
    out.map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_default()
}

fn main() {
    if !std::env::args().any(|a| a == "--watch") {
        match snapshot() {
            Ok(state) => println!("{}", serde_json::to_string_pretty(&state).expect("serialise")),
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        }
        return;
    }
    let mut last = String::new();
    loop {
        let line = match snapshot() {
            Ok(state) => summary(&state),
            Err(e) => format!("ERROR {e}"),
        };
        if line != last {
            println!("{} {line}", local_time());
            last = line;
        }
        sleep(Duration::from_secs(1));
    }
}
