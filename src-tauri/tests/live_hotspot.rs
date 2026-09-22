//! Opt-in checks against the REAL system. They are `#[ignore]`d because their outcome depends
//! on the machine (hotspot up or not, which clients are connected):
//!
//!     cargo test --test live_hotspot -- --ignored --nocapture
//!
//! The oracle below asks `iw` through the shell and shares no code with the application.

use std::collections::BTreeSet;
use std::process::Command;
use std::time::Duration;

use hot_stream_lib::discovery::snapshot;

/// (AP interfaces, MACs of the stations associated with them, MACs of those interfaces)
fn oracle() -> (Vec<String>, BTreeSet<String>, BTreeSet<String>) {
    let script = r#"
        for i in $(iw dev | awk '$1=="Interface"{i=$2} $1=="type" && $2=="AP"{print i}'); do
            echo "AP $i"
            echo "OWN $(tr A-Z a-z < /sys/class/net/$i/address)"
            iw dev "$i" station dump | awk '/^Station/{print "STA " tolower($2)}'
        done"#;
    let out = Command::new("sh").arg("-c").arg(script).output().expect("run sh");
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let (mut aps, mut stations, mut own) = (vec![], BTreeSet::new(), BTreeSet::new());
    for line in text.lines() {
        match line.split_once(' ') {
            Some(("AP", v)) => aps.push(v.to_string()),
            Some(("STA", v)) => {
                stations.insert(v.to_string());
            }
            Some(("OWN", v)) => {
                own.insert(v.to_string());
            }
            _ => {}
        }
    }
    (aps, stations, own)
}

#[test]
#[ignore = "reads the real system"]
fn snapshot_agrees_with_iw_on_the_real_system() {
    for attempt in 1..=5 {
        let state = snapshot().expect("snapshot must not fail on a healthy system");
        let (aps, stations, own) = oracle();
        println!("attempt {attempt}: {}", serde_json::to_string_pretty(&state).unwrap());
        println!("oracle: aps={aps:?} stations={stations:?}");

        let got: BTreeSet<String> = state.clients.iter().map(|c| c.mac.clone()).collect();
        assert!(got.is_disjoint(&own), "the laptop's own interface is listed as a client: {got:?}");
        if state.hotspot.is_some() == !aps.is_empty() && got == stations {
            return;
        }
        // Stations can join/leave between our read and the oracle's read: look again.
        std::thread::sleep(Duration::from_millis(500));
    }
    panic!("snapshot never agreed with what `iw` reports");
}
