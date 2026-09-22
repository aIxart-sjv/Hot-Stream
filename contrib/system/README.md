# Hotspot Internet-sharing fix (system-level, not part of Hot-Stream)

## What this is

`90-hotstream-uplink` is a [NetworkManager dispatcher
script](https://man.archlinux.org/man/NetworkManager-dispatcher.8). It is **not** part of
Hot-Stream's GUI or its privileged helper, is not installed by either of them, and does not
run unless you install it yourself. It exists because, on this machine, starting a
NetworkManager hotspot (`ipv4.method=shared`) does not give connected devices working
Internet access at all — see "Why this is needed" below — and that is true whether or not
Hot-Stream is installed or running.

Hot-Stream's own per-client block/unblock feature (the `hotstream` nftables table, managed
by `hot-stream-helper`) is unaffected by whether this script is installed, and this script
never touches Hot-Stream's table. They are deliberately independent: this script exists so
the hotspot has Internet access to block in the first place.

## Why this is needed

Investigated directly on this machine (see the project conversation history for the full
investigation): NetworkManager's own NAT/forwarding setup for a "shared" connection is
implemented via `NMFirewalldManager`, which talks to **firewalld** over D-Bus. firewalld is
not installed here. Confirmed empirically: across every real hotspot activation observed,
there is not one firewall/nft/iptables-related line in NetworkManager's own log — it
configures the DHCP/IP side of the shared connection and stops there.

Separately, this machine's Docker installation adds an `ip filter FORWARD` chain with
`policy drop`. That chain is unrelated to hotspot sharing, but since the hotspot's traffic
isn't otherwise permitted, it falls through to that policy and is dropped.

**A separate nftables table at an earlier priority cannot fix the second problem.** This was
tested directly (minimal isolated reproduction, real packet counters): an `accept` verdict
in one base chain does not stop a later, independent base chain (different table, same hook)
from also being invoked and applying its own policy — only an explicit `drop` is immediately
authoritative across chains. So the only mechanism that actually works, without touching
UFW or libvirt at all and without altering any of Docker's own rules, is to *add* two
narrowly-scoped `accept` rules to the front of Docker's own `FORWARD` chain's rule list.
That's what this script does — nothing more.

## What it does, precisely

On every NetworkManager interface up/down event, it re-derives the current truth (never
trusts that the event is still accurate — NetworkManager's own dispatcher docs say a script
can run after its triggering event is already obsolete) and reconciles the kernel to match:

- If no interface is currently running a "shared" connection: makes sure none of this
  script's rules exist. (Safe no-op if they don't.)
- If one is: determines its current IPv4 subnet and the current default-route interface
  (excluding the hotspot's own interface — never a hardcoded name), and ensures exactly:
  - two `accept` rules inserted at the **front** of the real `ip filter FORWARD` chain,
    scoped to *exactly* that (hotspot interface, uplink interface) pair, each tagged with an
    nft comment (`hotstream-uplink-fwd-out` / `hotstream-uplink-fwd-in`) so they — and only
    they — can be found and removed later. Docker's own rules are never edited, reordered,
    or removed.
  - one `masquerade` rule in a separate table it fully owns (`ip hotstream-uplink-nat`),
    scoped to the hotspot's actual subnet and excluding the hotspot's own interface as
    egress (so hotspot-internal traffic is never masqueraded).

Because every run recomputes from scratch, this handles hotspot restarts, and the uplink
changing while the hotspot stays up (Wi-Fi drops, Ethernet gets plugged in, etc.) without
any special-casing — the next up/down event on *either* interface reconciles it correctly.

## What it never touches

UFW and libvirt's own tables/chains are never read or written. Docker's own rules are never
edited, reordered, or removed — only two additional, precisely-tagged rules are inserted
ahead of them, and removed just as precisely.

## Install

Requires `nft`, `nmcli`, `jq` (all already present on this system).

```sh
sudo install -o root -g root -m 0755 90-hotstream-uplink /etc/NetworkManager/dispatcher.d/
```

(NetworkManager requires dispatcher scripts to be a regular file, owned by root, not
writable by group or other, and not setuid — `install` above sets exactly that.)

It takes effect on the next interface up/down event — no need to restart NetworkManager. To
apply it immediately to an already-running hotspot, toggle it off and on, or just wait for
any interface event.

## Remove

```sh
sudo rm /etc/NetworkManager/dispatcher.d/90-hotstream-uplink
sudo nft delete table ip hotstream-uplink-nat 2>/dev/null
sudo sh -c '
  for tag in hotstream-uplink-fwd-out hotstream-uplink-fwd-in; do
    h=$(nft -j list chain ip filter FORWARD | jq -r --arg t "$tag" \
      ".nftables[] | select(.rule?.comment==\$t) | .rule.handle")
    for x in $h; do nft delete rule ip filter FORWARD handle "$x"; done
  done
'
```

## Testing performed before this was written for real use

- Minimal isolated test proving the early-accept-in-a-separate-table idea does *not* work
  (real packet counters showed both chains independently evaluating every packet).
- A faithful, byte-for-byte reproduction of this machine's actual Docker `FORWARD` chain
  (same chain name, hook, priority, policy, jump structure), used to verify: forwarding
  works once the two rules are inserted; an unrelated interface is still correctly blocked
  by Docker's own policy (not a blanket bypass); NAT works independently (verified via a
  real TCP connection — the upstream side observed the router's translated address, not the
  client's private one); the uplink can change while the hotspot stays up and the rules
  correctly follow it (old uplink's path stops being permitted, new one starts); removal is
  exact (Docker's chain returns to a byte-for-byte match of its original state); repeated
  reconciliation for both "hotspot present" and "hotspot absent" states stays idempotent
  (never duplicates rules, never errors).
- Not yet verified against this script's actual NetworkManager-facing detection logic
  (`find_hotspot_iface`, which needs a real `nmcli`/NetworkManager, not just a sandboxed
  network namespace) — that part is verified by installing it for real and testing against
  the live hotspot, per the acceptance steps used for this feature.
