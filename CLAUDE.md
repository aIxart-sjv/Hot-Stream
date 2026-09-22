# Hot-Stream — Project Definition & Development Contract

## 1. What Hot-Stream Is

Hot-Stream is a Linux desktop application for controlling devices connected to the **Wi-Fi hotspot hosted by the user's laptop**.

The product is NOT a generic network monitor, generic Wi-Fi manager, remote agent system, or cloud service.

The central purpose is:

> **See who is connected to my laptop's hotspot, control who is allowed to use it, limit how many devices can connect, and independently control each connected device's Internet speed.**

The application should turn Linux hotspot/network-control capabilities into a usable desktop interface.

---

## 2. Core User Goal

When the laptop is running a Wi-Fi hotspot, the user should be able to open Hot-Stream and immediately understand:

- Is my hotspot running?
- Which devices are connected right now?
- What are those devices?
- Which devices are allowed?
- Which devices are blocked?
- How many devices can connect?
- What speed limit is applied to each device?

The user should be able to make changes from the application rather than manually performing a sequence of Linux networking commands.

---

## 3. Mandatory Core Features

### A. Connected-device discovery

Hot-Stream must discover clients connected specifically to the laptop's hotspot.

For each client, the application should aim to expose useful information such as:

- Device name / hostname when available
- IP address
- MAC address
- Connection state
- Whether the device is currently blocked
- Configured bandwidth limit
- Useful traffic statistics when technically reliable

The application must distinguish hotspot clients from unrelated interfaces/devices on the laptop.

Do not present the laptop's own Wi-Fi connection as a hotspot client.

---

### B. Per-device blocking

The user must be able to select a connected device and block it.

Expected user experience:

1. Device appears in the client list.
2. User selects the device.
3. User presses Block.
4. The device loses Internet access through the hotspot.
5. UI clearly shows that it is blocked.
6. User can unblock it later.

Blocking should be persistent enough to remain effective while the hotspot is running and should not merely hide the device from the UI.

---

### C. Maximum connected-device limit

The user must be able to configure a maximum number of allowed hotspot clients.

Example:

```text
Maximum devices: 3

Device 1 → allowed
Device 2 → allowed
Device 3 → allowed
Device 4 → denied
```

The UI should make the current state obvious:

```text
Connected: 2 / 3
```

Changing the maximum should take effect predictably.

Do not confuse this feature with simply displaying a count. The limit must actually affect who can use the hotspot.

---

### D. Per-device Internet speed limits

The user must be able to configure bandwidth limits independently for individual devices.

Examples:

```text
Phone A       10 Mbps
Laptop B       5 Mbps
Tablet C     512 Kbps
```

Changing one device's limit must not unintentionally change another device's limit.

The user should be able to:

- Set a limit
- Modify a limit
- Remove a limit / restore unrestricted bandwidth
- See the currently configured limit

The application should distinguish between upload and download limits if the underlying Linux networking capabilities and project design support that distinction reliably.

---

### E. Hotspot awareness / control

Hot-Stream must understand the laptop's hotspot state.

The application should be able to show relevant state such as:

```text
Hotspot
────────────
Status: Running
Interface: ...
SSID: ...
Connected devices: 2 / 5
```

The project may eventually include hotspot start/stop and configuration controls, but these should support the central product goal rather than becoming a generic Wi-Fi configuration application.

---

## 4. What This Project Is NOT

Do NOT allow the project to drift into these unrelated architectures or features:

### Not a remote-agent architecture

We previously experimented with a backend + WebSocket agent model. That is NOT the intended architecture for the product.

There should not be an unnecessary:

```text
Desktop → WebSocket Server → Agent
```

architecture merely to control the local laptop's hotspot.

Hot-Stream is primarily a **local Linux desktop networking-control application**.

### Not a cloud application

No cloud backend is required for the core product.

### Not a generic network scanner

Scanning arbitrary nearby networks is not the goal.

The application cares about:

> **Clients connected to this laptop's hotspot.**

### Not a Wi-Fi analyzer

Signal strength, nearby SSID discovery, channel analysis, etc. are secondary at best.

### Not a generic firewall GUI

Firewall functionality exists to support Hot-Stream's client-control features.

Do not turn the project into a general-purpose firewall management application.

### Not a bandwidth benchmark

Speed testing is not the product.

The goal is **enforcing configurable per-device bandwidth limits**.

---

## 5. Current Technology Direction

The current project has been freshly scaffolded as a Tauri desktop application.

Current intended stack:

- Tauri 2
- Rust backend
- TypeScript frontend
- Vite
- Linux-first
- NetworkManager / Linux networking facilities
- nftables where appropriate
- Linux traffic-control facilities where appropriate

The project has already successfully reached the point where:

- Tauri launches
- The Rust backend can invoke Linux networking commands
- The frontend can invoke Rust commands
- NetworkManager (`nmcli`) is available
- `tc` is available
- `nft` is available
- `iptables` is available
- The laptop uses a Wi-Fi interface such as `wlo1`
- The application has been tested under Hyprland/Wayland
- A WebKit rendering issue was worked around using:
  `WEBKIT_DISABLE_DMABUF_RENDERER=1`

Do not unnecessarily replace the established stack.

---

## 6. Current Repository State

The project was intentionally reset before starting the real implementation.

The repository was recreated as a Tauri application using:

- `vanilla-ts`
- Tauri 2
- npm
- Rust

The initial Tauri scaffold was successfully built.

The application currently has a basic proof-of-concept Rust command that queries NetworkManager and displays network-interface information.

That proof of concept is only a starting point.

Do not mistake the current `nmcli device status` display for the actual product.

The next meaningful milestone is **hotspot-client discovery**.

---

## 7. Product Development Priorities

Development should follow the actual product dependency order.

### Priority 1 — Hotspot/client visibility

Make Hot-Stream reliably identify the laptop's hotspot and discover the clients connected to it.

The UI should evolve from generic interface output into an actual client-management dashboard.

### Priority 2 — Client identity/state

Represent clients cleanly and reliably.

### Priority 3 — Blocking

Allow individual clients to be blocked and unblocked.

### Priority 4 — Maximum client limit

Allow the user to enforce a maximum number of usable hotspot clients.

### Priority 5 — Per-device bandwidth control

Allow independent bandwidth policies for individual clients.

### Priority 6 — UX hardening

Improve:

- reliability
- error handling
- privilege handling
- state synchronization
- persistence where appropriate
- startup/shutdown behavior
- recovery when the hotspot changes state
- clean user feedback

Do not polish the UI endlessly before the underlying networking functionality works.

---

## 8. Engineering Principles

### Linux-first is intentional

This is a Linux networking-control project.

Do not weaken the architecture by pretending all platforms have identical networking capabilities.

Platform support can be considered later.

### Prefer direct local control

If Linux already exposes the required capability locally, use it rather than introducing an unnecessary server, agent, or cloud component.

### Separate UI from networking logic

The frontend should represent state and user actions.

The Rust side should own privileged/local networking operations and system integration.

Do not bury important networking logic inside frontend JavaScript.

### Treat system state as unreliable

Network state can change outside the application.

Examples:

- User turns hotspot off.
- NetworkManager restarts.
- A device disconnects.
- A device reconnects with a changed IP.
- The Wi-Fi interface changes.
- A bandwidth rule disappears or becomes stale.

The application should reconcile with actual system state rather than assuming its previous state is always correct.

### Fail explicitly

If Hot-Stream cannot perform an operation because of permissions, unsupported hardware, hotspot state, or another system condition, expose a useful error.

Never silently pretend an operation succeeded.

---

## 9. UX Goal

The application should eventually feel like a control panel rather than a terminal wrapper.

A good conceptual dashboard is:

```text
┌─────────────────────────────────────────────────────┐
│ HOT-STREAM                              ● HOTSPOT ON│
├─────────────────────────────────────────────────────┤
│                                                     │
│  Connected Devices                    2 / 5         │
│                                                     │
│  ┌───────────────────────────────────────────────┐  │
│  │ 📱 Phone                                      │  │
│  │ 192.168.x.x   AA:BB:CC:DD:EE:FF              │  │
│  │ Speed: 10 Mbps                  [Block]       │  │
│  └───────────────────────────────────────────────┘  │
│                                                     │
│  ┌───────────────────────────────────────────────┐  │
│  │ 💻 Laptop                                     │  │
│  │ 192.168.x.x   11:22:33:44:55:66              │  │
│  │ Speed: 5 Mbps                   [Block]       │  │
│  └───────────────────────────────────────────────┘  │
│                                                     │
│  Maximum devices: [ 5 ]                             │
│                                                     │
└─────────────────────────────────────────────────────┘
```

This is a product direction, not a requirement to copy this exact design.

---

## 10. Important Constraints

Before implementing a feature, verify that the underlying Linux networking mechanism can actually enforce it.

Do not build fake controls.

For example:

- A "Block" button that only changes UI state is unacceptable.
- A "5 Mbps" label without actual traffic enforcement is unacceptable.
- A "maximum 3 devices" counter that still allows unlimited clients is unacceptable.

Every major control should correspond to a real system-level effect.

---

## 11. Security / Privilege Expectations

Some networking operations may require elevated privileges.

Design privilege handling deliberately.

Do not solve permission problems by casually running the entire GUI as root.

The application should eventually have a controlled mechanism for operations that genuinely require elevated privileges.

The exact mechanism should be selected based on the Linux environment and Tauri architecture after investigation.

---

## 12. Development Workflow

Before making large architectural changes:

1. Inspect the current repository.
2. Understand the existing Tauri structure.
3. Identify what already works.
4. Define the smallest vertical slice of the next feature.
5. Implement it.
6. Test it against the actual Linux hotspot.
7. Only then expand.

Do not generate huge amounts of speculative code.

Prefer working vertical slices.

---

## 13. Definition of Done

The project is NOT considered successful because:

- the GUI looks good,
- `nmcli` output is displayed,
- buttons exist,
- commands are logged,
- or mock devices appear.

The core project is successful when the user can actually do this:

```text
1. Start laptop hotspot
2. Open Hot-Stream
3. See connected devices
4. Select a device
5. Block it
6. Confirm it loses hotspot Internet access
7. Unblock it
8. Set a maximum client count
9. Verify additional clients are prevented/rejected appropriately
10. Assign a bandwidth limit to one device
11. Verify that device is actually limited
12. Give another device a different limit
13. Verify the limits are independent
```

Real system behavior matters more than UI demonstrations.

---

## 14. Claude's Role

Act as the primary engineering agent for this project.

You are expected to:

- inspect the repository before changing architecture
- maintain the project's central goal
- challenge unnecessary complexity
- avoid feature creep
- test assumptions against the actual Linux environment
- keep the implementation maintainable
- build incrementally
- explain important decisions
- verify real behavior instead of assuming it

If an approach does not actually satisfy the user's core requirement, reject it rather than polishing it.

If there are multiple technically valid approaches, choose the simplest robust approach that fits the Linux-first Tauri architecture.

---

## 15. Non-Negotiable Product Statement

Keep this statement in mind throughout development:

> **Hot-Stream is a Linux desktop hotspot-control application that lets the laptop owner see connected hotspot clients, block individual clients, enforce a maximum number of clients, and independently limit each client's Internet bandwidth.**

Any proposed feature, architecture, or implementation should be judged against that statement.
