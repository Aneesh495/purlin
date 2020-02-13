# Purlin Operator CLI Handbook & Telemetry Runbook

This guide covers operational usage, command-line interfaces, Prometheus metrics configuration, and troubleshooting procedures for the Purlin BGP routing engine.

---

## 1. Operator CLI Command Reference

The Purlin CLI provides network engineers with interactive and scriptable inspection of protocol sessions, routing information bases, forwarding tables, and RPKI caches.

### 1.1 `show bgp summary`

Displays the status and telemetry of all configured BGP peer sessions:

```bash
$ purlin show bgp summary
```

**Example Output:**
```
====================================================================================================
Neighbor        AS       MsgRcvd   MsgSent   TableVer  InQ  OutQ  Up/Down    State/PfxRcvd
----------------------------------------------------------------------------------------------------
10.0.0.1        65001    1420      1422      48        0    0     04:12:33   Established (12 prefixes)
10.0.0.2        65002    1418      1419      48        0    0     04:12:31   Established (8 prefixes)
172.16.1.1      65100    42        45        0         0    0     00:01:14   Active
----------------------------------------------------------------------------------------------------
Total Peers: 3 | Established: 2 | Total Inactive: 1
====================================================================================================
```

**Field Descriptions:**
- `Neighbor`: Remote peer IPv4 address.
- `AS`: Autonomous System Number of the neighbor.
- `MsgRcvd / MsgSent`: Total BGP message counters across session lifetime.
- `InQ / OutQ`: Packets currently queued in non-blocking memory buffers.
- `Up/Down`: Duration since the last state machine transition.
- `State/PfxRcvd`: Current FSM state, or prefix count if Established.

---

### 1.2 `show bgp routes` and `show bgp route <prefix>`

Inspects routes in the Loc-RIB, displaying best-path status, AS-paths, next hops, and tie-break explanations:

```bash
$ purlin show bgp routes
```

**Example Output:**
```
====================================================================================================
Status: *> Best Path, * Valid Candidate, i Internal (iBGP), d Damped
----------------------------------------------------------------------------------------------------
   Network             Next Hop         Metric    LocPrf   Weight   Path
*> 198.51.100.0/24     10.0.0.1         0         100      0        65001 65005 IGP
*  198.51.100.0/24     10.0.0.2         10        100      0        65002 65005 IGP
*> 203.0.113.0/24      10.0.0.1         0         200      0        65001 IGP
====================================================================================================
```

To view full attribute breakdown and tie-break reasoning for a specific prefix:

```bash
$ purlin show bgp route 198.51.100.0/24
```

**Example Detailed Output:**
```
Prefix: 198.51.100.0/24 (2 available paths, best #1)
  Path #1 (Selected as Best Path):
    Advertised by Neighbor: 10.0.0.1 (AS 65001)
    Origin: IGP (0)
    AS_PATH: 65001 65005
    NEXT_HOP: 10.0.0.1 (Resolved via interface eth0, gateway 172.16.1.1)
    LOCAL_PREF: 100
    MED: 0
    RPKI Status: Valid (Validated via ROA AS 65005 /24 max 24)
    Flap Penalty: 0 (State: Unsuppressed)
    Tie-break Decision: Step 4 (Lowest MED from neighbor AS)
  Path #2:
    Advertised by Neighbor: 10.0.0.2 (AS 65002)
    Origin: IGP (0)
    AS_PATH: 65002 65005
    NEXT_HOP: 10.0.0.2
    LOCAL_PREF: 100
    MED: 10
    RPKI Status: Valid
```

---

### 1.3 `show fib summary`

Displays the active hardware Forwarding Information Base (FIB) programmed into the kernel routing table:

```bash
$ purlin show fib summary
```

**Example Output:**
```
====================================================================================================
FIB Routing Table (Platform: Linux Netlink / Generic Hardware)
----------------------------------------------------------------------------------------------------
Destination          Direct Next Hop     Interface       Weight    Status
----------------------------------------------------------------------------------------------------
10.0.0.0/24          Connected           eth0 (idx 2)    1         Active
172.16.1.0/24        Connected           eth1 (idx 3)    1         Active
198.51.100.0/24      172.16.1.1          eth1 (idx 3)    1         Resolved (Recursive)
203.0.113.0/24       172.16.1.1          eth1 (idx 3)    1         Resolved (Recursive)
====================================================================================================
Total FIB Entries: 4 | Recursive Lookups: 2 | Dropped: 0
```

---

### 1.4 `show rpki roas`

Displays the current Route Origin Authorization cache synchronized from RPKI validators via the RTR protocol (RFC 8210):

```bash
$ purlin show rpki roas
```

**Example Output:**
```
====================================================================================================
RPKI ROA Cache (Session ID: 410, Serial Number: 18)
----------------------------------------------------------------------------------------------------
Prefix                 Max Length    Authorized ASN     Source
----------------------------------------------------------------------------------------------------
198.51.100.0/24        24            65005              RTR (127.0.0.1:8282)
203.0.113.0/24         24            65001              RTR (127.0.0.1:8282)
192.0.2.0/24           28            65010              Manual Static
====================================================================================================
Total ROAs: 3 | Validated Prefixes: 2 | Invalid Rejected: 0
```

---

## 2. Prometheus Telemetry and Metrics Exporter

Purlin includes a native Prometheus HTTP exporter serving text-formatted metrics on port `9179` at `/metrics`.

### 2.1 Prometheus Configuration (`prometheus.yml`)

```yaml
scrape_configs:
  - job_name: "purlin"
    scrape_interval: 5s
    scrape_timeout: 3s
    static_configs:
      - targets: ["localhost:9179"]
        labels:
          role: "edge-router"
          cluster: "core-dc1"
```

### 2.2 Exported Metrics Catalog

| Metric Name | Type | Description |
|---|---|---|
| `purlin_bgp_peer_state` | Gauge | Current peer state (0=Idle, 1=Connect, 2=Active, 3=OpenSent, 4=OpenConfirm, 5=Established) |
| `purlin_bgp_peer_fsm_transitions_total` | Counter | Total number of state transitions experienced by this peer |
| `purlin_bgp_routes_received_total` | Counter | Total UPDATE routes parsed from peer |
| `purlin_bgp_routes_accepted` | Gauge | Routes currently accepted into Adj-RIB-In after policy evaluation |
| `purlin_bgp_routes_suppressed` | Gauge | Routes currently damped due to excessive flapping (RFC 2439) |
| `purlin_fib_routes_active` | Gauge | Number of prefixes installed in hardware FIB |
| `purlin_rpki_valid_routes` | Gauge | Number of routes in Loc-RIB verified as RPKI Valid |
| `purlin_rpki_invalid_routes` | Gauge | Number of routes identified as RPKI Invalid |
| `purlin_fsm_collision_events_total` | Counter | Total connection collisions resolved via Router ID comparison |

### 2.3 Recommended Prometheus Alerts

```yaml
groups:
  - name: purlin_alerts
    rules:
      - alert: BgpPeerDown
        expr: purlin_bgp_peer_state < 5
        for: 30s
        labels:
          severity: critical
        annotations:
          summary: "BGP neighbor {{ $labels.peer }} session down"

      - alert: RpkiInvalidRoutesDetected
        expr: purlin_rpki_invalid_routes > 0
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: "Potential route hijacking detected: {{ $value }} RPKI invalid routes"
```

---

## 3. Operational Troubleshooting Runbooks

### 3.1 Runbook: BGP Session Stuck in `Active` or `Connect`

**Symptom:** Peer state remains `Active` without transitioning to `OpenSent` or `Established`.

**Investigation Steps:**
1. Check TCP reachability to peer:
   ```bash
   nc -zv <peer-ip> 179
   ```
2. Verify local firewall allows ingress and egress TCP port 179:
   ```bash
   sudo iptables -L -n -v | grep 179
   ```
3. Check DSCP configuration: Purlin tags control frames with DSCP `CS6` (precedence 6). Ensure intermediary firewalls do not drop CS6 packets.
4. Review Purlin logs for collision events or ASN mismatches:
   ```bash
   tail -n 100 /var/log/purlin/daemon.log | grep -E "collision|NOTIFICATION"
   ```

---

### 3.2 Runbook: Route Flap Damping Suppression

**Symptom:** A valid customer route is not installed in the FIB despite the peer being Established.

**Investigation Steps:**
1. Query route status:
   ```bash
   $ purlin show bgp route <prefix>
   ```
   Check if the route has the `d` (Damped) flag set.
2. Check penalty value:
   - Penalty > 2000 indicates route was suppressed after multiple rapid withdrawal/announcement cycles.
3. If the flap condition has stabilized and emergency unsuppression is needed:
   ```bash
   $ purlin clear bgp damping <prefix>
   ```
   This resets the penalty curve to 0 and immediately evaluates the prefix for Loc-RIB inclusion.

---

### 3.3 Runbook: RPKI RTR Synchronization Failure

**Symptom:** `purlin show rpki roas` shows stale serial numbers or connection errors to RPKI validator.

**Investigation Steps:**
1. Test connectivity to local RTR cache (e.g. Routinator, OctoRPKI, or StayRTR):
   ```bash
   nc -zv 127.0.0.1 8282
   ```
2. Force an RTR cache reset query:
   ```bash
   $ purlin clear rpki cache-reset
   ```
   This triggers an RFC 8210 Reset Query PDU (Type 2), fetching an atomic refresh of all ROA records.
