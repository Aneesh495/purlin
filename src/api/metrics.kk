// Prometheus metrics exporter for BGP telemetry and monitoring
module api/metrics

import std/core/list
import std/core/string
import proto/types
import proto/fsm
import rib/table
import fib/table
import rpki/roa
import engine/peer
import engine/daemon

// Export Prometheus text-based exposition format metrics from BGP daemon state
pub fun export-prometheus-metrics(d : bgp-daemon) : div string
  val peers-up = d.peers.filter(fn(p) p.fsm-state == StateEstablished).length
  val total-rib = rib-all-routes(d.rib).length
  val total-fib = fib-all-entries(d.fib).length
  val total-roas = roa-count(d.rpki)
  val total-flaps = d.flaps.records.length
  
  val lines = [
    "# HELP bgp_peers_configured Total number of configured BGP neighbors",
    "# TYPE bgp_peers_configured gauge",
    "bgp_peers_configured " ++ d.peers.length.show,
    "",
    "# HELP bgp_peers_up Number of BGP neighbors in Established state",
    "# TYPE bgp_peers_up gauge",
    "bgp_peers_up " ++ peers-up.show,
    "",
    "# HELP bgp_rib_routes_total Total number of active route candidates in RIB",
    "# TYPE bgp_rib_routes_total gauge",
    "bgp_rib_routes_total " ++ total-rib.show,
    "",
    "# HELP bgp_fib_entries_total Total number of active hardware FIB entries",
    "# TYPE bgp_fib_entries_total gauge",
    "bgp_fib_entries_total " ++ total-fib.show,
    "",
    "# HELP bgp_rpki_roas_total Total number of valid ROA authorizations in cache",
    "# TYPE bgp_rpki_roas_total gauge",
    "bgp_rpki_roas_total " ++ total-roas.show,
    "",
    "# HELP bgp_route_flaps_total Total number of tracked route flap penalty records",
    "# TYPE bgp_route_flaps_total counter",
    "bgp_route_flaps_total " ++ total-flaps.show,
    ""
  ]
  
  // Per-peer route metrics
  val peer-lines = d.peers.flatmap(fn(p) {
    val peer-str = p.config.peer-ip.show
    val asn-str = p.config.peer-asn.show
    val labels = "{peer=\"" ++ peer-str ++ "\",asn=\"" ++ asn-str ++ "\"}"
    [
      "bgp_peer_routes_received_total" ++ labels ++ " " ++ p.routes-received.show,
      "bgp_peer_routes_advertised_total" ++ labels ++ " " ++ p.routes-advertised.show
    ]
  })
  
  (lines ++ peer-lines).join("\n") ++ "\n"
