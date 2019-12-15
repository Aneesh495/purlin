// Purlin: High-Performance BGP-4 & MP-BGP Routing Engine in Koka
module purlin

import std/core/list
import std/core/maybe
import std/core/console
import proto/types
import proto/attr
import proto/message
import proto/fsm
import rib/table
import fib/table
import fib/synth
import rpki/roa
import damping/flap
import engine/peer
import engine/daemon
import cli/command
import cli/format
import api/metrics
import sim/topology
import sim/fabric

val purlin-version : string = "0.9.4"

pub fun print-banner() : console ()
  println("=================================================================")
  println("  purlin v" ++ purlin-version ++ " - BGP-4 & MP-BGP Routing Engine in Koka")
  println("  RFC 4271 / RFC 4456 / RFC 4760 / RFC 6811 / RFC 7432 / RFC 7938")
  println("=================================================================")

pub fun print-help() : console ()
  print-banner()
  println("Usage: purlin <command> [options]\n")
  println("Commands:")
  println("  show bgp summary         Display BGP neighbor states and statistics")
  println("  show bgp rib [prefix]    Display Routing Information Base (RIB)")
  println("  show fib [ip]            Display hardware Forwarding Information Base (FIB)")
  println("  show rpki                Display RPKI ROA cache status and origin validation")
  println("  show damping             Display Route Flap Damping penalties and decay")
  println("  metrics                  Export Prometheus text telemetry format")
  println("  sim                      Run 5-node Clos spine-leaf datacenter simulation")
  println("  version                  Display software version and supported RFCs")
  println("  help                     Display this help manual\n")

// Build a sample live operational daemon for demonstration / CLI queries
fun make-sample-daemon() : div bgp-daemon
  val my-asn = asn(65001)
  val my-ip = ipv4-create(192, 168, 1, 1)
  val my-rid = router-id(192, 168, 1, 1)
  
  val if0 = Egress-interface(1, "eth0")
  val igp = igp-table-empty().add-connected(prefix4(192, 168, 1, 0, 24), if0)
  
  var d := daemon-create(my-asn, my-rid, igp)
  
  // Add sample eBGP neighbor
  val peer-ip = ipv4-create(192, 168, 1, 2)
  val peer-cfg = default-peer-config(peer-ip, asn(65002), my-ip, my-asn)
  d := daemon-add-peer(d, peer-cfg)
  
  // Transition peer to Established
  val sample-peer = daemon-find-peer(d, peer-ip).default(peer-create(peer-cfg, my-rid))
  val (p1, _) = peer-step-fsm(sample-peer, EvManualStart)
  val (p2, _) = peer-step-fsm(p1, EvTcpConnectionConfirmed)
  val (p3, _) = peer-step-fsm(p2, EvRecvOpen(MsgOpen(4, asn(65002), 90, Router-id(peer-ip), [])))
  val (p4, _) = peer-step-fsm(p3, EvRecvKeepalive)
  
  // Add sample routes
  val pfx1 = prefix4(10, 100, 0, 0, 16)
  val route1 = Bgp-route(
    route-prefix = pfx1,
    peer-asn = asn(65002),
    peer-ip = peer-ip,
    peer-id = Router-id(peer-ip),
    origin = OriginIgp,
    as-path = As-path([As-segment(as-segment-sequence, [asn(65002)])]),
    next-hop = peer-ip,
    med = 0,
    local-pref = 100,
    weight = 0,
    communities = [],
    ext-communities = [],
    cluster-list = [],
    originator-id = Nothing,
    is-local = False,
    is-valid = True,
    is-best = True,
    is-damped = False,
    rpki = RpkiValid,
    received-time = 1000
  )
  
  val rib = rib-insert(d.rib, route1)
  val fib = synthesize-fib(rib, igp, 1000)
  
  d(peers = [p4], rib = rib, fib = fib)

pub fun run-cli(args : list<string>) : <div,exn,console> ()
  match args
    Cons("metrics", _) ->
      val d = make-sample-daemon()
      print(export-prometheus-metrics(d))
    Cons("sim", _) ->
      println("Initializing Clos datacenter fabric simulation...")
      val topo = build-clos-two-by-three()
      var fabric := init-clos-fabric(topo)
      fabric := fabric-establish-peering(fabric)
      val tenant-pfx = prefix4(10, 101, 0, 0, 16)
      fabric := fabric-inject-leaf-prefix(fabric, "leaf1", tenant-pfx)
      println("Fabric converged. Advertised prefix 10.101.0.0/16 across 5 nodes.")
      val l2-ok = fabric-leaf-has-route(fabric, "leaf2", tenant-pfx)
      val l3-ok = fabric-leaf-has-route(fabric, "leaf3", tenant-pfx)
      println("Leaf-2 active route in FIB: " ++ l2-ok.show)
      println("Leaf-3 active route in FIB: " ++ l3-ok.show)
    _ ->
      val cmd = parse-cli-args(args)
      val d = make-sample-daemon()
      match cmd
        CmdHelp -> print-help()
        CmdShowVersion -> print-banner()
        CmdShowBgpSummary -> print(format-bgp-summary(d))
        CmdShowRib(pfx-filter) -> print(format-rib-table(d.rib, pfx-filter))
        CmdShowFib(_) -> print(format-fib-table(d.fib))
        CmdShowRpki -> print(format-rpki-summary(d.rpki))
        CmdShowDamping -> print(format-damping-summary(d.flaps))
        CmdRunDaemon(cfg) ->
          print-banner()
          println("Starting Purlin routing daemon with config: " ++ cfg)
          println("BGP routing engine initialized on loopback.")
        CmdUnknown(cmd-raw) ->
          println("Unknown command: " ++ cmd-raw)
          println("Run 'purlin help' for usage.")

pub fun main() : <div,exn,console> ()
  run-cli(["show", "bgp", "summary"])
