// High-density operator terminal table and JSON output formatters
module cli/format

import std/core/list
import std/core/maybe
import std/core/string
import proto/types
import proto/attr
import proto/fsm
import rib/table
import fib/table
import rpki/roa
import damping/flap
import engine/peer
import engine/daemon


// Format standard BGP summary table (Cisco/Juniper/FRR style)
pub fun format-bgp-summary(d : bgp-daemon) : div string
  val header = "BGP router identifier " ++ d.local-id.show ++ ", local AS number " ++ d.local-asn.show ++ "\n" ++
               "RIB entries " ++ rib-all-routes(d.rib).length.show ++ ", FIB entries " ++ fib-all-entries(d.fib).length.show ++ "\n" ++
               "Peers " ++ d.peers.length.show ++ "\n\n" ++
               pad-right("Neighbor", 18) ++
               pad-right("V", 4) ++
               pad-right("AS", 10) ++
               pad-right("MsgRcvd", 10) ++
               pad-right("MsgSent", 10) ++
               pad-right("State/PfxRcd", 16) ++ "\n" ++
               "-".repeat(68) ++ "\n"
               
  val rows = d.peers.map(fn(p) {
    val state-str = match p.fsm-state
      StateEstablished -> p.routes-received.show
      other -> other.show
      
    pad-right(p.config.peer-ip.show, 18) ++
    pad-right("4", 4) ++
    pad-right(p.config.peer-asn.show, 10) ++
    pad-right(p.routes-received.show, 10) ++
    pad-right(p.routes-advertised.show, 10) ++
    pad-right(state-str, 16)
  }).join("\n")
  
  header ++ rows ++ "\n"

// Format BGP Routing Information Base (RIB) table
pub fun format-rib-table(rib : rib-table, pfx-filter : maybe<ip-prefix>) : div string
  val legend = "Status codes: s suppressed, d damped, * valid, > best, i - internal\n" ++
               "Origin codes: i - IGP, e - EGP, ? - incomplete\n" ++
               "RPKI validation: V valid, I invalid, N not-found\n\n" ++
               pad-right("   Network", 24) ++
               pad-right("Next Hop", 18) ++
               pad-right("Metric", 10) ++
               pad-right("LocPrf", 10) ++
               pad-right("Weight", 10) ++
               "Path\n" ++
               "-".repeat(82) ++ "\n"
               
  val all-routes = match pfx-filter
    Just(target-pfx) -> rib-lookup(rib, target-pfx)
    Nothing -> rib-all-routes(rib)
    
  val rows = all-routes.map(fn(r) {
    val best-char = if r.is-best then ">" else " "
    val valid-char = if r.is-valid then "*" else " "
    val damped-char = if r.is-damped then "d" else " "
    val status-prefix = valid-char ++ best-char ++ damped-char ++ " "
    
    val pfx-str = pad-right(status-prefix ++ r.route-prefix.show, 24)
    val nh-str = pad-right(r.next-hop.show, 18)
    val med-str = pad-right(r.med.show, 10)
    val lp-str = pad-right(r.local-pref.show, 10)
    val w-str = pad-right(r.weight.show, 10)
    val path-str = r.as-path.show ++ " " ++ (match r.origin { OriginIgp -> "i"; OriginEgp -> "e"; OriginIncomplete -> "?" })
    
    pfx-str ++ nh-str ++ med-str ++ lp-str ++ w-str ++ path-str
  }).join("\n")
  
  legend ++ rows ++ "\n"

// Format Forwarding Information Base (FIB) active routes
pub fun format-fib-table(fib : fib-table) : div string
  val header = pad-right("Destination", 22) ++
               pad-right("Gateway / NextHop", 22) ++
               pad-right("Interface", 14) ++
               "Proto\n" ++
               "-".repeat(68) ++ "\n"
               
  val entries = fib-all-entries(fib)
  val rows = entries.map(fn(e) {
    val dst-str = pad-right(e.dest-prefix.show, 22)
    val nh-rows = e.nexthops.map(fn(nh) {
      val gw-str = pad-right(nh.gateway-ip.show, 22)
      val if-str = pad-right(nh.egress-if.if-name, 14)
      gw-str ++ if-str ++ e.route-source
    })
    
    match nh-rows
      Cons(first-nh, other-nhs) ->
        val first-line = dst-str ++ first-nh
        val other-lines = other-nhs.map(fn(onh) {
          pad-right("", 22) ++ onh
        })
        Cons(first-line, other-lines).join("\n")
      Nil -> dst-str ++ pad-right("DIRECT", 22) ++ pad-right("lo", 14) ++ e.route-source
  }).join("\n")
  
  header ++ rows ++ "\n"

// Format RPKI ROA cache summary
pub fun format-rpki-summary(cache : roa-cache) : div string
  val total = roa-cache-size(cache)
  "RPKI Route Origin Authorization (ROA) Cache Status:\n" ++
  "  Total Valid ROAs Indexed : " ++ total.show ++ "\n" ++
  "  Validation Policy         : RFC 6811 Prefix Origin Validation\n" ++
  "  Cache Synchronization    : Ready\n"

// Format Route Flap Damping history
pub fun format-damping-summary(tbl : damp-table) : string
  val header = pad-right("Network", 22) ++
               pad-right("Peer", 18) ++
               pad-right("Flaps", 8) ++
               pad-right("Penalty", 10) ++
               "State\n" ++
               "-".repeat(68) ++ "\n"
               
  val rows = tbl.records.map(fn(r) {
    pad-right(r.target-prefix.show, 22) ++
    pad-right(r.peer-ip.show, 18) ++
    pad-right(r.flap-count.show, 8) ++
    pad-right(r.penalty.show, 10) ++
    r.state.show
  }).join("\n")
  
  header ++ rows ++ "\n"
