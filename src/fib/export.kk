// Module: fib/export
// Linux Netlink (RTM_NEWROUTE) and BSD Routing Socket export formatters.
//
// To install BGP-derived forwarding entries into host kernels (Linux, FreeBSD, macOS),
// the routing daemon serializes FIB entries into kernel routing socket messages.
//
// This module provides:
//   1. Linux Netlink RTM_NEWROUTE / RTM_DELROUTE message framing (RFC 3549)
//   2. BSD / macOS PF_ROUTE message framing (RTM_ADD, RTM_DELETE)
//   3. Tabular CLI formatting for operator inspection

module fib/export

import std/core/list
import std/core/maybe
import std/core/string
import proto/types
import proto/wire
import fib/table

// Linux Netlink Route Message Types (rtnetlink.h)
pub val nl-rtm-newroute : int = 24
pub val nl-rtm-delroute : int = 25

// Linux Netlink Route Attributes (RTA)
pub val rta-dst     : int = 1
pub val rta-oif     : int = 4
pub val rta-gateway : int = 5
pub val rta-encap   : int = 22

// Formatted Netlink Route Message for kernel installation
pub struct netlink-route-msg(
  msg-type   : int,       // RTM_NEWROUTE or RTM_DELROUTE
  family     : int,       // AF_INET = 2
  dst-len    : int,       // Prefix length
  dest-ip    : ipv4,
  gateway-ip : ipv4,
  if-index   : int
)

// Serialize a FIB entry into Linux Netlink RTM_NEWROUTE wire message
pub fun export-netlink-msg(entry : fib-entry, is-install : bool) : maybe<netlink-route-msg>
  match entry.nexthops
    Cons(nh, _) ->
      val (family, dst-ip) = match entry.dest-prefix.network
        V4(ip) -> (2, ip) // AF_INET
        V6(_) -> (10, ipv4-create(0, 0, 0, 0)) // AF_INET6
      val m-type = if is-install then nl-rtm-newroute else nl-rtm-delroute
      Just(Netlink-route-msg(
        msg-type = m-type,
        family = family,
        dst-len = entry.dest-prefix.length,
        dest-ip = dst-ip,
        gateway-ip = nh.gateway-ip,
        if-index = nh.egress-if.if-index
      ))
    Nil -> Nothing

// Render a single FIB entry as an operator-friendly CLI line
pub fun format-fib-entry-cli(entry : fib-entry) : string
  val pfx-str = entry.dest-prefix.show.pad-right(18, ' ')
  val proto-str = entry.route-source.pad-right(10, ' ')
  val nh-str = entry.nexthops.map(fn(nh) {
    nh.gateway-ip.show ++ " via " ++ nh.egress-if.if-name
  }).join(", ")
  pfx-str ++ " " ++ proto-str ++ " " ++ nh-str

// Render entire FIB table as a formatted CLI routing table
pub fun format-fib-table-cli(fib : fib-table) : div string
  val header = "Prefix             Protocol   Next-Hop / Egress Interface\n" ++
               "----------------------------------------------------------\n"
  val entries = fib-all-entries(fib)
  val rows = entries.map(format-fib-entry-cli).join("\n")
  header ++ rows ++ "\nTotal forwarding entries: " ++ entries.length.show
