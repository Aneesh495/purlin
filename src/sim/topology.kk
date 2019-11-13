// Graph topology builder for BGP-routed IP Clos fabrics (RFC 7938)
module sim/topology

import std/core/list
import std/core/maybe
import proto/types
import fib/table

// Node role in the data center Clos fabric
pub type node-role
  RoleSpine
  RoleLeaf
  RoleTorHost

pub fun node-role/show(r : node-role) : string
  match r
    RoleSpine -> "SPINE"
    RoleLeaf -> "LEAF"
    RoleTorHost -> "HOST"

// Switch node descriptor in the topology
pub struct sim-node(
  node-id   : string,
  node-asn  : asn,
  router-ip : ipv4,
  role      : node-role,
  prefixes  : list<ip-prefix>
)

// Inter-switch point-to-point physical link
pub struct sim-link(
  link-id   : string,
  node-a    : string,
  if-a      : egress-interface,
  ip-a      : ipv4,
  node-b    : string,
  if-b      : egress-interface,
  ip-b      : ipv4,
  subnet    : ip-prefix,
  is-up     : bool
)

// Full Clos fabric graph
pub struct clos-topology(
  nodes : list<sim-node>,
  links : list<sim-link>
)

// Helper: build a standard 2-Spine, 3-Leaf RFC 7938 Data Center Fabric
pub fun build-clos-two-by-three() : clos-topology
  // 2 Spines sharing AS 65100
  val s1 = Sim-node("spine1", asn(65100), ipv4-create(10, 0, 0, 1), RoleSpine, [])
  val s2 = Sim-node("spine2", asn(65100), ipv4-create(10, 0, 0, 2), RoleSpine, [])
  
  // 3 Leaves each with independent private ASNs
  val l1-pfx = prefix4(10, 101, 0, 0, 16)
  val l2-pfx = prefix4(10, 102, 0, 0, 16)
  val l3-pfx = prefix4(10, 103, 0, 0, 16)
  
  val l1 = Sim-node("leaf1", asn(65011), ipv4-create(10, 0, 0, 11), RoleLeaf, [l1-pfx])
  val l2 = Sim-node("leaf2", asn(65012), ipv4-create(10, 0, 0, 12), RoleLeaf, [l2-pfx])
  val l3 = Sim-node("leaf3", asn(65013), ipv4-create(10, 0, 0, 13), RoleLeaf, [l3-pfx])
  
  // 6 Point-to-Point Links (full bipartite graph)
  // Leaf 1 uplinks
  val link-l1-s1 = Sim-link("l1-s1", "leaf1", Egress-interface(1, "swp1"), ipv4-create(10, 0, 11, 2),
                                     "spine1", Egress-interface(1, "swp1"), ipv4-create(10, 0, 11, 1),
                                     prefix4(10, 0, 11, 0, 30), True)
  val link-l1-s2 = Sim-link("l1-s2", "leaf1", Egress-interface(2, "swp2"), ipv4-create(10, 0, 12, 2),
                                     "spine2", Egress-interface(1, "swp1"), ipv4-create(10, 0, 12, 1),
                                     prefix4(10, 0, 12, 0, 30), True)
  // Leaf 2 uplinks
  val link-l2-s1 = Sim-link("l2-s1", "leaf2", Egress-interface(1, "swp1"), ipv4-create(10, 0, 21, 2),
                                     "spine1", Egress-interface(2, "swp2"), ipv4-create(10, 0, 21, 1),
                                     prefix4(10, 0, 21, 0, 30), True)
  val link-l2-s2 = Sim-link("l2-s2", "leaf2", Egress-interface(2, "swp2"), ipv4-create(10, 0, 22, 2),
                                     "spine2", Egress-interface(2, "swp2"), ipv4-create(10, 0, 22, 1),
                                     prefix4(10, 0, 22, 0, 30), True)
  // Leaf 3 uplinks
  val link-l3-s1 = Sim-link("l3-s1", "leaf3", Egress-interface(1, "swp1"), ipv4-create(10, 0, 31, 2),
                                     "spine1", Egress-interface(3, "swp3"), ipv4-create(10, 0, 31, 1),
                                     prefix4(10, 0, 31, 0, 30), True)
  val link-l3-s2 = Sim-link("l3-s2", "leaf3", Egress-interface(2, "swp2"), ipv4-create(10, 0, 32, 2),
                                     "spine2", Egress-interface(3, "swp3"), ipv4-create(10, 0, 32, 1),
                                     prefix4(10, 0, 32, 0, 30), True)
                                     
  Clos-topology(
    nodes = [s1, s2, l1, l2, l3],
    links = [link-l1-s1, link-l1-s2, link-l2-s1, link-l2-s2, link-l3-s1, link-l3-s2]
  )

// Find node by identifier
pub fun topology-find-node(topo : clos-topology, nid : string) : maybe<sim-node>
  topo.nodes.filter(fn(n) n.node-id == nid).head

// Get all links connected to a specific node
pub fun topology-node-links(topo : clos-topology, nid : string) : list<sim-link>
  topo.links.filter(fn(l) l.node-a == nid || l.node-b == nid)
