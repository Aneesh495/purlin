// Multi-node in-memory simulation engine for Clos spine-leaf fabrics (RFC 7938)
module sim/fabric

import std/core/list
import std/core/maybe
import proto/types
import proto/message
import proto/attr
import proto/wire
import proto/fsm
import rib/table
import rib/decision
import fib/table
import fib/synth
import engine/peer
import engine/scheduler
import engine/daemon
import sim/topology
import sim/event

pub struct fabric-node(
  node-id : string,
  daemon  : bgp-daemon,
  role    : node-role
)

pub struct fabric-state(
  nodes    : list<fabric-node>,
  topology : clos-topology,
  queue    : packet-queue,
  clock    : int
)

// Helper: build an IGP table for a switch node from its connected topology links
fun build-node-igp(topo : clos-topology, nid : string) : igp-table
  val node-links = topology-node-links(topo, nid)
  var igp := igp-table-empty()
  
  val node-opt = topology-find-node(topo, nid)
  match node-opt
    Just(n) ->
      val lo-pfx = Ip-prefix(V4(n.router-ip), 32)
      igp := igp.add-connected(lo-pfx, Egress-interface(0, "lo"))
      n.prefixes.foreach(fn(p) {
        igp := igp.add-connected(p, Egress-interface(100, "vlan100"))
      })
    Nothing -> ()
    
  node-links.foreach(fn(l) {
    if l.node-a == nid then
      igp := igp.add-connected(l.subnet, l.if-a)
    elif l.node-b == nid then
      igp := igp.add-connected(l.subnet, l.if-b)
    else ()
  })
  igp

// Initialize the 5-node Clos fabric with daemons and eBGP neighbor peering sessions
pub fun init-clos-fabric(topo : clos-topology) : <div,exn> fabric-state
  val fabric-nodes = topo.nodes.map(fn(n) {
    val igp = build-node-igp(topo, n.node-id)
    var d := daemon-create(n.node-asn, Router-id(n.router-ip), igp)
    
    // Add peering sessions for all connected links
    val node-links = topology-node-links(topo, n.node-id)
    node-links.foreach(fn(l) {
      if l.node-a == n.node-id then
        val remote-node = topology-find-node(topo, l.node-b).unjust
        val cfg = default-peer-config(l.ip-b, remote-node.node-asn, l.ip-a, n.node-asn)
        d := daemon-add-peer(d, cfg)
      elif l.node-b == n.node-id then
        val remote-node = topology-find-node(topo, l.node-a).unjust
        val cfg = default-peer-config(l.ip-a, remote-node.node-asn, l.ip-b, n.node-asn)
        d := daemon-add-peer(d, cfg)
      else ()
    })
    
    Fabric-node(n.node-id, d, n.role)
  })
  
  Fabric-state(fabric-nodes, topo, packet-queue-empty(), 0)

// Helper: find fabric node by ID
pub fun fabric-find-node(state : fabric-state, nid : string) : maybe<fabric-node>
  state.nodes.filter(fn(fn-node) fn-node.node-id == nid).head

// Helper: update or replace a fabric node in state
fun fabric-update-node(state : fabric-state, updated : fabric-node) : fabric-state
  val filtered = state.nodes.filter(fn(n) n.node-id != updated.node-id)
  state(nodes = Cons(updated, filtered))

// Establish BGP peering across all active links in the fabric
pub fun fabric-establish-peering(state : fabric-state) : div fabric-state
  var cur-nodes := state.nodes
  
  // Transition all peer sessions on all nodes from Idle to Established
  cur-nodes := cur-nodes.map(fn(fn-node) {
    val updated-peers = fn-node.daemon.peers.map(fn(p) {
      // Step through FSM: Idle -> Connect -> OpenSent -> OpenConfirm -> Established
      val (p1, _) = peer-step-fsm(p, EvManualStart)
      val (p2, _) = peer-step-fsm(p1, EvTcpConnectionConfirmed)
      val dummy-open = MsgOpen(4, p.config.peer-asn, 90, Router-id(p.config.peer-ip), [])
      val (p3, _) = peer-step-fsm(p2, EvRecvOpen(dummy-open))
      val (p4, _) = peer-step-fsm(p3, EvRecvKeepalive)
      p4
    })
    val cur-d = fn-node.daemon
    val updated-daemon = cur-d(peers = updated-peers)
    fn-node(daemon = updated-daemon)
  })
  
  state(nodes = cur-nodes)

// Inject a tenant prefix advertisement at a specific leaf switch
// Advertises the prefix to both connected Spines via UPDATE messages
pub fun fabric-inject-leaf-prefix(
  state   : fabric-state,
  leaf-id : string,
  pfx     : ip-prefix
) : div fabric-state
  val leaf-opt = fabric-find-node(state, leaf-id)
  match leaf-opt
    Nothing -> state
    Just(leaf-fn) ->
      val now = state.clock
      val leaf-asn = leaf-fn.daemon.local-asn
      val leaf-rid = leaf-fn.daemon.local-id
      
      // Construct local route
      val local-route = Bgp-route(
        route-prefix = pfx,
        peer-asn = leaf-asn,
        peer-ip = leaf-fn.daemon.local-id.rid-addr,
        peer-id = leaf-rid,
        origin = OriginIgp,
        as-path = As-path([As-segment(as-segment-sequence, [leaf-asn])]),
        next-hop = leaf-fn.daemon.local-id.rid-addr,
        med = 0,
        local-pref = 100,
        weight = 32768,
        communities = [],
        ext-communities = [],
        cluster-list = [],
        originator-id = Nothing,
        is-local = True,
        is-valid = True,
        is-best = True,
        is-damped = False,
        rpki = RpkiValid,
        received-time = now
      )
      
      // Insert locally into leaf RIB and synthesize FIB
      val leaf-rib = rib-insert(leaf-fn.daemon.rib, local-route)
      val leaf-fib = synthesize-fib(leaf-rib, leaf-fn.daemon.igp, now)
      val cur-ld = leaf-fn.daemon
      val leaf-daemon = cur-ld(rib = leaf-rib, fib = leaf-fib)
      
      // Propagate announcement to Spines
      var current-state := fabric-update-node(state, leaf-fn(daemon = leaf-daemon))
      
      val links = topology-node-links(state.topology, leaf-id)
      links.foreach(fn(l) {
        if l.is-up then
          val (remote-nid, local-ip, _remote-ip) = if l.node-a == leaf-id then
            (l.node-b, l.ip-a, l.ip-b)
          else
            (l.node-a, l.ip-b, l.ip-a)
            
          val spine-opt = fabric-find-node(current-state, remote-nid)
          match spine-opt
            Just(spine-fn) ->
              // Construct update message sent to spine
              val update-attrs = [
                AttrOrigin(OriginIgp),
                AttrAsPath(As-path([As-segment(as-segment-sequence, [leaf-asn])])),
                AttrNextHop(local-ip),
                AttrMed(0),
                AttrLocalPref(100)
              ]
              val update-msg = MsgUpdate([], update-attrs, [pfx])
              val spine-d = daemon-handle-update(spine-fn.daemon, local-ip, update-msg)
              current-state := fabric-update-node(current-state, spine-fn(daemon = spine-d))
            Nothing -> ()
        else ()
      })
      
      // Step 2: Now each Spine that received the route announces it down to all OTHER leaves
      val current-spines = current-state.nodes.filter(fn(n) n.role == RoleSpine)
      current-spines.foreach(fn(s-node) {
        val s-nid = s-node.node-id
        val s-asn = s-node.daemon.local-asn
        val s-links = topology-node-links(current-state.topology, s-nid)
        
        s-links.foreach(fn(l) {
          val other-leaf-id = if l.node-a == s-nid then l.node-b else l.node-a
          if l.is-up && other-leaf-id != leaf-id then
            val (spine-if-ip, _leaf-if-ip) = if l.node-a == s-nid then (l.ip-a, l.ip-b) else (l.ip-b, l.ip-a)
            val other-leaf-opt = fabric-find-node(current-state, other-leaf-id)
            match other-leaf-opt
              Just(ol-fn) ->
                val spine-update-attrs = [
                  AttrOrigin(OriginIgp),
                  AttrAsPath(As-path([As-segment(as-segment-sequence, [s-asn, leaf-asn])])),
                  AttrNextHop(spine-if-ip),
                  AttrMed(0),
                  AttrLocalPref(100)
                ]
                val spine-update = MsgUpdate([], spine-update-attrs, [pfx])
                val updated-leaf-d = daemon-handle-update(ol-fn.daemon, spine-if-ip, spine-update)
                current-state := fabric-update-node(current-state, ol-fn(daemon = updated-leaf-d))
              Nothing -> ()
          else ()
        })
      })
      
      current-state

// Helper: withdraw a list of routes from a daemon iteratively
fun withdraw-all-routes(d : bgp-daemon, sender-ip : ipv4, routes : list<bgp-route>) : div bgp-daemon
  match routes
    Nil -> d
    Cons(r, rest) ->
      val withdraw-msg = MsgUpdate([r.route-prefix], [], [])
      val next-d = daemon-handle-update(d, sender-ip, withdraw-msg)
      withdraw-all-routes(next-d, sender-ip, rest)

// Simulate physical link cut between a leaf and spine
pub fun fabric-cut-link(
  state          : fabric-state,
  target-link-id : string
) : div fabric-state
  val link-opt = state.topology.links.filter(fn(l) l.link-id == target-link-id).head
  match link-opt
    Nothing -> state
    Just(l) ->
      // 1. Mark link down in topology
      val updated-links = state.topology.links.map(fn(cur-l) {
        if cur-l.link-id == target-link-id then cur-l(is-up = False)
        else cur-l
      })
      val cur-topo = state.topology
      val new-topo = cur-topo(links = updated-links)
      
      // 2. Drop pending packets on this link
      val filtered-queue = drop-link-packets(state.queue, l.node-a, l.node-b)
      
      // 3. Withdraw routes advertised across this link on both sides
      val node-a-opt = fabric-find-node(state, l.node-a)
      val node-b-opt = fabric-find-node(state, l.node-b)
      
      val (next-na, next-nb) = match (node-a-opt, node-b-opt)
        (Just(na), Just(nb)) ->
          val na-routes = rib-all-routes(na.daemon.rib).filter(fn(r) r.peer-ip == l.ip-b)
          val na-d = withdraw-all-routes(na.daemon, l.ip-b, na-routes)
          
          val nb-routes = rib-all-routes(nb.daemon.rib).filter(fn(r) r.peer-ip == l.ip-a)
          val nb-d = withdraw-all-routes(nb.daemon, l.ip-a, nb-routes)
          
          (Just(na(daemon = na-d)), Just(nb(daemon = nb-d)))
        _ -> (node-a-opt, node-b-opt)
        
      var cur-state := state(topology = new-topo, queue = filtered-queue)
      match next-na
        Just(na) -> cur-state := fabric-update-node(cur-state, na)
        Nothing -> ()
      match next-nb
        Just(nb) -> cur-state := fabric-update-node(cur-state, nb)
        Nothing -> ()
        
      cur-state

// Check if a leaf node has installed an active FIB entry for an advertised prefix
pub fun fabric-leaf-has-route(
  state   : fabric-state,
  leaf-id : string,
  pfx     : ip-prefix
) : div bool
  val leaf-opt = fabric-find-node(state, leaf-id)
  match leaf-opt
    Just(leaf-fn) ->
      val fib-entry = leaf-fn.daemon.fib.fib-lookup-exact(pfx)
      fib-entry.is-just
    Nothing -> False

// Get the count of resolved ECMP next-hops for a prefix at a given leaf
pub fun fabric-leaf-ecmp-count(
  state   : fabric-state,
  leaf-id : string,
  pfx     : ip-prefix
) : div int
  val leaf-opt = fabric-find-node(state, leaf-id)
  match leaf-opt
    Just(leaf-fn) ->
      val fib-entry = leaf-fn.daemon.fib.fib-lookup-exact(pfx)
      match fib-entry
        Just(fe) -> fe.nexthops.length
        Nothing -> 0
    Nothing -> 0
