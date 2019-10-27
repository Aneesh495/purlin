// RFC 4456 BGP Route Reflection logic and loop prevention
module engine/reflector

import std/core/list
import std/core/maybe
import proto/types
import proto/attr
import proto/message
import rib/table
import engine/peer

// Peer role in an Autonomous System Route Reflection cluster
pub type rr-role
  RoleClient
  RoleNonClient
  RoleEbgp

pub fun rr-role/show(r : rr-role) : string
  match r
    RoleClient -> "CLIENT"
    RoleNonClient -> "NON-CLIENT"
    RoleEbgp -> "EBGP"

pub fun rr-role/(==)(a : rr-role, b : rr-role) : bool
  match (a, b)
    (RoleClient, RoleClient) -> True
    (RoleNonClient, RoleNonClient) -> True
    (RoleEbgp, RoleEbgp) -> True
    _ -> False

// Configuration for an RFC 4456 Route Reflector
pub struct rr-config(
  cluster-id          : router-id,
  local-router-id     : router-id,
  local-asn           : asn,
  is-route-reflector  : bool
)

pub fun rr-config-default(local-asn : asn, local-rid : router-id) : rr-config
  Rr-config(local-rid, local-rid, local-asn, True)

// RFC 4456 §9: Detect routing loops using ORIGINATOR_ID and CLUSTER_LIST
pub fun rr-detect-loop(
  route         : bgp-route,
  local-cluster : router-id,
  local-rid     : router-id
) : bool
  // Check 1: ORIGINATOR_ID loop detection (RFC 4456 §9)
  // If the ORIGINATOR_ID matches local BGP router ID, reject route
  val originator-loop = match route.originator-id
    Just(orig) -> orig == local-rid
    Nothing -> False
    
  // Check 2: CLUSTER_LIST loop detection (RFC 4456 §9)
  // If local cluster ID is found in the CLUSTER_LIST attribute, reject route
  val cluster-loop = route.cluster-list.any(fn(cid) cid == local-cluster)
  
  originator-loop || cluster-loop

// RFC 4456 §8: Route reflection forwarding rules
// Dictates whether a route received from sender-role should be reflected to receiver-role
pub fun rr-should-reflect(
  sender-role   : rr-role,
  receiver-role : rr-role
) : bool
  match sender-role
    RoleEbgp ->
      // Routes from EBGP are sent to all internal peers (Clients and Non-Clients)
      match receiver-role
        RoleClient -> True
        RoleNonClient -> True
        RoleEbgp -> False // Standard eBGP export rules apply separately
    RoleClient ->
      // Routes from a Client are reflected to Non-Clients AND other Clients
      match receiver-role
        RoleClient -> True
        RoleNonClient -> True
        RoleEbgp -> True
    RoleNonClient ->
      // Routes from a Non-Client are reflected ONLY to Clients (prevents iBGP mesh loops)
      match receiver-role
        RoleClient -> True
        RoleNonClient -> False
        RoleEbgp -> True

// RFC 4456 §5: Route attribute transformation during reflection
// - If no ORIGINATOR_ID is present, set ORIGINATOR_ID to sender router ID
// - Prepend local cluster-id to CLUSTER_LIST
// - Maintain NEXT_HOP, AS_PATH, LOCAL_PREF, and MED unmodified for iBGP peers
pub fun rr-reflect-route(
  route         : bgp-route,
  local-cluster : router-id,
  sender-rid    : router-id
) : bgp-route
  val updated-originator = match route.originator-id
    Just(_) -> route.originator-id
    Nothing -> Just(sender-rid)
    
  val updated-cluster-list = Cons(local-cluster, route.cluster-list)
  
  route(
    originator-id = updated-originator,
    cluster-list = updated-cluster-list
  )

// Classify peer session role based on configuration and ASN
pub fun rr-classify-peer(
  peer-asn       : asn,
  local-asn      : asn,
  is-configured-client : bool
) : rr-role
  if peer-asn != local-asn then RoleEbgp
  elif is-configured-client then RoleClient
  else RoleNonClient

// Compute the set of reflected route advertisements for an incoming route
pub fun rr-plan-reflection(
  route         : bgp-route,
  sender-peer   : peer-session,
  sender-role   : rr-role,
  peers         : list<(peer-session, rr-role)>,
  rr-cfg        : rr-config
) : list<(peer-session, bgp-route)>
  // Verify loop-free before reflecting
  if rr-detect-loop(route, rr-cfg.cluster-id, rr-cfg.local-router-id) then []
  else
    val sender-rid = Router-id(sender-peer.config.peer-ip)
    val reflected-route = rr-reflect-route(route, rr-cfg.cluster-id, sender-rid)
    
    // Select eligible peers excluding the sender
    val eligible-targets = peers.filter(fn((p, target-role)) {
      val is-sender = p.config.peer-ip == sender-peer.config.peer-ip
      !is-sender && rr-should-reflect(sender-role, target-role)
    })
    
    eligible-targets.map(fn((p, _)) (p, reflected-route))
