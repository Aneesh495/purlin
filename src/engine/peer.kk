// Module: engine/peer
// BGP peer session lifecycle, wire buffer queues, and FSM integration.
//
// Each peering relationship with a neighboring router is maintained as a
// peer session encapsulating its RFC 4271 Finite State Machine, inbound
// TCP stream reassembly buffer, outbound wire queue, and negotiated timers.
//
// This module provides:
//   1. Peer configuration and negotiated capabilities
//   2. Stream reassembly and wire message parser integration
//   3. Inbound/outbound message queuing and statistics
//   4. Hold timer and keepalive deadline monitoring

module engine/peer

import std/core/list
import std/core/maybe
import std/core/string
import proto/types
import proto/wire
import proto/capabilities
import proto/attr
import proto/message
import proto/fsm
import policy/ast

// Configuration parameters for a BGP peer
pub struct peer-config(
  peer-ip          : ipv4,
  peer-asn         : asn,
  local-ip         : ipv4,
  local-asn        : asn,
  hold-time        : int,                   // Configured hold time in seconds (default 90)
  keepalive-time   : int,                   // Configured keepalive in seconds (default 30)
  connect-retry    : int,                   // Connect retry interval in seconds (default 120)
  is-passive       : bool,                  // Passive listening mode
  caps             : list<bgp-capability>,  // Local supported capabilities
  import-policy    : maybe<route-map>,      // Inbound route policy
  export-policy    : maybe<route-map>       // Outbound route policy
)

pub fun default-peer-config(
  peer-ip   : ipv4,
  peer-as   : asn,
  local-ip  : ipv4,
  local-as  : asn
) : peer-config
  val default-caps = [
    CapFourOctetAsn(local-as),
    CapMpBgp(1, 1),
    CapMpBgp(25, 70),
    CapRouteRefresh
  ]
  Peer-config(
    peer-ip = peer-ip,
    peer-asn = peer-as,
    local-ip = local-ip,
    local-asn = local-as,
    hold-time = 90,
    keepalive-time = 30,
    connect-retry = 120,
    is-passive = False,
    caps = default-caps,
    import-policy = Nothing,
    export-policy = Nothing
  )

// Active peer session runtime state
pub struct peer-session(
  config               : peer-config,
  fsm-state            : fsm-state,
  fsm-cfg              : fsm-config,
  rx-buffer            : list<int>,       // Incomplete TCP stream bytes
  tx-queue             : list<list<int>>, // Outbound serialized frames
  last-rx-time         : int,             // Monotonic timestamp of last received byte
  last-tx-time         : int,             // Monotonic timestamp of last sent frame
  negotiated-hold      : int,
  negotiated-keepalive : int,
  routes-received      : int,
  routes-advertised    : int
)

// Construct a new peer session initialized in Idle state
pub fun peer-create(cfg : peer-config, local-id : router-id) : peer-session
  val fsm-c = Fsm-config(
    local-asn = cfg.local-asn,
    remote-asn = cfg.peer-asn,
    local-router-id = local-id,
    remote-router-id = Router-id(cfg.peer-ip),
    hold-time-configured = cfg.hold-time,
    connect-retry-time = cfg.connect-retry
  )
  Peer-session(
    config = cfg,
    fsm-state = StateIdle,
    fsm-cfg = fsm-c,
    rx-buffer = [],
    tx-queue = [],
    last-rx-time = 0,
    last-tx-time = 0,
    negotiated-hold = cfg.hold-time,
    negotiated-keepalive = cfg.keepalive-time,
    routes-received = 0,
    routes-advertised = 0
  )

// Check if peer session is in Established state
pub fun peer-is-established(peer : peer-session) : bool
  peer.fsm-state == StateEstablished

// Check if peer is an eBGP session (external AS)
pub fun peer-is-ebgp(peer : peer-session) : bool
  peer.config.peer-asn != peer.config.local-asn

// Step peer FSM with an incoming event
pub fun peer-step-fsm(peer : peer-session, ev : fsm-event) : (peer-session, list<fsm-action>)
  val res = step-fsm(peer.fsm-state, ev, peer.fsm-cfg)
  (peer(fsm-state = res.next-state), res.actions)

// Queue an outbound message for transmission
pub fun peer-queue-message(
  peer            : peer-session,
  msg             : bgp-message,
  use-four-byte   : bool = True
) : peer-session
  val bytes = serialize-message(msg, use-four-byte)
  peer(tx-queue = Cons(bytes, peer.tx-queue))

// Flush pending outbound frames from queue
pub fun peer-flush-tx(peer : peer-session) : (peer-session, list<list<int>>)
  val pending = peer.tx-queue.reverse
  (peer(tx-queue = []), pending)

// Feed newly received bytes from TCP socket into the peer stream reassembler.
// Extracts all complete, framed BGP messages.
pub fun peer-process-rx(
  peer          : peer-session,
  incoming      : list<int>,
  now           : int,
  use-four-byte : bool = True
) : div (peer-session, list<bgp-message>)
  val stream = peer.rx-buffer ++ incoming
  
  fun extract-frames(bytes : list<int>, acc : list<bgp-message>) : div (list<int>, list<bgp-message>)
    if bytes.length < bgp-header-length then
      (bytes, acc)
    else
      // Inspect header length
      val len-hi = bytes.drop(16).head.default(0)
      val len-lo = bytes.drop(17).head.default(0)
      val msg-len = (len-hi * 256) + len-lo
      
      if msg-len < bgp-header-length || msg-len > bgp-max-message-length then
        // Corrupt frame: discard leading byte to resynchronize on next marker
        extract-frames(bytes.drop(1), acc)
      elif bytes.length < msg-len then
        // Frame is incomplete; leave in buffer
        (bytes, acc)
      else
        val frame-bytes = bytes.take(msg-len)
        val remainder = bytes.drop(msg-len)
        match parse-message(frame-bytes, use-four-byte)
          Right(parsed-msg) ->
            extract-frames(remainder, Cons(parsed-msg, acc))
          Left(_) ->
            // Skip corrupt frame
            extract-frames(remainder, acc)
            
  val (leftover, messages) = extract-frames(stream, [])
  val updated-peer = peer(
    rx-buffer = leftover,
    last-rx-time = if incoming.is-empty then peer.last-rx-time else now
  )
  (updated-peer, messages.reverse)

// Check if keepalive transmission deadline has arrived
pub fun peer-needs-keepalive(peer : peer-session, now : int) : bool
  if !peer-is-established(peer) then False
  elif peer.negotiated-keepalive <= 0 then False
  else (now - peer.last-tx-time) >= peer.negotiated-keepalive

// Check if hold timer has expired without receiving traffic
pub fun peer-hold-expired(peer : peer-session, now : int) : bool
  if !peer-is-established(peer) then False
  elif peer.negotiated-hold <= 0 then False
  else (now - peer.last-rx-time) >= peer.negotiated-hold
