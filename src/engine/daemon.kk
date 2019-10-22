// Module: engine/daemon
// Top-level BGP routing daemon coordinator and multi-peer engine.
//
// The daemon coordinator manages the lifecycle of all peer sessions,
// integrates the policy engine, coordinates RFC 6811 RPKI prefix validation,
// drives RFC 2439 route flap damping, and synthesizes the global FIB.
//
// This module provides:
//   1. Full daemon state encapsulating RIB, FIB, RPKI, Damping, and Peer sessions
//   2. Event loop processing TCP data, timeouts, and route injections
//   3. Inbound UPDATE handling with policy evaluation and RPKI tagging
//   4. Automated KEEPALIVE generation and dead peer termination

module engine/daemon

import std/core/list
import std/core/maybe
import std/core/string
import proto/types
import proto/wire
import proto/message
import proto/attr
import proto/fsm
import rib/table
import rib/decision
import fib/table
import fib/synth
import policy/ast
import policy/eval
import rpki/roa
import rpki/validator
import damping/decay
import damping/flap
import engine/peer
import engine/scheduler

// Main routing daemon state
pub struct bgp-daemon(
  local-asn      : asn,
  local-id       : router-id,
  peers          : list<peer-session>,
  rib            : rib-table,
  fib            : fib-table,
  igp            : igp-table,
  rpki           : roa-cache,
  flaps          : damp-table,
  decision-cfg   : decision-config,
  damping-cfg    : damping-config,
  sched          : scheduler
)

// Construct an initialized BGP routing daemon
pub fun daemon-create(
  asn-val  : asn,
  rid      : router-id,
  init-igp : igp-table = igp-table-empty()
) : bgp-daemon
  Bgp-daemon(
    local-asn = asn-val,
    local-id = rid,
    peers = [],
    rib = rib-empty(),
    fib = fib-empty(),
    igp = init-igp,
    rpki = roa-cache-empty(),
    flaps = damp-table-empty(),
    decision-cfg = decision-config-default(asn-val),
    damping-cfg = default-damping-config(),
    sched = scheduler-empty(1000)
  )

// Register a new BGP peering neighbor
pub fun daemon-add-peer(daemon : bgp-daemon, cfg : peer-config) : bgp-daemon
  val session = peer-create(cfg, daemon.local-id)
  daemon(peers = Cons(session, daemon.peers))

// Find a peer session by its remote IP address
pub fun daemon-find-peer(daemon : bgp-daemon, remote-ip : ipv4) : maybe<peer-session>
  daemon.peers.filter(fn(p) p.config.peer-ip == remote-ip).head

// Replace or update a peer session in the daemon
fun daemon-update-peer(daemon : bgp-daemon, updated : peer-session) : bgp-daemon
  val filtered = daemon.peers.filter(fn(p) !(p.config.peer-ip == updated.config.peer-ip))
  daemon(peers = Cons(updated, filtered))

// Process an incoming UPDATE message from a peer
pub fun daemon-handle-update(
  daemon    : bgp-daemon,
  sender-ip : ipv4,
  msg       : bgp-message
) : div bgp-daemon
  match msg
    MsgUpdate(withdrawn, path-attrs, nlri) ->
      val peer-opt = daemon-find-peer(daemon, sender-ip)
      match peer-opt
        Nothing -> daemon
        Just(peer) ->
          var cur-rib := daemon.rib
          var cur-flaps := daemon.flaps
          val now = daemon.sched.clock-seconds
          
          // 1. Process withdrawals
          withdrawn.foreach(fn(w-pfx) {
            cur-rib := rib-withdraw(cur-rib, w-pfx, sender-ip)
            cur-rib := rib-update-best-paths(cur-rib, w-pfx)
            cur-flaps := damp-on-withdrawal(cur-flaps, w-pfx, sender-ip, peer.config.peer-asn, now, daemon.damping-cfg)
          })
          
          // 2. Process announced prefixes
          nlri.foreach(fn(announced-pfx) {
            val base-route = route-from-attributes(
              announced-pfx,
              peer.config.peer-asn,
              sender-ip,
              Router-id(sender-ip),
              path-attrs,
              now
            )
            
            // Apply Inbound Route Policy if configured
            val filtered-route-opt = match peer.config.import-policy
              Just(rmap) -> eval-route-map(rmap, base-route)
              Nothing -> Just(base-route)
              
            match filtered-route-opt
              Just(policied-route) ->
                // Check Route Flap Damping
                val (flaps-after, is-damped) = damp-on-announce(
                  cur-flaps, announced-pfx, sender-ip, peer.config.peer-asn, now, False, daemon.damping-cfg
                )
                cur-flaps := flaps-after
                
                // Validate origin via RPKI
                val rpki-res = validate-bgp-route(daemon.rpki, policied-route, daemon.local-asn)
                val final-route = policied-route(
                  rpki = rpki-res.status,
                  is-damped = is-damped
                )
                
                cur-rib := rib-insert(cur-rib, final-route)
                cur-rib := rib-update-best-paths(cur-rib, announced-pfx)
              Nothing -> () // Dropped by policy
          })
          
          // 3. Re-synthesize FIB from updated RIB
          val new-fib = synthesize-fib(cur-rib, daemon.igp, now)
          val updated-peer = peer(routes-received = peer.routes-received + nlri.length)
          val daemon-with-peer = daemon-update-peer(daemon, updated-peer)
          
          daemon-with-peer(rib = cur-rib, fib = new-fib, flaps = cur-flaps)
    _ -> daemon

// Internal helper: update timers and keepalive/hold expirations for a single peer
fun tick-peer(p : peer-session, now : int) : peer-session
  val p-ka = if peer-needs-keepalive(p, now) then
    peer-queue-message(p, MsgKeepalive, True)(last-tx-time = now)
  else p
  
  if peer-hold-expired(p-ka, now) then
    val notif = MsgNotification(4, 0, [])
    val p-notif = peer-queue-message(p-ka, notif, True)
    val (p-dead, _) = peer-step-fsm(p-notif, EvHoldTimerExpires)
    p-dead
  else p-ka

// Advance timers and handle periodic keepalive/hold deadlines across all peers
pub fun daemon-timer-tick(daemon : bgp-daemon, now : int) : div bgp-daemon
  val updated-peers = daemon.peers.map(fn(p) tick-peer(p, now))
  
  // Sweep flap damping decay
  val (flaps-swept, unsuppressed) = damp-decay-sweep(daemon.flaps, now, daemon.damping-cfg)
  
  // If routes were unsuppressed, re-synthesize FIB
  val final-fib = if !unsuppressed.is-empty then
    synthesize-fib(daemon.rib, daemon.igp, now)
  else daemon.fib
  
  daemon(peers = updated-peers, fib = final-fib, flaps = flaps-swept)

// Step the daemon by processing the next pending event in the scheduler.
// Returns (updated-daemon, did-work-bool).
pub fun daemon-step(daemon : bgp-daemon) : div (bgp-daemon, bool)
  match scheduler-pop(daemon.sched)
    Just((ev, next-sched)) ->
      val d = daemon(sched = next-sched)
      val updated-d = match ev
        EventTimerTick(t) ->
          daemon-timer-tick(d, t)
        EventTcpData(from-ip, bytes) ->
          val peer-opt = daemon-find-peer(d, from-ip)
          match peer-opt
            Just(p) ->
              val (p-after-rx, msgs) = peer-process-rx(p, bytes, d.sched.clock-seconds, True)
              var d-iter := daemon-update-peer(d, p-after-rx)
              msgs.foreach(fn(m) {
                d-iter := daemon-handle-update(d-iter, from-ip, m)
              })
              d-iter
            Nothing -> d
        EventInjectRoute(r) ->
          val updated-rib = rib-update-best-paths(rib-insert(d.rib, r), r.route-prefix)
          val updated-fib = synthesize-fib(updated-rib, d.igp, d.sched.clock-seconds)
          d(rib = updated-rib, fib = updated-fib)
        EventWithdrawRoute(pfx, p-ip) ->
          val updated-rib = rib-update-best-paths(rib-withdraw(d.rib, pfx, p-ip), pfx)
          val updated-fib = synthesize-fib(updated-rib, d.igp, d.sched.clock-seconds)
          d(rib = updated-rib, fib = updated-fib)
        _ -> d
      (updated-d, True)
    Nothing ->
      (daemon, False)
