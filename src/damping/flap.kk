// Module: damping/flap
// RFC 2439 BGP Route Flap Damping state machine and event processor.
//
// When a route oscillates, penalty is added on withdrawal or attribute change.
// This module implements:
//   1. Flap record tracking per (Prefix, Peer) tuple
//   2. State transitions: Unsuppressed -> Suppressed -> History -> Unsuppressed
//   3. Penalty ceiling capping to prevent permanent suppression
//   4. Periodic decay sweep and unsuppression trigger

module damping/flap

import std/core/list
import std/core/maybe
import std/core/string
import proto/types
import damping/decay

// RFC 2439 Damping States
pub type damp-state
  DampUnsuppressed
  DampSuppressed
  DampHistory

pub fun damp-state/show(s : damp-state) : string
  match s
    DampUnsuppressed -> "Unsuppressed"
    DampSuppressed -> "Suppressed"
    DampHistory -> "History"

pub fun damp-state/(==)(a : damp-state, b : damp-state) : bool
  match (a, b)
    (DampUnsuppressed, DampUnsuppressed) -> True
    (DampSuppressed, DampSuppressed) -> True
    (DampHistory, DampHistory) -> True
    _ -> False

// Flap tracking record for a single route from a specific peer
pub struct flap-record(
  target-prefix    : ip-prefix,
  peer-ip          : ipv4,
  peer-asn         : asn,
  penalty          : int,
  last-update-time : int,        // Monotonic timestamp of last flap or decay
  suppress-time    : maybe<int>, // Monotonic timestamp when suppression began
  flap-count       : int,
  state            : damp-state
)

// In-memory table of route flap records
pub struct damp-table(
  records : list<flap-record>
)

pub fun damp-table-empty() : damp-table
  Damp-table([])

// Find existing record for (Prefix, Peer)
pub fun find-record(tbl : damp-table, pfx : ip-prefix, peer : ipv4) : maybe<flap-record>
  tbl.records.filter(fn(r) (r.target-prefix == pfx) && (r.peer-ip == peer)).head

// Update or insert a flap-record in the table
fun update-record(tbl : damp-table, rec : flap-record) : damp-table
  val filtered = tbl.records.filter(fn(r) !((r.target-prefix == rec.target-prefix) && (r.peer-ip == rec.peer-ip)))
  Damp-table(Cons(rec, filtered))

// Process a route withdrawal flap event
pub fun damp-on-withdrawal(
  tbl     : damp-table,
  pfx     : ip-prefix,
  peer    : ipv4,
  peer-as : asn,
  now     : int,
  cfg     : damping-config
) : damp-table
  val ceiling = calculate-penalty-ceiling(cfg)
  val existing = find-record(tbl, pfx, peer)
  
  val rec = match existing
    Just(prev) ->
      val elapsed = now - prev.last-update-time
      val decayed = decay-penalty(prev.penalty, elapsed, cfg.half-life)
      val new-penalty = min(decayed + cfg.withdrawal-penalty, ceiling)
      val new-state = if new-penalty >= cfg.suppress-threshold then DampSuppressed else DampHistory
      val s-time = if new-state == DampSuppressed && prev.suppress-time.is-nothing then Just(now)
                   else prev.suppress-time
      Flap-record(pfx, peer, peer-as, new-penalty, now, s-time, prev.flap-count + 1, new-state)
    Nothing ->
      val new-penalty = cfg.withdrawal-penalty
      val new-state = if new-penalty >= cfg.suppress-threshold then DampSuppressed else DampHistory
      val s-time = if new-state == DampSuppressed then Just(now) else Nothing
      Flap-record(pfx, peer, peer-as, new-penalty, now, s-time, 1, new-state)
      
  update-record(tbl, rec)

// Process a route announcement flap event.
// Returns (updated-table, is-suppressed).
pub fun damp-on-announce(
  tbl           : damp-table,
  pfx           : ip-prefix,
  peer          : ipv4,
  peer-as       : asn,
  now           : int,
  attr-changed  : bool,
  cfg           : damping-config
) : (damp-table, bool)
  val ceiling = calculate-penalty-ceiling(cfg)
  val existing = find-record(tbl, pfx, peer)
  
  match existing
    Just(prev) ->
      val elapsed = now - prev.last-update-time
      val decayed = decay-penalty(prev.penalty, elapsed, cfg.half-life)
      val added-penalty = if attr-changed then cfg.attribute-change-penalty else 0
      val new-penalty = min(decayed + added-penalty, ceiling)
      
      // Check suppression state transition
      val (new-state, s-time) = if prev.state == DampSuppressed then
        // If already suppressed, check if it has decayed below reuse threshold
        if new-penalty <= cfg.reuse-threshold then (DampUnsuppressed, Nothing)
        else (DampSuppressed, prev.suppress-time)
      else
        if new-penalty >= cfg.suppress-threshold then (DampSuppressed, Just(now))
        else (DampUnsuppressed, Nothing)
      
      val is-damped = (new-state == DampSuppressed)
      val rec = Flap-record(pfx, peer, peer-as, new-penalty, now, s-time, prev.flap-count, new-state)
      (update-record(tbl, rec), is-damped)
      
    Nothing ->
      // Fresh announcement without prior flap history is unsuppressed
      (tbl, False)

// Check if a route is currently suppressed
pub fun damp-is-suppressed(tbl : damp-table, pfx : ip-prefix, peer : ipv4) : bool
  match find-record(tbl, pfx, peer)
    Just(r) -> r.state == DampSuppressed
    Nothing -> False

// Sweep table, decaying all penalties to time `now`.
// Unsuppresses routes that decayed below reuse threshold.
// Purges history records whose penalty has decayed to near zero (< 50).
// Returns (updated-table, list-of-unsuppressed-prefixes).
pub fun damp-decay-sweep(
  tbl : damp-table,
  now : int,
  cfg : damping-config
) : (damp-table, list<ip-prefix>)
  var unsuppressed := []
  var kept-records := []
  
  tbl.records.foreach(fn(prev) {
    val elapsed = now - prev.last-update-time
    val decayed = decay-penalty(prev.penalty, elapsed, cfg.half-life)
    
    if prev.state == DampSuppressed then
      if decayed <= cfg.reuse-threshold then
        // Route unsuppressed!
        unsuppressed := Cons(prev.target-prefix, unsuppressed)
        val rec = Flap-record(
          prev.target-prefix, prev.peer-ip, prev.peer-asn,
          decayed, now, Nothing, prev.flap-count, DampUnsuppressed
        )
        kept-records := Cons(rec, kept-records)
      else
        // Remains suppressed
        val rec = prev(penalty = decayed, last-update-time = now)
        kept-records := Cons(rec, kept-records)
    elif prev.state == DampHistory then
      if decayed > 50 then
        // Still has significant penalty in history
        val rec = prev(penalty = decayed, last-update-time = now)
        kept-records := Cons(rec, kept-records)
      else () // Purge expired history record
    else
      if decayed > 50 then
        val rec = prev(penalty = decayed, last-update-time = now)
        kept-records := Cons(rec, kept-records)
      else ()
  })
  
  (Damp-table(kept-records.reverse), unsuppressed.reverse)
