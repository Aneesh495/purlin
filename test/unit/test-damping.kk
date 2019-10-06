// Unit tests for RFC 2439 Route Flap Damping decay curves and state machine
module unit/test-damping

import std/core/list
import std/core/maybe
import proto/types
import damping/decay
import damping/flap

fun test-decay-math() : div bool
  val half-life = 900 // 15 minutes
  
  // 0 seconds: unchanged
  val p0 = decay-penalty(1000, 0, half-life)
  val t1 = p0 == 1000
  
  // 1 half-life (900s): halved
  val p1 = decay-penalty(1000, 900, half-life)
  val t2 = p1 == 500
  
  // 2 half-lives (1800s): quartered
  val p2 = decay-penalty(1000, 1800, half-life)
  val t3 = p2 == 250
  
  // Fractional decay: 450s (0.5 half-life) ~ 750
  val p-half = decay-penalty(1000, 450, half-life)
  val t4 = (p-half >= 700) && (p-half <= 800)
  
  // Penalty ceiling computation
  val cfg = default-damping-config()
  val ceiling = calculate-penalty-ceiling(cfg)
  // max-suppress-time 3600 / half-life 900 = 4 half-lives. 2^4 = 16. ceiling = 750 * 16 = 12000
  val t5 = ceiling == 12000
  
  // Time until reuse: 2000 down to 750
  val t-reuse = time-until-reuse(2000, cfg)
  val t6 = (t-reuse >= 1200) && (t-reuse <= 1500)
  
  t1 && t2 && t3 && t4 && t5 && t6

fun test-flap-state-machine() : bool
  val cfg = default-damping-config()
  val pfx = prefix4(198, 51, 100, 0, 24)
  val peer = ipv4-create(192, 0, 2, 1)
  val peer-as = asn(64496)
  
  var tbl := damp-table-empty()
  var clock := 1000
  
  // Event 1: First route withdrawal (t=1000)
  // Adds 1000 penalty. 1000 < suppress_threshold (2000) -> State is DampHistory
  tbl := damp-on-withdrawal(tbl, pfx, peer, peer-as, clock, cfg)
  val rec1 = find-record(tbl, pfx, peer)
  val t1 = match rec1
    Just(r) -> (r.penalty == 1000) && (r.state == DampHistory)
    Nothing -> False
  val t2 = !damp-is-suppressed(tbl, pfx, peer)
  
  // Event 2: Second withdrawal in quick succession (t=1000)
  // 1000 + 1000 = 2000 >= suppress_threshold (2000) -> Transitions to DampSuppressed!
  tbl := damp-on-withdrawal(tbl, pfx, peer, peer-as, clock, cfg)
  val rec2 = find-record(tbl, pfx, peer)
  val t3 = match rec2
    Just(r) -> (r.penalty >= 2000) && (r.state == DampSuppressed)
    Nothing -> False
  val t4 = damp-is-suppressed(tbl, pfx, peer)
  
  // Event 3: Route is re-announced while suppressed (t=1000)
  // Announcement should be flagged as suppressed
  val (tbl-ann, is-suppressed) = damp-on-announce(tbl, pfx, peer, peer-as, clock, False, cfg)
  tbl := tbl-ann
  val t5 = is-suppressed == True
  val t6 = damp-is-suppressed(tbl, pfx, peer)
  
  // Event 4: Time passes by 1800s (2 half-lives) without flaps (t=2800)
  // Penalty decays from 2000 by factor of 4 down to 500 (< reuse_threshold 750)
  clock := 2800
  val (tbl-swept, unsuppressed-list) = damp-decay-sweep(tbl, clock, cfg)
  val t7 = unsuppressed-list.length == 1
  val t8 = match unsuppressed-list
    Cons(p, _) -> p == pfx
    Nil -> False
  val t9 = !damp-is-suppressed(tbl-swept, pfx, peer)
  
  t1 && t2 && t3 && t4 && t5 && t6 && t7 && t8 && t9

pub fun main() : <div,console> ()
  val t1 = test-decay-math()
  val t2 = test-flap-state-machine()
  if t1 && t2 then
    println("PASS: damping subsystem unit tests passed successfully")
  else
    println("FAIL: damping subsystem unit tests failed")
