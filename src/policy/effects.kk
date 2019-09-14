// Module: policy/effects
// Algebraic effects for declarative BGP route policy evaluation and transformation.
//
// In Koka, algebraic effects allow clean separation between policy rule logic
// and operational execution semantics (filtering, mutation, audit logging,
// dry-run tracing).
//
// This module provides:
//   1. route-filter effect: non-local control flow for route acceptance and rejection
//   2. route-mutate effect: encapsulated stateful attribute modification
//   3. route-audit effect: structured telemetry tracking policy evaluation
//   4. Canonical effect handlers for production pipeline execution

module policy/effects

import std/core/list
import std/core/maybe
import std/core/string
import proto/types
import proto/attr
import policy/ast
import rib/table

// Structured audit event recording a policy rule execution step
pub struct audit-event(
  rule-seq     : int,
  disposition  : policy-disposition,
  description  : string
)

// Control flow effect: Route Filtering
// Allows an evaluation step to accept or abort early with a rejection reason
pub effect route-filter
  ctl reject(reason : string) : a
  fun accept() : ()

// State modification effect: Route Attribute Mutation
// Encapsulates all permitted BGP attribute modifications
pub effect route-mutate
  fun mutate-local-pref(new-pref : int) : ()
  fun mutate-med(new-med : int) : ()
  fun mutate-weight(new-weight : int) : ()
  fun mutate-next-hop(new-nh : ipv4) : ()
  fun mutate-prepend(asns : list<asn>) : ()
  fun mutate-add-community(c : community) : ()
  fun mutate-delete-community(c : community) : ()

// Telemetry effect: Route Policy Auditing
// Captures structured traces of matched rules and applied actions
pub effect route-audit
  fun audit-log(seq-num : int, disp : policy-disposition, desc : string) : ()

// Handler for route-filter effect.
// Catches reject() calls and translates them into Nothing.
// Successful evaluations that finish without reject() yield Just(result).
pub fun with-filter(action : () -> <route-filter|e> a) : e maybe<a>
  with handler
    ctl reject(_reason) Nothing
    fun accept() ()
  Just(action())

// Handler for route-mutate effect.
// Runs the action against an initial route and returns the mutated route.
pub fun with-mutation(initial-route : bgp-route, action : () -> <route-mutate|e> a) : e (a, bgp-route)
  var curr := initial-route
  with handler
    fun mutate-local-pref(p)
      curr := curr(local-pref = p)
    fun mutate-med(m)
      curr := curr(med = m)
    fun mutate-weight(w)
      curr := curr(weight = w)
    fun mutate-next-hop(nh)
      curr := curr(next-hop = nh)
    fun mutate-prepend(asns)
      val updated-path = asns.foldr(curr.as-path, fn(a, p) as-path-prepend(p, a))
      curr := curr(as-path = updated-path)
    fun mutate-add-community(c)
      if !curr.communities.any(fn(x) x == c) then
        curr := curr(communities = Cons(c, curr.communities))
      else ()
    fun mutate-delete-community(c)
      curr := curr(communities = curr.communities.filter(fn(x) x != c))
  val res = action()
  (res, curr)

// Handler for route-audit effect.
// Collects an ordered log of audit events during evaluation.
pub fun with-audit(action : () -> <route-audit|e> a) : e (a, list<audit-event>)
  var events := []
  with handler
    fun audit-log(seq, disp, desc)
      events := Cons(Audit-event(seq, disp, desc), events)
  val res = action()
  (res, events.reverse)
