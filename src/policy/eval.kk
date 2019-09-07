// Module: policy/eval
// Policy evaluation pipeline executing route-maps with algebraic effect handlers.
//
// This module implements the operational evaluation of BGP route policies.
// It executes ordered route-map clauses against candidate routes, triggering
// route-filter, route-mutate, and route-audit algebraic effects.

module policy/eval

import std/core/list
import std/core/maybe
import std/core/string
import proto/types
import proto/attr
import rib/table
import policy/ast
import policy/effects

// Check if a single route match condition holds for a given route
pub fun check-match-condition(m : route-match, route : bgp-route) : bool
  match m
    MatchPrefixList(plist) ->
      eval-prefix-list(plist, route.route-prefix) == PolicyPermit
    MatchAsPath(pat) ->
      match-as-path(pat, route.as-path)
    MatchCommunity(c-filt) ->
      match-community-filter(c-filt, route.communities)
    MatchMed(expected-med) ->
      route.med == expected-med
    MatchLocalPref(expected-pref) ->
      route.local-pref == expected-pref
    MatchNextHop(expected-nh) ->
      route.next-hop == expected-nh

// Check if all match criteria in a clause match the route (logical AND)
pub fun match-clause(clause : route-map-clause, route : bgp-route) : bool
  if clause.matches.is-empty then True // Empty match list matches all routes
  else clause.matches.all(fn(m) check-match-condition(m, route))

// Apply set actions via route-mutate effect
pub fun apply-set-action(s : route-set) : <route-mutate> ()
  match s
    SetLocalPref(p) -> mutate-local-pref(p)
    SetMed(m) -> mutate-med(m)
    SetWeight(w) -> mutate-weight(w)
    SetNextHop(nh) -> mutate-next-hop(nh)
    SetAsPathPrepend(asns) -> mutate-prepend(asns)
    SetCommunityAdd(c) -> mutate-add-community(c)
    SetCommunityDelete(c) -> mutate-delete-community(c)

// Apply all set actions in a clause
pub fun apply-sets(sets : list<route-set>) : <route-mutate> ()
  sets.foreach(apply-set-action)

// Core route-map evaluation function using algebraic effects.
// Scans clauses sequentially. On first matching clause:
//   - If Permit: applies sets, logs audit event, calls accept(), returns True
//   - If Deny: logs audit event, calls reject()
// If no clauses match, rejects with implicit deny.
pub fun eval-route-map-effects(rmap : route-map, route : bgp-route) : <route-filter,route-mutate,route-audit> bool
  fun loop(rem : list<route-map-clause>) : <route-filter,route-mutate,route-audit> bool
    match rem
      Nil ->
        audit-log(99999, PolicyDeny, "Implicit deny: no route-map clauses matched")
        reject("Implicit deny at end of route-map " ++ rmap.map-name)
      Cons(c, tail) ->
        if match-clause(c, route) then
          match c.clause-action
            PolicyPermit ->
              audit-log(c.seq-num, PolicyPermit, "Clause " ++ c.seq-num.show ++ " matched: permit")
              apply-sets(c.sets)
              accept()
              True
            PolicyDeny ->
              audit-log(c.seq-num, PolicyDeny, "Clause " ++ c.seq-num.show ++ " matched: deny")
              reject("Denied by route-map " ++ rmap.map-name ++ " clause " ++ c.seq-num.show)
        else
          loop(tail)
  loop(rmap.clauses)

// High-level pipeline runner: evaluates route-map and returns modified route if permitted,
// or Nothing if rejected.
pub fun eval-route-map(rmap : route-map, route : bgp-route) : maybe<bgp-route>
  val (res-and-route, _) = with-audit(fn() {
    with-mutation(route, fn() {
      with-filter(fn() {
        eval-route-map-effects(rmap, route)
      })
    })
  })
  match res-and-route
    (Just(_), mutated-route) -> Just(mutated-route)
    _ -> Nothing

// High-level pipeline runner with audit trace collection.
// Returns (permitted-route-opt, audit-event-log).
pub fun eval-route-map-with-audit(rmap : route-map, route : bgp-route) : (maybe<bgp-route>, list<audit-event>)
  val (res-and-route, events) = with-audit(fn() {
    with-mutation(route, fn() {
      with-filter(fn() {
        eval-route-map-effects(rmap, route)
      })
    })
  })
  val final-route = match res-and-route
    (Just(_), mutated-route) -> Just(mutated-route)
    _ -> Nothing
  (final-route, events)
