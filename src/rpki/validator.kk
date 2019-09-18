// Module: rpki/validator
// RFC 6811 BGP Prefix Origin Validation (POV) algorithm.
//
// Prefix Origin Validation protects Autonomous Systems from BGP route hijacking
// by cryptographically verifying that the origin AS announcing a route prefix
// matches an authorized Route Origin Authorization (ROA) payload.
//
// States defined in RFC 6811 §2:
//   - NotFound: No covering ROA exists for the route prefix
//   - Valid: At least one covering ROA matches origin ASN and prefix length <= max-length
//   - Invalid: Covering ROA(s) exist, but none authorize the prefix/ASN combination

module rpki/validator

import std/core/list
import std/core/maybe
import std/core/string
import proto/types
import proto/attr
import rib/table
import rpki/roa

// Detailed diagnostic explanation of validation outcome
pub type validation-reason
  ReasonNotFound
  ReasonValid(authorized-by : roa-payload)
  ReasonInvalidLengthExceeded(route-len : int, max-allowed : int, roa-asn : asn)
  ReasonInvalidAsnMismatch(route-asn : asn, expected-asns : list<asn>)

pub fun validation-reason/show(r : validation-reason) : string
  match r
    ReasonNotFound -> "NotFound: No covering VRP in cache"
    ReasonValid(roa) -> "Valid: Authorized by " ++ roa.show
    ReasonInvalidLengthExceeded(rlen, max-len, a) ->
      "Invalid: Prefix length /" ++ rlen.show ++ " exceeds max-length /" ++ max-len.show ++ " for AS" ++ a.show
    ReasonInvalidAsnMismatch(orig, expected) ->
      val exp-str = expected.map(fn(a) "AS" ++ a.show).join(", ")
      "Invalid: Origin AS" ++ orig.show ++ " not authorized (expected: " ++ exp-str ++ ")"

// Complete RFC 6811 validation result
pub struct validation-result(
  status         : rpki-status,
  reason         : validation-reason,
  covering-roas  : list<roa-payload>
)

// Extract origin ASN from AS_PATH (rightmost AS in sequence)
pub fun extract-origin-asn(path : as-path, default-local : asn) : asn
  val asns = as-path-asns(path)
  match asns.reverse
    Cons(orig, _) -> orig
    Nil -> default-local

// RFC 6811 §2 Prefix Origin Validation algorithm
pub fun validate-prefix-origin(
  cache      : roa-cache,
  target-pfx : ip-prefix,
  origin-as  : asn
) : div validation-result
  val covering = roa-cache-lookup-covering(cache, target-pfx)
  if covering.is-empty then
    Validation-result(RpkiNotFound, ReasonNotFound, [])
  else
    // Check if any covering ROA matches ASN and length bounds
    val valid-match = covering.filter(fn(r) {
      (r.origin-asn == origin-as) && (target-pfx.length <= r.max-length)
    })
    match valid-match
      Cons(matching-roa, _) ->
        Validation-result(RpkiValid, ReasonValid(matching-roa), covering)
      Nil ->
        // Disallowed: diagnose whether length exceeded or ASN mismatched
        val same-asn = covering.filter(fn(r) r.origin-asn == origin-as)
        match same-asn
          Cons(roa-len-fail, _) ->
            val reason = ReasonInvalidLengthExceeded(target-pfx.length, roa-len-fail.max-length, origin-as)
            Validation-result(RpkiInvalid, reason, covering)
          Nil ->
            val exp-asns = covering.map(fn(r) r.origin-asn)
            val reason = ReasonInvalidAsnMismatch(origin-as, exp-asns)
            Validation-result(RpkiInvalid, reason, covering)

// Convenience function to validate an entire BGP route
pub fun validate-bgp-route(cache : roa-cache, route : bgp-route, local-asn : asn) : div validation-result
  val orig-as = extract-origin-asn(route.as-path, local-asn)
  validate-prefix-origin(cache, route.route-prefix, orig-as)
