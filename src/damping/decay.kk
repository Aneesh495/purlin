// Module: damping/decay
// RFC 2439 BGP Route Flap Damping exponential decay and penalty curves.
//
// In carrier backbones and exchange points, oscillating routes (route flaps)
// trigger cascading BGP UPDATE waves. Route Flap Damping (RFD) mitigates this
// by tracking route oscillations with an exponential decay penalty metric.
//
// Mathematical Model (RFC 2439 §2.2):
//   P(t) = P_0 * (1/2)^(elapsed / half_life)
//
// When P(t) exceeds suppress_threshold, the route is suppressed.
// When P(t) decays below reuse_threshold, the route is restored to service.

module damping/decay

import std/core/list
import std/core/maybe
import std/core/string
import proto/types

// Configuration parameters governing route flap damping behavior
pub struct damping-config(
  half-life                : int, // Seconds for penalty to decay to half (default 900s / 15m)
  reuse-threshold          : int, // Penalty below which route is unsuppressed (default 750)
  suppress-threshold       : int, // Penalty above which route is suppressed (default 2000)
  max-suppress-time        : int, // Maximum seconds a route can remain suppressed (default 3600s / 60m)
  withdrawal-penalty       : int, // Penalty assessed on route withdrawal (default 1000)
  attribute-change-penalty : int  // Penalty assessed on attribute change (default 500)
)

// Recommended default RFD configuration according to RIPE-378 / RFC 2439
pub fun default-damping-config() : damping-config
  Damping-config(
    half-life = 900,
    reuse-threshold = 750,
    suppress-threshold = 2000,
    max-suppress-time = 3600,
    withdrawal-penalty = 1000,
    attribute-change-penalty = 500
  )

// Calculate penalty ceiling to prevent unbounded suppression duration.
// ceiling = reuse_threshold * 2^(max_suppress_time / half_life)
pub fun calculate-penalty-ceiling(cfg : damping-config) : int
  val max-halves = cfg.max-suppress-time / cfg.half-life
  val factor = pow2(max-halves)
  cfg.reuse-threshold * factor

// Compute exponential decay of a penalty value over elapsed seconds.
// P = initial_penalty * (1/2)^(elapsed / half_life)
// Computed accurately using integer fixed-point arithmetic without float instability.
pub fun decay-penalty(initial-penalty : int, elapsed-seconds : int, half-life-seconds : int) : int
  if elapsed-seconds <= 0 then initial-penalty
  elif initial-penalty <= 0 then 0
  elif half-life-seconds <= 0 then 0
  else
    val full-halves = elapsed-seconds / half-life-seconds
    if full-halves >= 30 then 0 // Penalty decays to zero after 30 half-lives
    else
      // First decay by full half-life divisions
      val p-after-halves = initial-penalty / pow2(full-halves)
      val rem-seconds = elapsed-seconds % half-life-seconds
      if rem-seconds == 0 then p-after-halves
      else
        // Interpolate remaining fraction: (1 - 0.5 * (rem / half_life))
        // Fixed-point scaling by 1000
        val frac-lost = (500 * rem-seconds) / half-life-seconds
        val frac-kept = 1000 - frac-lost
        (p-after-halves * frac-kept) / 1000

// Estimate remaining seconds until a suppressed penalty decays down to reuse_threshold
pub fun time-until-reuse(current-penalty : int, cfg : damping-config) : div int
  if current-penalty <= cfg.reuse-threshold then 0
  else
    // Estimate using binary search / step simulation
    fun estimate(lo : int, hi : int) : div int
      if lo >= hi then lo
      else
        val mid = lo + ((hi - lo) / 2)
        val decayed = decay-penalty(current-penalty, mid, cfg.half-life)
        if decayed <= cfg.reuse-threshold then
          estimate(lo, mid)
        else
          estimate(mid + 1, hi)
    estimate(0, cfg.max-suppress-time)
