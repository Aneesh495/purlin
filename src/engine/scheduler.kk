// Module: engine/scheduler
// Event dispatcher, timer deadlines, and discrete-time scheduler.
//
// In an asynchronous routing engine, network I/O events (TCP packets),
// protocol timers (Keepalive, Hold Timer, Connect-Retry), and management
// operations (route injection, policy reload) must be serialized through
// a deterministic event loop.
//
// This module provides:
//   1. Unified engine event model
//   2. Priority event queueing
//   3. Discrete virtual/real clock advancement
//   4. Periodic timer deadline dispatching

module engine/scheduler

import std/core/list
import std/core/maybe
import std/core/string
import proto/types
import rib/table

// Engine event variants processed by the routing daemon
pub type engine-event
  EventTcpConnected(peer-ip : ipv4)
  EventTcpClosed(peer-ip : ipv4, reason : string)
  EventTcpData(peer-ip : ipv4, payload : list<int>)
  EventTimerTick(clock-now : int)
  EventInjectRoute(injected-route : bgp-route)
  EventWithdrawRoute(withdrawn-prefix : ip-prefix, peer-ip : ipv4)

pub fun engine-event/show(ev : engine-event) : string
  match ev
    EventTcpConnected(ip) -> "Event: TCP Connected to " ++ ip.show
    EventTcpClosed(ip, reason) -> "Event: TCP Closed for " ++ ip.show ++ " (" ++ reason ++ ")"
    EventTcpData(ip, bytes) -> "Event: TCP Data from " ++ ip.show ++ " (" ++ bytes.length.show ++ " bytes)"
    EventTimerTick(t) -> "Event: Timer Tick at " ++ t.show ++ "s"
    EventInjectRoute(r) -> "Event: Inject Route " ++ r.route-prefix.show
    EventWithdrawRoute(p, ip) -> "Event: Withdraw Route " ++ p.show ++ " from " ++ ip.show

// Scheduler state maintaining current timestamp and event queue
pub struct scheduler(
  clock-seconds  : int,
  event-queue    : list<engine-event>
)

pub fun scheduler-empty(initial-time : int = 0) : scheduler
  Scheduler(initial-time, [])

// Enqueue an event at the tail of the event queue (FIFO)
pub fun scheduler-enqueue(sched : scheduler, ev : engine-event) : scheduler
  sched(event-queue = sched.event-queue ++ [ev])

// Enqueue a batch of events
pub fun scheduler-enqueue-many(sched : scheduler, events : list<engine-event>) : scheduler
  sched(event-queue = sched.event-queue ++ events)

// Pop the next event from the head of the queue
pub fun scheduler-pop(sched : scheduler) : maybe<(engine-event, scheduler)>
  match sched.event-queue
    Cons(head-ev, rest) ->
      Just((head-ev, sched(event-queue = rest)))
    Nil -> Nothing

// Advance the scheduler clock to new-time and generate a timer tick event
pub fun scheduler-advance-clock(sched : scheduler, new-time : int) : scheduler
  val tick-ev = EventTimerTick(new-time)
  Scheduler(new-time, sched.event-queue ++ [tick-ev])

// Check if queue has pending events
pub fun scheduler-has-events(sched : scheduler) : bool
  !sched.event-queue.is-empty
