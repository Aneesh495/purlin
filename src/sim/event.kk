// Simulation event model, transmission delays, and virtual fiber links
module sim/event

import std/core/list
import std/core/maybe
import proto/types

// Packet in transit across a virtual fiber link
pub struct in-flight-packet(
  src-node     : string,
  dst-node     : string,
  src-ip       : ipv4,
  dst-ip       : ipv4,
  payload      : list<int>,
  deliver-time : int // Monotonic millisecond or second timestamp
)

// Simulation discrete events
pub type sim-event
  SimPacketDelivery(pkt : in-flight-packet)
  SimLinkDown(link-id : string)
  SimLinkUp(link-id : string)
  SimInjectPrefix(node-id : string, pfx : ip-prefix)
  SimWithdrawPrefix(node-id : string, pfx : ip-prefix)
  SimClockTick(time-val : int)

// In-flight packet queue
pub struct packet-queue(
  packets : list<in-flight-packet>
)

pub fun packet-queue-empty() : packet-queue
  Packet-queue([])

// Enqueue an in-flight packet with propagation latency
pub fun queue-packet(
  q         : packet-queue,
  pkt       : in-flight-packet
) : packet-queue
  // Insert sorted by deliver-time
  fun insert-sorted(items : list<in-flight-packet>, item : in-flight-packet) : list<in-flight-packet>
    match items
      Nil -> [item]
      Cons(head, tail) ->
        if item.deliver-time < head.deliver-time then Cons(item, items)
        else Cons(head, insert-sorted(tail, item))
        
  Packet-queue(insert-sorted(q.packets, pkt))

// Drain packets that have arrived at or before the given current timestamp
pub fun drain-ready-packets(
  q   : packet-queue,
  now : int
) : (packet-queue, list<in-flight-packet>)
  val (ready, pending) = q.packets.partition(fn(p) p.deliver-time <= now)
  (Packet-queue(pending), ready)

// Filter packets belonging to a failed link
pub fun drop-link-packets(
  q       : packet-queue,
  node-a  : string,
  node-b  : string
) : packet-queue
  val surviving = q.packets.filter(fn(p) {
    val matches-link = (p.src-node == node-a && p.dst-node == node-b) ||
                       (p.src-node == node-b && p.dst-node == node-a)
    !matches-link
  })
  Packet-queue(surviving)
