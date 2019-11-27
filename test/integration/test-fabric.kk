// Integration test: 5-node Clos spine-leaf datacenter fabric convergence and failover
module integration/test-fabric

import std/core/list
import std/core/maybe
import proto/types
import rib/table
import fib/table
import engine/daemon
import sim/topology
import sim/fabric

fun test-clos-fabric-convergence-and-failover() : <div,exn,console> bool
  val topo = build-clos-two-by-three()
  var fabric := init-clos-fabric(topo)
  
  // Step 1: Establish BGP peering across all links in the fabric
  fabric := fabric-establish-peering(fabric)
  
  // Step 2: Inject tenant subnet 10.101.0.0/16 on Leaf 1
  val tenant-pfx = prefix4(10, 101, 0, 0, 16)
  fabric := fabric-inject-leaf-prefix(fabric, "leaf1", tenant-pfx)
  
  // Step 3: Verify route installation and convergence across nodes
  val l1-has-route = fabric-leaf-has-route(fabric, "leaf1", tenant-pfx)
  val l2-has-route = fabric-leaf-has-route(fabric, "leaf2", tenant-pfx)
  val l3-has-route = fabric-leaf-has-route(fabric, "leaf3", tenant-pfx)
  
  // Verify packet forwarding LPM lookup on Leaf 2 and Leaf 3 for destination 10.101.42.1
  val test-dst = ipv4-create(10, 101, 42, 1)
  val l2-fn = fabric-find-node(fabric, "leaf2").unjust
  val l3-fn = fabric-find-node(fabric, "leaf3").unjust
  val l2-lpm = l2-fn.daemon.fib.fib-lpm(test-dst)
  val l3-lpm = l3-fn.daemon.fib.fib-lpm(test-dst)
  
  val t1 = l1-has-route
  val t2 = l2-has-route
  val t3 = l3-has-route
  val t4 = l2-lpm.is-just
  val t5 = l3-lpm.is-just
  
  // Step 4: Link Failure Chaos Simulation
  // Cut link between Leaf 2 and Spine 1 ("l2-s1")
  fabric := fabric-cut-link(fabric, "l2-s1")
  
  // Verify Leaf 2 still has an active route to 10.101.0.0/16 via surviving Spine 2!
  val l2-surviving-route = fabric-leaf-has-route(fabric, "leaf2", tenant-pfx)
  val l2-fn-after = fabric-find-node(fabric, "leaf2").unjust
  val l2-lpm-after = l2-fn-after.daemon.fib.fib-lpm(test-dst)
  
  val t6 = l2-surviving-route
  val t7 = l2-lpm-after.is-just
  
  // Verify surviving next-hop on Leaf 2 is Spine 2 (10.0.22.1)
  val t8 = match l2-fn-after.daemon.fib.fib-lookup-exact(tenant-pfx)
    Just(entry) ->
      entry.nexthops.any(fn(nh) nh.gateway-ip == ipv4-create(10, 0, 22, 1))
    Nothing -> False
    
  t1 && t2 && t3 && t4 && t5 && t6 && t7 && t8
    
  t1 && t2 && t3 && t4 && t5 && t6 && t7 && t8

pub fun main() : <div,exn,console> ()
  println("Running 5-Node Clos Spine-Leaf Fabric Simulation...")
  val ok = test-clos-fabric-convergence-and-failover()
  if ok then
    println("PASS: 5-Node Clos fabric converged and survived link failure with zero route loss")
  else
    println("FAIL: Clos fabric convergence or failover failed")
