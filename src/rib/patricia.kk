module rib/patricia

import std/core/list
import std/core/maybe
import proto/types

// Test bit at index 0..31 (0 is most significant bit)
pub fun test-ipv4-bit(ip-val : ipv4, bit-idx : int) : bool {
  if bit-idx < 0 || bit-idx >= 32 then False
  else {
    val bit-power = pow2(31 - bit-idx)
    (ip-val.addr / bit-power) % 2 == 1
  }
}

// Patricia Trie node polymorphic over payload type <a>
pub type patricia-node<a>
  PatEmpty
  PatNode(prefix-val : ip-prefix,
          entry      : maybe<a>,
          left       : patricia-node<a>,
          right      : patricia-node<a>)

// Patricia Trie wrapper
pub struct patricia-trie<a>
  root : patricia-node<a>

pub fun patricia-empty() : patricia-trie<a> {
  Patricia-trie(PatEmpty)
}

// Check if a node is empty
pub fun is-empty(trie : patricia-trie<a>) : bool {
  match trie.root
    PatEmpty -> True
    _ -> False
}

// Insert or update an entry for an IP prefix
pub fun patricia-insert(trie : patricia-trie<a>, p : ip-prefix, val-item : a) : div patricia-trie<a> {
  match p.network
    V4(net-ip) -> {
      fun insert-node(node, bit-idx) {
        if bit-idx >= p.length then {
          match node
            PatEmpty -> PatNode(p, Just(val-item), PatEmpty, PatEmpty)
            PatNode(cur-p, _, l, r) -> PatNode(cur-p, Just(val-item), l, r)
        } else {
          val is-right = test-ipv4-bit(net-ip, bit-idx)
          match node
            PatEmpty -> {
              if is-right then {
                val next-right = insert-node(PatEmpty, bit-idx + 1)
                PatNode(p, Nothing, PatEmpty, next-right)
              } else {
                val next-left = insert-node(PatEmpty, bit-idx + 1)
                PatNode(p, Nothing, next-left, PatEmpty)
              }
            }
            PatNode(cur-p, cur-val, l, r) -> {
              if is-right then {
                val next-right = insert-node(r, bit-idx + 1)
                PatNode(cur-p, cur-val, l, next-right)
              } else {
                val next-left = insert-node(l, bit-idx + 1)
                PatNode(cur-p, cur-val, next-left, r)
              }
            }
        }
      }
      Patricia-trie(insert-node(trie.root, 0))
    }
    V6(_) -> trie
}

// Exact lookup for an IP prefix
pub fun patricia-lookup-exact(trie : patricia-trie<a>, p : ip-prefix) : div maybe<a> {
  match p.network
    V4(net-ip) -> {
      fun lookup-node(node, bit-idx) {
        match node
          PatEmpty -> Nothing
          PatNode(cur-p, val-opt, l, r) -> {
            if bit-idx >= p.length then {
              if cur-p == p then val-opt else Nothing
            } else {
              val is-right = test-ipv4-bit(net-ip, bit-idx)
              if is-right then lookup-node(r, bit-idx + 1)
              else lookup-node(l, bit-idx + 1)
            }
          }
      }
      lookup-node(trie.root, 0)
    }
    V6(_) -> Nothing
}

// Longest Prefix Match (LPM): finds the most specific route covering destination IPv4
pub fun patricia-lpm(trie : patricia-trie<a>, dst-ip : ipv4) : div maybe<(ip-prefix, a)> {
  fun lpm-node(node, bit-idx, best-so-far) {
    match node
      PatEmpty -> best-so-far
      PatNode(cur-p, val-opt, l, r) -> {
        val updated-best = match val-opt
          Just(v) -> if prefix-contains-ipv4(cur-p, dst-ip) then Just((cur-p, v)) else best-so-far
          Nothing -> best-so-far
        
        if bit-idx >= 32 then updated-best
        else {
          val is-right = test-ipv4-bit(dst-ip, bit-idx)
          val next-child = if is-right then r else l
          lpm-node(next-child, bit-idx + 1, updated-best)
        }
      }
  }
  lpm-node(trie.root, 0, Nothing)
}

// Delete an IP prefix from the Patricia Trie
pub fun patricia-delete(trie : patricia-trie<a>, p : ip-prefix) : div patricia-trie<a> {
  match p.network
    V4(net-ip) -> {
      fun delete-node(node, bit-idx) {
        match node
          PatEmpty -> PatEmpty
          PatNode(cur-p, val-opt, l, r) -> {
            if bit-idx >= p.length then {
              if cur-p == p then {
                // Remove value. If both children are empty, prune node entirely
                match (l, r)
                  (PatEmpty, PatEmpty) -> PatEmpty
                  _ -> PatNode(cur-p, Nothing, l, r)
              } else node
            } else {
              val is-right = test-ipv4-bit(net-ip, bit-idx)
              val (new-l, new-r) = if is-right then (l, delete-node(r, bit-idx + 1))
                                   else (delete-node(l, bit-idx + 1), r)
              match (new-l, new-r, val-opt)
                (PatEmpty, PatEmpty, Nothing) -> PatEmpty
                _ -> PatNode(cur-p, val-opt, new-l, new-r)
            }
          }
      }
      Patricia-trie(delete-node(trie.root, 0))
    }
    V6(_) -> trie
}

// Flatten trie to list of (prefix, value) pairs
pub fun patricia-to-list(trie : patricia-trie<a>) : div list<(ip-prefix, a)> {
  fun collect(node, acc) {
    match node
      PatEmpty -> acc
      PatNode(cur-p, val-opt, l, r) -> {
        val with-curr = match val-opt
          Just(v) -> Cons((cur-p, v), acc)
          Nothing -> acc
        val with-left = collect(l, with-curr)
        collect(r, with-left)
      }
  }
  collect(trie.root, [])
}

// Count total prefixes stored in trie
pub fun patricia-count(trie : patricia-trie<a>) : div int {
  patricia-to-list(trie).length
}
