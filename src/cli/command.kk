// Operator CLI command definitions and argument parser
module cli/command

import std/core/list
import std/core/maybe
import std/core/string
import proto/types

// Operator CLI commands supported by the Purlin daemon
pub type cli-command
  CmdShowBgpSummary
  CmdShowRib(pfx-filter : maybe<ip-prefix>)
  CmdShowFib(dst-filter : maybe<ipv4>)
  CmdShowRpki
  CmdShowDamping
  CmdShowVersion
  CmdRunDaemon(config-path : string)
  CmdHelp
  CmdUnknown(raw-str : string)

pub fun cli-command/show(cmd : cli-command) : string
  match cmd
    CmdShowBgpSummary -> "show bgp summary"
    CmdShowRib(pfx) ->
      match pfx
        Just(p) -> "show bgp rib " ++ p.show
        Nothing -> "show bgp rib"
    CmdShowFib(dst) ->
      match dst
        Just(ip) -> "show fib " ++ ip.show
        Nothing -> "show fib"
    CmdShowRpki -> "show rpki"
    CmdShowDamping -> "show damping"
    CmdShowVersion -> "version"
    CmdRunDaemon(path) -> "daemon " ++ path
    CmdHelp -> "help"
    CmdUnknown(s) -> "unknown: " ++ s

// Parse string command-line arguments into structured cli-command
pub fun parse-cli-args(args : list<string>) : cli-command
  match args
    Nil -> CmdHelp
    Cons("help", _) -> CmdHelp
    Cons("--help", _) -> CmdHelp
    Cons("-h", _) -> CmdHelp
    Cons("version", _) -> CmdShowVersion
    Cons("--version", _) -> CmdShowVersion
    Cons("-v", _) -> CmdShowVersion
    
    // show bgp summary
    Cons("show", Cons("bgp", Cons("summary", _))) ->
      CmdShowBgpSummary
      
    // show bgp rib [prefix]
    Cons("show", Cons("bgp", Cons("rib", rest))) ->
      match rest
        Cons(pfx-str, _) ->
          match parse-ipv4-prefix-str(pfx-str)
            Just(p) -> CmdShowRib(Just(p))
            Nothing -> CmdShowRib(Nothing)
        Nil -> CmdShowRib(Nothing)
        
    // show fib [ip]
    Cons("show", Cons("fib", rest)) ->
      match rest
        Cons(ip-str, _) ->
          match parse-ipv4-str(ip-str)
            Just(ip) -> CmdShowFib(Just(ip))
            Nothing -> CmdShowFib(Nothing)
        Nil -> CmdShowFib(Nothing)
        
    // show rpki
    Cons("show", Cons("rpki", _)) ->
      CmdShowRpki
      
    // show damping
    Cons("show", Cons("damping", _)) ->
      CmdShowDamping
      
    // daemon <config.json>
    Cons("daemon", Cons(cfg-path, _)) ->
      CmdRunDaemon(cfg-path)
      
    Cons(other, rest) ->
      CmdUnknown(other ++ " " ++ rest.join(" "))

// Helper: parse string "10.0.0.0/16" into ip-prefix
fun parse-ipv4-prefix-str(s : string) : maybe<ip-prefix>
  val parts = s.split("/")
  if parts.length != 2 then Nothing
  else
    val ip-str = parts.head.default("")
    val len-str = parts.drop(1).head.default("")
    match (parse-ipv4-str(ip-str), parse-int(len-str))
      (Just(ip), Just(l)) ->
        if l >= 0 && l <= 32 then
          Just(Ip-prefix(V4(ip), l))
        else Nothing
      _ -> Nothing

// Helper: parse string "192.168.1.1" into ipv4
fun parse-ipv4-str(s : string) : maybe<ipv4>
  val octets = s.split(".")
  if octets.length != 4 then Nothing
  else
    val b0 = parse-int(octets.head.default(""))
    val b1 = parse-int(octets.drop(1).head.default(""))
    val b2 = parse-int(octets.drop(2).head.default(""))
    val b3 = parse-int(octets.drop(3).head.default(""))
    match (b0, b1, b2, b3)
      (Just(o0), Just(o1), Just(o2), Just(o3)) ->
        if o0 >= 0 && o0 <= 255 && o1 >= 0 && o1 <= 255 &&
           o2 >= 0 && o2 <= 255 && o3 >= 0 && o3 <= 255 then
          Just(ipv4-create(o0, o1, o2, o3))
        else Nothing
      _ -> Nothing
