// Module: evpn/routes
// RFC 7432 / RFC 9136 BGP EVPN NLRI Encoders, Decoders, and Route Types.
//
// EVPN NLRIs are carried in Multiprotocol BGP (AFI 25 = L2VPN, SAFI 70 = EVPN).
// This module implements serialization and deserialization for:
//   - Route Type 2: MAC/IP Advertisement Route (host reachability & mobility)
//   - Route Type 3: Inclusive Multicast Ethernet Tag (IMET) Route (BUM flood trees)
//   - Route Type 5: IP Prefix Route (symmetric/asymmetric inter-subnet routing)

module evpn/routes

import std/core/list
import std/core/maybe
import std/core/string
import proto/types
import proto/wire
import evpn/types

// EVPN Route Type Constants (RFC 7432 §7)
pub val evpn-type-ethernet-ad : int = 1
pub val evpn-type-mac-ip      : int = 2
pub val evpn-type-imet        : int = 3
pub val evpn-type-eth-segment : int = 4
pub val evpn-type-ip-prefix   : int = 5

// EVPN NLRI representation
pub type evpn-nlri
  EvpnTypeTwo(
    rd       : route-distinguisher,
    esi-val  : esi,
    eth-tag  : eth-tag,
    mac      : mac-address,
    ip-val   : maybe<ipv4>,
    vni-val  : vni
  )
  EvpnTypeThree(
    rd       : route-distinguisher,
    eth-tag  : eth-tag,
    orig-ip  : ipv4
  )
  EvpnTypeFive(
    rd       : route-distinguisher,
    esi-val  : esi,
    eth-tag  : eth-tag,
    pfx      : ip-prefix,
    gw-ip    : ipv4,
    vni-val  : vni
  )

pub fun evpn-nlri/show(nlri : evpn-nlri) : string
  match nlri
    EvpnTypeTwo(rd, esi-val, tag, mac, ip-opt, v) ->
      val ip-str = match ip-opt
        Just(ip) -> "/" ++ ip.show
        Nothing -> ""
      "[Type-2 RD=" ++ rd.show ++ " ESI=" ++ esi-val.show ++ " MAC=" ++ mac.show ++ ip-str ++ " " ++ v.show ++ "]"
    EvpnTypeThree(rd, tag, orig) ->
      "[Type-3 IMET RD=" ++ rd.show ++ " Tag=" ++ tag.show ++ " OrigIP=" ++ orig.show ++ "]"
    EvpnTypeFive(rd, esi-val, tag, pfx, gw, v) ->
      "[Type-5 RD=" ++ rd.show ++ " Prefix=" ++ pfx.show ++ " GW=" ++ gw.show ++ " " ++ v.show ++ "]"

// Encode an EVPN NLRI into wire bytes (including 2-byte header: Route Type, Length)
pub fun encode-evpn-nlri(nlri : evpn-nlri) : list<int>
  match nlri
    EvpnTypeTwo(rd, esi-val, tag, mac, ip-opt, v) ->
      val rd-bytes = encode-rd(rd)
      val esi-bytes = encode-esi(esi-val)
      val tag-bytes = write-u32(tag.tag-val)
      val mac-len = 48
      val mac-bytes = mac-to-bytes(mac)
      val (ip-len, ip-bytes) = match ip-opt
        Just(ip) -> (32, write-ipv4(ip))
        Nothing -> (0, [])
      val vni-bytes = vni-to-bytes(v)
      val payload = rd-bytes ++ esi-bytes ++ tag-bytes ++ [mac-len] ++ mac-bytes ++ [ip-len] ++ ip-bytes ++ vni-bytes
      [evpn-type-mac-ip, payload.length] ++ payload

    EvpnTypeThree(rd, tag, orig) ->
      val rd-bytes = encode-rd(rd)
      val tag-bytes = write-u32(tag.tag-val)
      val ip-len = 32
      val ip-bytes = write-ipv4(orig)
      val payload = rd-bytes ++ tag-bytes ++ [ip-len] ++ ip-bytes
      [evpn-type-imet, payload.length] ++ payload

    EvpnTypeFive(rd, esi-val, tag, pfx, gw, v) ->
      val rd-bytes = encode-rd(rd)
      val esi-bytes = encode-esi(esi-val)
      val tag-bytes = write-u32(tag.tag-val)
      val p-len = pfx.length
      val pfx-ip-bytes = match pfx.network
        V4(ip) -> write-ipv4(ip)
        V6(_) -> []
      val gw-bytes = write-ipv4(gw)
      val vni-bytes = vni-to-bytes(v)
      val payload = rd-bytes ++ esi-bytes ++ tag-bytes ++ [p-len] ++ pfx-ip-bytes ++ gw-bytes ++ vni-bytes
      [evpn-type-ip-prefix, payload.length] ++ payload

// Decode an EVPN NLRI from wire bytes
pub fun decode-evpn-nlri(bytes : list<int>) : maybe<evpn-nlri>
  if bytes.length < 2 then Nothing
  else
    val r-type = bytes.head.default(0)
    val r-len = bytes.drop(1).head.default(0)
    val body = bytes.drop(2).take(r-len)
    
    if r-type == evpn-type-mac-ip then
      // RD (8) + ESI (10) + EthTag (4) + MacLen (1) + MAC (6) + IpLen (1) + [IP] + VNI (3)
      if body.length < 33 then Nothing
      else
        val rd-opt = decode-rd(body.take(8))
        val esi-opt = decode-esi(body.drop(8).take(10))
        val tag-val = decode-u32(body.drop(18).head.default(0), body.drop(19).head.default(0),
                                 body.drop(20).head.default(0), body.drop(21).head.default(0))
        val mac-opt = mac-from-bytes(body.drop(23).take(6))
        val ip-len = body.drop(29).head.default(0)
        
        match (rd-opt, esi-opt, mac-opt)
          (Just(rd), Just(esi-val), Just(mac)) ->
            val (ip-opt, after-ip) = if ip-len == 32 then
              val ip = ipv4-create(body.drop(30).head.default(0), body.drop(31).head.default(0),
                                   body.drop(32).head.default(0), body.drop(33).head.default(0))
              (Just(ip), body.drop(34))
            else
              (Nothing, body.drop(30))
            
            val vni-val = vni-from-bytes(
              after-ip.head.default(0),
              after-ip.drop(1).head.default(0),
              after-ip.drop(2).head.default(0)
            )
            Just(EvpnTypeTwo(rd, esi-val, Eth-tag(tag-val), mac, ip-opt, vni-val))
          _ -> Nothing

    elif r-type == evpn-type-imet then
      // RD (8) + EthTag (4) + IpLen (1) + OrigIP (4) = 17 bytes
      if body.length < 17 then Nothing
      else
        val rd-opt = decode-rd(body.take(8))
        val tag-val = decode-u32(body.drop(8).head.default(0), body.drop(9).head.default(0),
                                 body.drop(10).head.default(0), body.drop(11).head.default(0))
        val orig-ip = ipv4-create(body.drop(13).head.default(0), body.drop(14).head.default(0),
                                  body.drop(15).head.default(0), body.drop(16).head.default(0))
        match rd-opt
          Just(rd) -> Just(EvpnTypeThree(rd, Eth-tag(tag-val), orig-ip))
          Nothing -> Nothing

    elif r-type == evpn-type-ip-prefix then
      // RD (8) + ESI (10) + EthTag (4) + PrefixLen (1) + PrefixIP (4) + GW (4) + VNI (3) = 34 bytes
      if body.length < 34 then Nothing
      else
        val rd-opt = decode-rd(body.take(8))
        val esi-opt = decode-esi(body.drop(8).take(10))
        val tag-val = decode-u32(body.drop(18).head.default(0), body.drop(19).head.default(0),
                                 body.drop(20).head.default(0), body.drop(21).head.default(0))
        val p-len = body.drop(22).head.default(0)
        val p-ip = ipv4-create(body.drop(23).head.default(0), body.drop(24).head.default(0),
                               body.drop(25).head.default(0), body.drop(26).head.default(0))
        val gw-ip = ipv4-create(body.drop(27).head.default(0), body.drop(28).head.default(0),
                                body.drop(29).head.default(0), body.drop(30).head.default(0))
        val vni-val = vni-from-bytes(
          body.drop(31).head.default(0),
          body.drop(32).head.default(0),
          body.drop(33).head.default(0)
        )
        match (rd-opt, esi-opt)
          (Just(rd), Just(esi-val)) ->
            val pfx = Ip-prefix(V4(p-ip), p-len)
            Just(EvpnTypeFive(rd, esi-val, Eth-tag(tag-val), pfx, gw-ip, vni-val))
          _ -> Nothing

    else Nothing
