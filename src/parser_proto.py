from scapy.all import Ether, ARP, IP, IPv6, ICMP, TCP, UDP, Raw
from scapy.all import IPv6ExtHdrFragment
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.dhcp import DHCP, BOOTP

try:
    from scapy.layers.inet6 import (
        ICMPv6EchoRequest, ICMPv6EchoReply,
        ICMPv6DestUnreach, ICMPv6TimeExceeded,
    )
    _HAS_ICMPV6 = True
except ImportError:
    _HAS_ICMPV6 = False
class PacketParser:
    _DHCP_TYPES = {
        1: "Discover", 2: "Offer",   3: "Request",
        4: "Decline",  5: "ACK",     6: "NAK",
        7: "Release",  8: "Inform",
    }

    _DNS_QTYPES = {
        1: "A", 2: "NS", 5: "CNAME", 6: "SOA",
        12: "PTR", 15: "MX", 16: "TXT",
        28: "AAAA", 33: "SRV", 255: "ANY",
    }

    _ICMP_TYPES = {
        0:  "Echo Reply",
        3:  "Dest Unreach",
        8:  "Echo Request",
        11: "Time Exceeded",
        12: "Parameter Problem",
    }

    _ICMP_UNREACH_CODES = {
        0: "Net Unreachable",    1: "Host Unreachable",
        2: "Protocol Unreach",   3: "Port Unreachable",
        4: "Fragmentation Needed", 5: "Source Route Failed",
        9: "Net Prohibited",     10: "Host Prohibited",
        13: "Comm Prohibited",
    }

    def _empty_record(self, timestamp: str, iface: str, pkt) -> dict:
        return {
            "timestamp":    timestamp,
            "iface":        iface,
            "size":         len(pkt),
            "payload_size": 0,
            "proto":        "UNKNOWN",
            "src_mac":      None,
            "dst_mac":      None,
            "src_ip":       None,
            "dst_ip":       None,
            "src_port":     None,
            "dst_port":     None,
            "ttl":          None,
            "ttl_exceeded": False,
            "flags":        None,
            "tcp_seq":      None,
            "tcp_ack":      None,
            "tcp_window":   None,
            "tcp_options":  None,
            "frag_id":      None,
            "frag_offset":  None,
            "frag_mf":      False,
            "frag_df":      False,
            "icmp_type":    None,
            "icmp_code":    None,
            "icmp_id":      None,
            "icmp_seq":     None,
            "dns_id":       None,
            "dns_qr":       None,
            "dns_rcode":    None,
            "dns_name":     None,
            "dns_qtype":    None,
            "dhcp_xid":     None,
            "dhcp_msg_type":None,
            "dhcp_yiaddr":  None,
            "dhcp_chaddr":  None,
            "dhcp_siaddr":  None,
            "summary":      "",
            "raw_layers":   [],
        }

    def parse(self, pkt, timestamp: str, iface: str) -> dict:
        record = self._empty_record(timestamp, iface, pkt)
        record["raw_layers"] = [type(l).__name__ for l in pkt.layers()]

        if pkt.haslayer(Ether):
            self._parse_ethernet(pkt, record)

        if pkt.haslayer(ARP):
            self._parse_arp(pkt, record)

        elif pkt.haslayer(IP):
            self._parse_ip(pkt, record)
            if pkt.haslayer(ICMP):
                self._parse_icmp(pkt, record)
            elif pkt.haslayer(TCP):
                self._parse_tcp(pkt, record)
            elif pkt.haslayer(UDP):
                self._parse_udp(pkt, record)

        elif pkt.haslayer(IPv6):
            self._parse_ipv6(pkt, record)
            if _HAS_ICMPV6:
                if pkt.haslayer(ICMPv6EchoRequest) or pkt.haslayer(ICMPv6EchoReply):
                    self._parse_icmpv6(pkt, record)
                elif pkt.haslayer(ICMPv6DestUnreach):
                    self._parse_icmpv6_error(pkt, record, 1, "Dest Unreach")
                elif pkt.haslayer(ICMPv6TimeExceeded):
                    self._parse_icmpv6_error(pkt, record, 3, "Time Exceeded")
            elif pkt.haslayer(TCP):
                self._parse_tcp(pkt, record)
            elif pkt.haslayer(UDP):
                self._parse_udp(pkt, record)

        if pkt.haslayer(Raw):
            record["payload_size"] = len(pkt[Raw].load)

        return record


    def _parse_ethernet(self, pkt, rec):
        rec["src_mac"] = pkt[Ether].src
        rec["dst_mac"] = pkt[Ether].dst

    def _parse_arp(self, pkt, rec):
        arp = pkt[ARP]
        rec["proto"]   = "ARP"
        rec["src_ip"]  = arp.psrc
        rec["dst_ip"]  = arp.pdst
        rec["src_mac"] = arp.hwsrc
        rec["dst_mac"] = arp.hwdst
        op = "Request" if arp.op == 1 else "Reply"
        rec["summary"] = f"ARP {op}: who has {arp.pdst}? tell {arp.psrc}"


    def _parse_ip(self, pkt, rec):
        ip = pkt[IP]
        rec["src_ip"]      = ip.src
        rec["dst_ip"]      = ip.dst
        rec["proto"]       = "IPv4"
        rec["ttl"]         = ip.ttl
        rec["frag_id"]     = ip.id
        rec["frag_offset"] = int(ip.frag) * 8
        flags_int          = int(ip.flags)
        rec["frag_df"]     = bool(flags_int & 0x2)
        rec["frag_mf"]     = bool(flags_int & 0x1)

        is_frag = rec["frag_mf"] or rec["frag_offset"] > 0
        rec["summary"] = (
            f"IPv4 ttl={ip.ttl} id={ip.id} "
            f"flags={'DF ' if rec['frag_df'] else ''}{'MF' if rec['frag_mf'] else ''} "
            f"frag_off={rec['frag_offset']}"
            + (" [FRAGMENTO]" if is_frag else "")
        )

    def _parse_ipv6(self, pkt, rec):
        ipv6 = pkt[IPv6]
        rec["proto"]  = "IPv6"
        rec["src_ip"] = ipv6.src
        rec["dst_ip"] = ipv6.dst
        rec["ttl"]    = ipv6.hlim

        if pkt.haslayer(IPv6ExtHdrFragment):
            frag = pkt[IPv6ExtHdrFragment]
            rec["frag_id"]     = frag.id
            rec["frag_offset"] = int(frag.offset) * 8
            rec["frag_mf"]     = bool(frag.m)
            rec["summary"] = (
                f"IPv6 hlim={ipv6.hlim} frag_id={frag.id} "
                f"frag_off={rec['frag_offset']} "
                f"{'MF' if rec['frag_mf'] else 'Last-frag'}"
            )
        else:
            rec["summary"] = f"IPv6 nh={ipv6.nh} hlim={ipv6.hlim}"


    def _parse_icmp(self, pkt, rec):
        icmp = pkt[ICMP]
        rec["proto"]     = "ICMP"
        rec["icmp_type"] = icmp.type
        rec["icmp_code"] = int(icmp.code)
        tipo_str         = self._ICMP_TYPES.get(icmp.type, f"type={icmp.type}")

        if icmp.type in (0, 8):
            rec["icmp_id"]  = icmp.id
            rec["icmp_seq"] = icmp.seq
            rec["summary"]  = f"ICMP {tipo_str} id={icmp.id} seq={icmp.seq}"

        elif icmp.type == 3:
            code_desc = self._ICMP_UNREACH_CODES.get(int(icmp.code), f"code={icmp.code}")
            detail = ""
            if icmp.haslayer(IP):
                inner  = icmp[IP]
                detail = f" (orig {inner.src} > {inner.dst}"
                if icmp.haslayer(TCP):
                    t = icmp[TCP]
                    detail += f":{t.sport} > {inner.dst}:{t.dport}"
                elif icmp.haslayer(UDP):
                    u = icmp[UDP]
                    detail += f":{u.sport} > {inner.dst}:{u.dport}"
                detail += ")"
            rec["summary"] = f"ICMP Dest Unreach: {code_desc}{detail}"

        elif icmp.type == 11:
            code_desc = (
                "TTL exceeded in transit" if int(icmp.code) == 0
                else "Fragment reassembly time exceeded"
            )
            # Marcar como TTL excedido para formatação especial
            rec["ttl_exceeded"] = True
            detail = ""
            if icmp.haslayer(IP):
                inner  = icmp[IP]
                detail = f" (orig TTL={inner.ttl} {inner.src} > {inner.dst})"
            rec["summary"] = f"ICMP Time Exceeded: {code_desc}{detail}"

        else:
            rec["summary"] = f"ICMP {tipo_str} code={icmp.code}"


    def _parse_icmpv6(self, pkt, rec):
        """Echo Request (type 128) e Echo Reply (type 129) IPv6."""
        rec["proto"] = "ICMPV6"
        if _HAS_ICMPV6 and pkt.haslayer(ICMPv6EchoRequest):
            msg = pkt[ICMPv6EchoRequest]
            rec["icmp_type"] = 128
            rec["icmp_code"] = 0
            rec["icmp_id"]   = msg.id
            rec["icmp_seq"]  = msg.seq
            rec["summary"]   = f"ICMPv6 Echo Request id={msg.id} seq={msg.seq}"
        elif _HAS_ICMPV6 and pkt.haslayer(ICMPv6EchoReply):
            msg = pkt[ICMPv6EchoReply]
            rec["icmp_type"] = 129
            rec["icmp_code"] = 0
            rec["icmp_id"]   = msg.id
            rec["icmp_seq"]  = msg.seq
            rec["summary"]   = f"ICMPv6 Echo Reply id={msg.id} seq={msg.seq}"

    def _parse_icmpv6_error(self, pkt, rec, icmp_type: int, label: str):
        rec["proto"]     = "ICMPV6"
        rec["icmp_type"] = icmp_type
        rec["icmp_code"] = 0
        rec["summary"]   = f"ICMPv6 {label}"


    def _parse_tcp(self, pkt, rec):
        tcp = pkt[TCP]
        rec["proto"]      = "TCP"
        rec["src_port"]   = tcp.sport
        rec["dst_port"]   = tcp.dport
        rec["flags"]      = self._decode_tcp_flags(tcp.flags)
        rec["tcp_seq"]    = tcp.seq
        rec["tcp_ack"]    = tcp.ack
        rec["tcp_window"] = tcp.window
        rec["tcp_options"]= self._parse_tcp_options(tcp.options)

        flags_str = rec["flags"]
        summary = (
            f"TCP {tcp.sport} > {tcp.dport} [{flags_str}] "
            f"seq={tcp.seq} ack={tcp.ack} win={tcp.window}"
        )

        if tcp.dport == 80 or tcp.sport == 80:
            if pkt.haslayer(HTTPRequest):
                req    = pkt[HTTPRequest]
                method = req.Method.decode() if req.Method else "?"
                path   = req.Path.decode()   if req.Path   else "/"
                host   = req.Host.decode()   if req.Host   else "?"
                summary      = f"HTTP {method} {host}{path}"
                rec["proto"] = "HTTP"
            elif pkt.haslayer(HTTPResponse):
                resp         = pkt[HTTPResponse]
                code         = resp.Status_Code.decode() if resp.Status_Code else "?"
                summary      = f"HTTP Response {code}"
                rec["proto"] = "HTTP"

        rec["summary"] = summary

    def _parse_udp(self, pkt, rec):
        udp = pkt[UDP]
        rec["proto"]    = "UDP"
        rec["src_port"] = udp.sport
        rec["dst_port"] = udp.dport
        rec["summary"]  = f"UDP {udp.sport} > {udp.dport} len={udp.len}"

        if udp.dport == 53 or udp.sport == 53:
            self._parse_dns(pkt, rec)
            return
        if udp.dport in (67, 68) or udp.sport in (67, 68):
            self._parse_dhcp(pkt, rec)


    def _parse_dns(self, pkt, rec):
        if not pkt.haslayer(DNS):
            rec["proto"] = "DNS"
            return

        dns = pkt[DNS]
        rec["proto"]    = "DNS"
        rec["dns_id"]   = dns.id
        rec["dns_qr"]   = dns.qr
        rec["dns_rcode"]= dns.rcode

        rcode_str = {0: "NOERROR", 2: "SERVFAIL", 3: "NXDOMAIN"}.get(
            dns.rcode, f"rcode={dns.rcode}"
        )

        if dns.qr == 0:
            if pkt.haslayer(DNSQR):
                q    = pkt[DNSQR]
                nome = q.qname.decode(errors="replace").rstrip(".")
                tipo = self._DNS_QTYPES.get(q.qtype, str(q.qtype))
                rec["dns_name"]  = nome
                rec["dns_qtype"] = tipo
                rec["summary"]   = f"DNS Query {tipo} {nome} (id={dns.id})"
            else:
                rec["summary"] = f"DNS Query (id={dns.id})"
        else:
            respostas = []
            rr = dns.an
            while rr and hasattr(rr, "rrname") and rr.rrname:
                tipo = self._DNS_QTYPES.get(rr.type, str(rr.type))
                nome = rr.rrname.decode(errors="replace").rstrip(".")
                if hasattr(rr, "rdata"):
                    respostas.append(f"{nome} {tipo} {rr.rdata}")
                rr = rr.payload if hasattr(rr, "payload") else None
                if not hasattr(rr, "rrname"):
                    break
            if respostas:
                rec["dns_name"] = respostas[0]
            rec["summary"] = (
                f"DNS Response {rcode_str} ({len(respostas)} rr) "
                f"id={dns.id}: " + "; ".join(respostas[:2])
            )


    def _parse_dhcp(self, pkt, rec):
        if not pkt.haslayer(BOOTP):
            return

        bootp = pkt[BOOTP]
        rec["proto"]       = "DHCP"
        rec["dhcp_xid"]    = bootp.xid
        rec["dhcp_yiaddr"] = str(bootp.yiaddr)
        rec["dhcp_siaddr"] = str(bootp.siaddr)

        if bootp.chaddr:
            mac_bytes          = bootp.chaddr[:6]
            rec["dhcp_chaddr"] = ":".join(f"{b:02x}" for b in mac_bytes)

        if pkt.haslayer(DHCP):
            dhcp     = pkt[DHCP]
            tipo_msg = None
            for opcao in dhcp.options:
                if isinstance(opcao, tuple) and opcao[0] == "message-type":
                    tipo_msg = opcao[1]
                    break
            nome_tipo           = self._DHCP_TYPES.get(tipo_msg, f"tipo={tipo_msg}")
            rec["dhcp_msg_type"]= nome_tipo

            descricao = f"DHCP {nome_tipo} xid={bootp.xid:#010x}"
            if rec["dhcp_yiaddr"] != "0.0.0.0":
                descricao += f" offer={rec['dhcp_yiaddr']}"
            if rec["dhcp_chaddr"]:
                descricao += f" client={rec['dhcp_chaddr']}"
            rec["summary"] = descricao
        else:
            rec["summary"] = f"BOOTP xid={bootp.xid:#010x}"


    @staticmethod
    def _decode_tcp_flags(flags) -> str:
        flag_map = [
            (0x002, "SYN"), (0x010, "ACK"), (0x001, "FIN"),
            (0x004, "RST"), (0x008, "PSH"), (0x020, "URG"),
            (0x040, "ECE"), (0x080, "CWR"),
        ]
        active = [name for bit, name in flag_map if int(flags) & bit]
        return "+".join(active) if active else "NONE"

    @staticmethod
    def _parse_tcp_options(options) -> dict:
        result = {}
        if not options:
            return result
        for opt in options:
            if not isinstance(opt, tuple):
                continue
            nome  = opt[0]
            valor = opt[1] if len(opt) > 1 else None
            if nome == "MSS":
                result["MSS"] = valor
            elif nome == "WScale":
                result["WScale"] = valor
            elif nome == "SAckOK":
                result["SACK_Permitted"] = True
            elif nome == "SAck":
                result["SACK_Blocks"] = valor
            elif nome == "Timestamp" and valor:
                result["TS_val"] = valor[0]
                result["TS_ecr"] = valor[1]
        return result
