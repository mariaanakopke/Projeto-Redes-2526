from datetime import datetime
from scapy.all import sniff, rdpcap
from parser_proto import PacketParser


_COR = {
    "reset":    "\033[0m",
    "negrito":  "\033[1m",
    "cinza":    "\033[90m",
    "verde":    "\033[92m",
    "amarelo":  "\033[93m",
    "azul":     "\033[94m",
    "magenta":  "\033[95m",
    "ciano":    "\033[96m",
    "vermelho": "\033[91m",
    "branco":   "\033[97m",
}

_COR_PROTO = {
    "ARP":    "amarelo",
    "ICMP":   "ciano",
    "ICMPV6": "ciano",
    "TCP":    "verde",
    "UDP":    "azul",
    "HTTP":   "magenta",
    "DNS":    "vermelho",
    "DHCP":   "branco",
    "IPv4":   "cinza",
    "IPv6":   "cinza",
}


def _cor(nome: str) -> str:
    return _COR.get(nome, "")


_COL_NO = 6
_COL_TIME = 14
_COL_SRC = 20
_COL_DST = 20
_COL_PROTO = 8
_COL_TTL = 5
_COL_LEN = 8
_COL_FRAG = 5
_COL_OFF = 7
_COL_FLAGS = 8


def _fit(text: str, width: int) -> str:
    value = str(text)
    if len(value) <= width:
        return value
    if width <= 3:
        return value[:width]
    return value[: width - 3] + "..."


class CaptureEngine:
    def __init__(self, iface=None, pcap_file=None, filters=None,
                 logger=None, analyzer=None, count=0):
        self.iface     = iface
        self.pcap_file = pcap_file
        self.filters   = filters
        self.logger    = logger
        self.analyzer  = analyzer
        self.count     = count
        self.stats     = {"total": 0, "accepted": 0, "dropped": 0}
        self.parser    = PacketParser()

    def start(self):
        if self.pcap_file:
            self._read_pcap()
        else:
            self._sniff_live()

    def _sniff_live(self):
        bpf = self.filters.to_bpf() if self.filters else None
        try:
            sniff(
                iface=self.iface,
                filter=bpf,
                prn=self._process,
                count=self.count,
                store=False,
            )
        except OSError as e:
            err = str(e).lower()
            if "no such device" in err:
                raise
            if bpf:
                print(f"\n[AVISO] BPF falhou ({e}).")
                print("[AVISO] A tentar sem filtro de kernel - filtro Python continua activo.\n")
                sniff(
                    iface=self.iface,
                    prn=self._process,
                    count=self.count,
                    store=False,
                )
            else:
                raise

    def _read_pcap(self):
        packets = rdpcap(self.pcap_file)
        for pkt in packets:
            self._process(pkt)

    def _process(self, pkt):
        self.stats["total"] += 1

        try:
            ts = datetime.fromtimestamp(float(pkt.time)).strftime("%H:%M:%S.%f")[:-3]
        except Exception:
            ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]

        parsed = self.parser.parse(pkt, ts, self.iface or "pcap")

        if self.filters and not self.filters.match(parsed):
            self.stats["dropped"] += 1
            return

        self.stats["accepted"] += 1
        self._display(parsed)

        if self.logger:
            self.logger.write(parsed)
        if self.analyzer:
            self.analyzer.process(parsed, pkt)

    def _display(self, p: dict):
        proto   = p.get("proto", "???")
        src     = _fit(p.get("src_ip") or p.get("src_mac") or "?", _COL_SRC)
        dst     = _fit(p.get("dst_ip") or p.get("dst_mac") or "?", _COL_DST)
        ttl     = p.get("ttl")
        ttl_str = str(ttl) if ttl is not None else "-"
        size    = _fit(f"{p.get('size', 0)}B", _COL_LEN)
        frag_id = p.get("frag_id")
        frag_offset = p.get("frag_offset")
        frag_mf = p.get("frag_mf")
        frag_df = p.get("frag_df")
        frag_id_str = _fit(str(frag_id) if frag_id is not None else "-", _COL_FRAG)
        frag_off_str = _fit(str(frag_offset) if frag_offset is not None else "-", _COL_OFF)
        frag_flags = []
        if frag_df:
            frag_flags.append("DF")
        if frag_mf:
            frag_flags.append("MF")
        frag_flags_str = _fit(" ".join(frag_flags) if frag_flags else "-", _COL_FLAGS)
        summary = p.get("summary", "")

        C_REQ = "\033[96m"
        C_REP = "\033[92m"
        C_ERR = "\033[91m"
        RESET = "\033[0m"

        raw_layers = p.get("raw_layers") or []
        is_ip_pkt = (
            p.get("proto") in ("IPv4", "IPv6")
            or "IP" in raw_layers
            or "IPv6" in raw_layers
        )
        ttl_low = isinstance(ttl, int) and is_ip_pkt and ttl <= 1

        # Análise de TTL excedido (Time Exceeded)
        if p.get("ttl_exceeded"):
            summary = summary.replace("Time Exceeded", f"{C_ERR}[TIME TO LIVE EXCEEDED]{RESET}")

        if "Query" in summary:
            summary = summary.replace("Query", f"{C_REQ}[REQUEST]{RESET} Query")
        elif "Response" in summary:
            summary = summary.replace("Response", f"{C_REP}[REPLY]{RESET} Response")

        for m in ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]:
            if f"HTTP {m}" in summary:
                summary = summary.replace(f"HTTP {m}", f"HTTP {C_REQ}[REQUEST]{RESET} {m}")
        if "HTTP Response" in summary:
            summary = summary.replace("HTTP Response", f"HTTP {C_REP}[REPLY]{RESET}")

        if proto == "DHCP":
            if any(k in summary for k in ("Discover", "Request")):
                summary = f"{C_REQ}[REQUEST]{RESET} " + summary
            elif any(k in summary for k in ("Offer", "ACK")):
                summary = f"{C_REP}[REPLY]{RESET} " + summary
            elif "NAK" in summary:
                summary = f"{C_ERR}[ERRO]{RESET} " + summary

        if "[SYN]" in summary and "[SYN+ACK]" not in summary:
            summary = summary.replace("[SYN]", f"{C_REQ}[TCP REQUEST - SYN]{RESET}")
        elif "[SYN+ACK]" in summary:
            summary = summary.replace("[SYN+ACK]", f"{C_REP}[TCP REPLY - SYN+ACK]{RESET}")
        elif "[FIN]" in summary:
            summary = summary.replace("[FIN]", f"{C_ERR}[FIN - Terminacao]{RESET}")
        elif "[RST]" in summary:
            summary = summary.replace("[RST]", f"{C_ERR}[RST - Reset]{RESET}")

        if "Dest Unreach" in summary:
            summary = summary.replace("Dest Unreach", f"{C_ERR}[ERRO] Dest Unreach{RESET}")
        elif "Time Exceeded" in summary and not p.get("ttl_exceeded"):
            summary = summary.replace("Time Exceeded", f"{C_ERR}[ERRO] Time Exceeded{RESET}")

        summary = summary.replace(" Request", f" {C_REQ}[REQUEST]{RESET}")
        summary = summary.replace(" Reply",   f" {C_REP}[REPLY]{RESET}")

        no       = self.stats["accepted"]
        cor_nome = _COR_PROTO.get(proto, "reset")
        cor      = _cor(cor_nome)
        rst      = _COR["reset"]
        dim      = _COR["cinza"]
        bold     = _COR["negrito"]
        ttl_fmt  = f"{C_ERR}{_fit(ttl_str, _COL_TTL):<{_COL_TTL}}{RESET}" if ttl_low else f"{dim}{_fit(ttl_str, _COL_TTL):<{_COL_TTL}}{rst}"
        proto_fmt = f"{bold}{cor}{_fit(proto, _COL_PROTO):<{_COL_PROTO}}{rst}"
        
        print(
            f"{dim}{no:<6}{rst} "
            f"{dim}{_fit(p['timestamp'], _COL_TIME):<{_COL_TIME}}{rst} "
            f"{src:<20} {dst:<20} "
            f"{proto_fmt} "
            f"{ttl_fmt} "
            f"{dim}{size:<8}{rst} "
            f"{dim}{frag_id_str:<{_COL_FRAG}}{rst} "
            f"{dim}{frag_off_str:<{_COL_OFF}}{rst} "
            f"{dim}{frag_flags_str:<{_COL_FLAGS}}{rst} "
            f"{summary}"
        )

        if ttl_low:
            print(f"       {C_ERR}|_ [ALERTA] TTL MUITO BAIXO!{RESET}")

        extras = []

        if p.get("tcp_seq") is not None and p.get("proto") not in ("TCP", "HTTP"):
            opts     = p.get("tcp_options") or {}
            wscale   = opts.get("WScale")
            win_real = (p["tcp_window"] << wscale) if wscale else p["tcp_window"]
            w_str    = f"win={win_real}B" + (f"(x2^{wscale})" if wscale else "")
            extras.append(f"seq={p['tcp_seq']} ack={p['tcp_ack']} {w_str}")
            if opts.get("MSS"):            extras.append(f"MSS={opts['MSS']}")
            if opts.get("SACK_Permitted"): extras.append("SACK")

        if p.get("frag_mf") or (p.get("frag_offset") or 0) > 0:
            extras.append(
                f"FRAG id={p['frag_id']} off={p['frag_offset']}B "
                f"{'MF' if p['frag_mf'] else 'last'}"
                f"{' DF' if p.get('frag_df') else ''}"
            )

        if p.get("icmp_id") is not None:
            extras.append(f"icmp_id={p['icmp_id']} seq={p['icmp_seq']}")

        if p.get("dns_id") is not None:
            rcode     = p.get("dns_rcode", 0)
            rcode_str = {0: "NOERROR", 2: "SERVFAIL", 3: "NXDOMAIN"}.get(rcode, str(rcode))
            extras.append(f"txid={p['dns_id']} {rcode_str}")

        if p.get("dhcp_xid") is not None:
            extras.append(f"xid={p['dhcp_xid']:#010x} type={p.get('dhcp_msg_type','?')}")

        if extras:
            print(f"       {dim}|_ {' | '.join(extras)}{rst}")

    def print_stats(self):
        total    = self.stats["total"]
        accepted = self.stats["accepted"]
        dropped  = self.stats["dropped"]
        pct = (dropped / total * 100) if total else 0
        print(
            f"\n[stats] Total: {total} | "
            f"Aceites: {accepted} | "
            f"Filtrados: {dropped} ({pct:.1f}%)"
        )
        assert accepted + dropped == total, "INVARIANTE VIOLADO: leakage de contagem!"
