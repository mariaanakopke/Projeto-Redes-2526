import time
from collections import defaultdict, Counter
from datetime import datetime
from typing import Optional


# -- Cores ANSI --
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


# -- Helpers de formatacao --

def _barra(pct: float, largura: int = 20) -> str:
    """Barra de progresso com caracteres Unicode."""
    cheio = round(pct / 100 * largura)
    return "█" * cheio + "░" * (largura - cheio)


def _sparkline(valores: list, altura: int = 1) -> str:
    """Gera sparkline a partir de lista de valores."""
    if not valores:
        return ""
    max_val = max(valores) if valores else 1
    if max_val == 0:
        return " " * len(valores)
    sparkchars = "▁▂▃▄▅▆▇█"
    return "".join(sparkchars[min(7, int(v / max_val * 8))] for v in valores)


def _fmt_bytes(b: int) -> str:
    if b < 1024:        return f"{b} B"
    elif b < 1_048_576: return f"{b/1024:.1f} KB"
    return f"{b/1_048_576:.1f} MB"


class TCPState:
    """Full TCP connection state machine with directional role tracking."""

    CLOSED        = "CLOSED"
    SYN_SENT      = "SYN_SENT"
    SYN_RECEIVED  = "SYN_RECEIVED"
    ESTABLISHED   = "ESTABLISHED"
    FIN_WAIT      = "FIN_WAIT"
    CLOSED_CLEAN  = "CLOSED (FIN)"

    def __init__(self, flow_key: str, client: str, server: str):
        self.flow_key   = flow_key
        self.client     = client
        self.server     = server
        self.state      = self.CLOSED
        self.history    = []
        self.start_time = datetime.now()
        self.client_seq_base: Optional[int] = None
        self.server_seq_base: Optional[int] = None
        self.bytes_client_to_server: int = 0
        self.bytes_server_to_client: int = 0
        self._last_client_ack: Optional[int] = None
        self._last_server_ack: Optional[int] = None

    def group_key(self):
        client_ip = self.client.rsplit(":", 1)[0]
        server_ip, server_port = self.server.rsplit(":", 1)
        return (client_ip, server_ip, server_port)

    def summary_steps(self) -> str:
        steps = []
        for _, flags, _, _ in self.history:
            if flags not in steps:
                steps.append(flags)
        if not steps:
            return "-"
        if len(steps) > 5:
            return " -> ".join(steps[:5]) + " -> ..."
        return " -> ".join(steps)

    def summary_card(self, index: int) -> dict:
        duration = (datetime.now() - self.start_time).total_seconds()
        dados = (
            f"{_fmt_bytes(self.bytes_client_to_server)} / "
            f"{_fmt_bytes(self.bytes_server_to_client)}"
        )
        return {
            "index": index,
            "flow": f"{self.client} -> {self.server}",
            "state": self.state,
            "duration": f"{duration:.2f}s",
            "data": dados,
            "events": self.summary_steps(),
        }

    def transition(self, flags: str, src_endpoint: str,
                   timestamp: str, tcp_seq: Optional[int] = None,
                   tcp_ack: Optional[int] = None,
                   payload_len: int = 0) -> Optional[str]:
        """
        Process TCP flags and return an event message if a relevant
        state transition occurred.

        Parameters
        ----------
        flags        : decoded flag string, e.g. "SYN", "SYN+ACK", "ACK"
        src_endpoint : "ip:port" of the packet sender
        timestamp    : formatted timestamp string
        tcp_seq      : TCP sequence number
        tcp_ack      : TCP acknowledgement number
        payload_len  : number of application payload bytes in this segment
        """
        old_state = self.state
        event     = None

        from_client = (src_endpoint == self.client)

        if "SYN" in flags and "ACK" not in flags:
            if self.state == self.CLOSED and from_client:
                self.state = self.SYN_SENT
                if tcp_seq is not None:
                    self.client_seq_base = tcp_seq
                event = f"[TCP] {self.flow_key} SYN  | {self.client}  {self.server} iniciando ligação"

        elif "SYN" in flags and "ACK" in flags:
            if self.state == self.SYN_SENT and not from_client:
                self.state = self.SYN_RECEIVED
                if tcp_seq is not None:
                    self.server_seq_base = tcp_seq
                event = f"[TCP] {self.flow_key} SYN+ACK | {self.server}  {self.client} servidor respondeu"

        elif flags == "ACK":
            if self.state == self.SYN_RECEIVED and from_client:
                self.state = self.ESTABLISHED
                event = f"[TCP] {self.flow_key} ACK | ESTABLISHED (handshake completo!)"
            elif self.state in (self.ESTABLISHED, self.FIN_WAIT):
                self._track_data(from_client, tcp_seq, tcp_ack, payload_len)

        elif "PSH" in flags and "ACK" in flags:
            if self.state == self.ESTABLISHED:
                self._track_data(from_client, tcp_seq, tcp_ack, payload_len)

        elif "FIN" in flags:
            if self.state == self.ESTABLISHED:
                self.state = self.FIN_WAIT
                direction = f"{self.client}  {self.server}" if from_client else f"{self.server}  {self.client}"
                event = (
                    f"[TCP] {self.flow_key} FIN | início de terminação ({direction}) "
                    f"{self.bytes_client_to_server}B {self.bytes_server_to_client}B"
                )
            elif self.state == self.FIN_WAIT:
                self.state = self.CLOSED_CLEAN
                event = f"[TCP] {self.flow_key} FIN+ACK | CLOSED"

        elif "RST" in flags:
            self.state = self.CLOSED
            event = f"[TCP] {self.flow_key} RST | ligação resetada abruptamente"

        if old_state != self.state:
            self.history.append((timestamp, flags, "client" if from_client else "server", self.state))

        return event

    def print_diagram(self):
        """Imprime o diagrama de sequência reconstruído a partir dos eventos reais."""
        C = self.client.split(":")[0]   # IP do cliente (sem porta)
        S = self.server.split(":")[0]   # IP do servidor (sem porta)
        duracao = (datetime.now() - self.start_time).total_seconds()

        _SETAS = {
            ("SYN",     "client"): (f"{C}", "---- SYN ------------------>", f"{S}"),
            ("SYN+ACK", "server"): (f"{C}", "<-- SYN+ACK ---------------", f"{S}"),
            ("ACK",     "client"): (f"{C}", "---- ACK ------------------>", f"{S}"),
            ("FIN",     "client"): (f"{C}", "---- FIN+ACK --------------->", f"{S}"),
            ("FIN",     "server"): (f"{C}", "<-- FIN+ACK ---------------", f"{S}"),
            ("FIN+ACK", "client"): (f"{C}", "---- FIN+ACK --------------->", f"{S}"),
            ("FIN+ACK", "server"): (f"{C}", "<-- FIN+ACK ---------------", f"{S}"),
            ("RST",     "client"): (f"{C}", "---- RST ------------------>", f"{S}"),
            ("RST",     "server"): (f"{C}", "<-- RST -------------------", f"{S}"),
        }

        linhas = []
        for ts, flags, role, estado in self.history:
            chave = (flags, role)
            if chave in _SETAS:
                esq, seta, dir_ = _SETAS[chave]
                diagrama = f"{esq} {seta} {dir_}"
            else:
                diagrama = f"[{role}] {flags}"

            nota = ""
            if estado == self.ESTABLISHED:
                nota = "  <- ESTABLISHED [OK]"
            elif estado == self.CLOSED_CLEAN:
                nota = "  <- CLOSED [OK]"
            elif estado == self.CLOSED:
                nota = "  <- RESET [x]"

            linhas.append((ts, f"{diagrama}{nota}"))

        conteudos = [
            f"TCP Flow : {self.flow_key}",
            f"Estado   : {self.state}",
            f"Duracao  : {duracao:.2f}s",
            f"Dados    : Cliente->Servidor {_fmt_bytes(self.bytes_client_to_server)}  Servidor->Cliente {_fmt_bytes(self.bytes_server_to_client)}",
            "Timestamp   |  Diagrama",
        ]
        conteudos.extend(f"{ts} |  {linha}" for ts, linha in linhas)

        larg = max(62, max(len(texto) for texto in conteudos) + 4)

        print(f"  +{'-'*larg}+")
        print(f"  |  TCP Flow : {self.flow_key:<{larg-14}}|")
        print(f"  |  Estado   : {self.state:<{larg-14}}|")
        print(f"  |  Duracao  : {duracao:.2f}s{'':<{larg-20}}|")
        print(f"  |  Dados    : Cliente->Servidor {_fmt_bytes(self.bytes_client_to_server):<10}"
              f"  Servidor->Cliente {_fmt_bytes(self.bytes_server_to_client):<{larg-55}}|")
        print(f"  +{'-'*12}+{'-'*(larg-13)}+")
        print(f"  |  {'Timestamp':<12}|  {'Diagrama':<{larg-16}}|")
        print(f"  +{'-'*12}+{'-'*(larg-13)}+")

        for ts, linha in linhas:
            print(f"  |  {ts:<12}|  {linha:<{larg-16}}|")

        print(f"  +{'-'*12}+{'-'*(larg-13)}+")

    def _track_data(self, from_client: bool, seq: Optional[int], ack: Optional[int], payload_len: int):

        if seq is None or ack is None:
            return

        if from_client:
            if self._last_client_ack is not None and ack > self._last_client_ack:
                delta = ack - self._last_client_ack
                if delta < 1_073_741_824:
                    self.bytes_server_to_client += delta
            if self._last_client_ack is None or ack > self._last_client_ack:
                self._last_client_ack = ack
        else:
            if self._last_server_ack is not None and ack > self._last_server_ack:
                delta = ack - self._last_server_ack
                if delta < 1_073_741_824:
                    self.bytes_client_to_server += delta
            if self._last_server_ack is None or ack > self._last_server_ack:
                self._last_server_ack = ack


class FragmentTracker:
    """
    Groups IP fragments by Identification field.
    Detects completed datagrams and garbage-collects stale fragment sets.
    """

    def __init__(self, timeout_sec: float = 30.0):
        self.timeout_sec  = timeout_sec
        self._pending: dict = {}
        self.frag_completed: list = []   # datagramas completos para o diagrama

    def _gc(self):
        """Remove fragment sets that have exceeded the reassembly timeout."""
        now = time.monotonic()
        expired = [
            k for k, v in self._pending.items()
            if (now - v["wall"]) > self.timeout_sec
        ]
        for k in expired:
            src, dst, frag_id = k
            n = len(self._pending[k]["fragments"])
            print(
                f"  |_ [FRAG] GC: datagrama id={frag_id} {src}{dst} "
                f"descartado após {self.timeout_sec}s ({n} fragmentos recebidos, incompleto)"
            )
            del self._pending[k]

    def process(self, p: dict) -> Optional[str]:
        """
        Register a fragment and return a message if the datagram is
        complete or if this is the first/intermediate fragment.
        """
        self._gc()

        frag_id     = p.get("frag_id")
        frag_offset = p.get("frag_offset", 0)
        frag_mf     = p.get("frag_mf", False)
        frag_df     = p.get("frag_df", False)

        if not frag_mf and frag_offset == 0:
            return None

        src = p.get("src_ip", "?")
        dst = p.get("dst_ip", "?")
        key = (src, dst, frag_id)

        if key not in self._pending:
            self._pending[key] = {
                "fragments": [],
                "src": src,
                "dst": dst,
                "ts":   p["timestamp"],
                "wall": time.monotonic(),
            }

        self._pending[key]["fragments"].append((frag_offset, p.get("size", 0), frag_mf))

        evento = (
            f"  |_ [FRAG] {src}->{dst} id={frag_id} offset={frag_offset}B "
            f"{'(mais fragmentos)' if frag_mf else '(ultimo fragmento)'}"
        )

        if not frag_mf:
            total = sum(s for _, s, _ in self._pending[key]["fragments"])
            n     = len(self._pending[key]["fragments"])
            # Guardar para diagrama final antes de apagar
            self.frag_completed.append({
                "frag_id":   frag_id,
                "src":       src,
                "dst":       dst,
                "n":         n,
                "total":     total,
                "fragments": list(self._pending[key]["fragments"]),
            })
            del self._pending[key]
            evento += f"\n  |_ [FRAG] Datagrama id={frag_id} COMPLETO ({n} fragmentos, ~{total}B)"

        return evento

    def pending_count(self) -> int:
        return len(self._pending)


class HTTPTracker:
    """
    Pair HTTP Requests with their Responses.

    A request is keyed by (client_ip, server_ip, client_port) - this
    uniquely identifies a single HTTP request on a connection without
    needing to inspect the Host header.
    """

    def __init__(self):
        self._pending: dict = {}
        self.paired: int = 0

    def process(self, p: dict) -> Optional[str]:
        proto   = p.get("proto")
        summary = p.get("summary", "")

        if proto != "HTTP":
            return None

        src_ip   = p.get("src_ip", "?")
        dst_ip   = p.get("dst_ip", "?")
        src_port = p.get("src_port", 0)
        dst_port = p.get("dst_port", 0)

        if dst_port == 80 and any(m in summary for m in
                ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH")):
            key = (src_ip, dst_ip, src_port)
            self._pending[key] = {
                "summary": summary,
                "ts": p["timestamp"],
            }
            return f"[HTTP] REQUEST  {src_ip}:{src_port}  {dst_ip}:80  {summary}"

        if src_port == 80:
            key = (dst_ip, src_ip, dst_port)
            if key in self._pending:
                req = self._pending.pop(key)
                self.paired += 1
                return (
                    f"[HTTP] RESPONSE {src_ip}:80  {dst_ip}:{dst_port}  {summary}  "
                    f"(par do request: {req['summary']})"
                )
            return f"[HTTP] RESPONSE {src_ip}:80  {dst_ip}:{dst_port}  {summary}"

        return None


class DNSTracker:
    """
    Pair DNS Queries with their Responses via dns_id (Transaction ID).
    """

    def __init__(self):
        self._pending: dict = {}
        self.paired: int = 0

    def process(self, p: dict) -> Optional[str]:
        if p.get("proto") != "DNS":
            return None

        dns_id  = p.get("dns_id")
        dns_qr  = p.get("dns_qr")
        name    = p.get("dns_name", "?")
        qtype   = p.get("dns_qtype", "?")
        rcode   = p.get("dns_rcode", 0)
        src_ip  = p.get("src_ip", "?")
        dst_ip  = p.get("dst_ip", "?")

        rcode_str = {0: "NOERROR", 2: "SERVFAIL", 3: "NXDOMAIN"}.get(rcode, f"rcode={rcode}")

        if dns_qr == 0:
            self._pending[dns_id] = {
                "name": name, "qtype": qtype,
                "src": src_ip, "ts": p["timestamp"],
            }
            return f"[DNS] Query   id={dns_id} {src_ip}  {dst_ip}  {qtype} {name}"

        elif dns_qr == 1:
            if dns_id in self._pending:
                req = self._pending.pop(dns_id)
                self.paired += 1
                return (
                    f"[DNS] Response id={dns_id} {src_ip}  {dst_ip}  "
                    f"{rcode_str}  (query: {req['qtype']} {req['name']})"
                )
            return f"[DNS] Response id={dns_id} {src_ip}  {dst_ip}  {rcode_str}  {name}"

        return None


class DHCPTracker:
    """
    Track DHCP DORA (Discover  Offer  Request  ACK) phases via dhcp_xid.
    """

    _DORA_ORDER = ["Discover", "Offer", "Request", "ACK"]
    _DORA_SET   = set(_DORA_ORDER)

    def __init__(self):
        self._sessions: dict = {}
        self.completed: int = 0

    def process(self, p: dict) -> Optional[str]:
        if p.get("proto") != "DHCP":
            return None

        xid      = p.get("dhcp_xid")
        msg_type = p.get("dhcp_msg_type", "")
        client   = p.get("dhcp_chaddr", "?")
        offered  = p.get("dhcp_yiaddr", "0.0.0.0")
        src_ip   = p.get("src_ip", "?")

        if xid is None:
            return None

        if xid not in self._sessions:
            self._sessions[xid] = {
                "phase": None, "client_mac": client,
                "offered_ip": "0.0.0.0", "ts": p["timestamp"],
                "history": [],
            }

        sess = self._sessions[xid]
        sess["history"].append(msg_type)
        if offered and offered != "0.0.0.0":
            sess["offered_ip"] = offered

        phase_label = f"xid={xid:#010x} client={client}"

        if msg_type == "Discover":
            sess["phase"] = "Discover"
            return f"[DHCP] DORA step 1/4 Discover  {phase_label}"

        elif msg_type == "Offer":
            sess["phase"] = "Offer"
            return f"[DHCP] DORA step 2/4 Offer     {phase_label} offered={offered}"

        elif msg_type == "Request":
            sess["phase"] = "Request"
            return f"[DHCP] DORA step 3/4 Request   {phase_label}"

        elif msg_type == "ACK":
            sess["phase"] = "ACK"
            ip = sess["offered_ip"]
            del self._sessions[xid]
            self.completed += 1
            return (
                f"[DHCP] DORA COMPLETO   {phase_label} "
                f"IP atribuído={ip}  (4 fases concluídas)"
            )

        elif msg_type == "NAK":
            self._sessions.pop(xid, None)
            return f"[DHCP] DORA NAK  {phase_label}  (servidor recusou)"

        else:
            return f"[DHCP] {msg_type}  {phase_label}"


class ProtocolAnalyzer:
    def __init__(self):
        self.tcp_flows     : dict = {}
        self.arp_table     : dict = {}
        self.arp_pending   : dict = {}
        self.arp_completed : list = []   # [(src_ip, src_mac, dst_ip, ts)]
        self.icmp_sessions : dict = {}
        self.icmp_completed: list = []   # [(src, dst, icmp_id, seq, ts)]
        self.frag_tracker   = FragmentTracker(timeout_sec=30.0)
        self.http_tracker   = HTTPTracker()
        self.dns_tracker    = DNSTracker()
        self.dhcp_tracker   = DHCPTracker()
        self.summary_data   = {
            "tcp_connections": 0,
            "arp_exchanges":   0,
            "icmp_exchanges":  0,
        }

        # -- Acumuladores para o resumo geral --
        self._proto_stats  : dict    = defaultdict(lambda: {"pkts": 0, "bytes": 0})
        self._flow_stats   : dict    = defaultdict(lambda: {"pkts": 0, "bytes": 0})
        self._port_counter : Counter = Counter()   # portas TCP destino
        self._timeline     : list    = []          # timestamps inteiros (segundos)
        self._capture_start: float   = time.monotonic()
        self._seen_ips     : set     = set()
        self._rst_count    : int     = 0
        self._retx_count   : int     = 0
        self._win_samples  : list    = []          # janelas efectivas observadas

    def process(self, parsed: dict, raw_pkt):
        proto = parsed.get("proto", "UNKNOWN")
        size  = parsed.get("size", 0)

        # -- Contadores universais (todos os pacotes) --
        self._proto_stats[proto]["pkts"]  += 1
        self._proto_stats[proto]["bytes"] += size
        self._timeline.append(int(time.monotonic() - self._capture_start))
        if parsed.get("src_ip"): self._seen_ips.add(parsed["src_ip"])
        if parsed.get("dst_ip"): self._seen_ips.add(parsed["dst_ip"])

        # Flow stats: chave (src_ip, dst_ip, proto)
        fk = (parsed.get("src_ip","?"), parsed.get("dst_ip","?"), proto)
        self._flow_stats[fk]["pkts"]  += 1
        self._flow_stats[fk]["bytes"] += size

        # Portas TCP destino
        if proto in ("TCP", "HTTP") and parsed.get("dst_port"):
            self._port_counter[parsed["dst_port"]] += 1

        # -- Fragmentacao --
        if parsed.get("frag_id") is not None:
            evento = self.frag_tracker.process(parsed)
            if evento:
                print(evento)

        if proto in ("TCP", "HTTP"):
            self._analyze_tcp(parsed, raw_pkt)
        elif proto == "ARP":
            self._analyze_arp(parsed)
        elif proto == "ICMP":
            self._analyze_icmp(parsed)
        elif proto == "ICMPv6":
            self._analyze_icmpv6(parsed)

        if proto == "HTTP":
            evt = self.http_tracker.process(parsed)
            if evt:
                print(f"  * {evt}")

        elif proto == "DNS":
            evt = self.dns_tracker.process(parsed)
            if evt:
                print(f"  * {evt}")

        elif proto == "DHCP":
            evt = self.dhcp_tracker.process(parsed)
            if evt:
                print(f"  * {evt}")


    def _analyze_tcp(self, p: dict, raw_pkt):
        flags = p.get("flags", "")
        if not flags:
            return

        src = f"{p.get('src_ip','?')}:{p.get('src_port','?')}"
        dst = f"{p.get('dst_ip','?')}:{p.get('dst_port','?')}"

        key_fwd = f"{src} <-> {dst}"
        key_rev = f"{dst} <-> {src}"

        if key_fwd in self.tcp_flows:
            key    = key_fwd
            client = self.tcp_flows[key].client
            server = self.tcp_flows[key].server
        elif key_rev in self.tcp_flows:
            key    = key_rev
            client = self.tcp_flows[key].client
            server = self.tcp_flows[key].server
        else:

            if "SYN" not in flags or "ACK" in flags:
                return
            key    = key_fwd
            client = src
            server = dst
            self.tcp_flows[key] = TCPState(key, client=client, server=server)

        payload_len = 0
        try:
            from scapy.all import TCP as ScapyTCP, Raw
            if raw_pkt.haslayer(ScapyTCP):
                tcp_layer = raw_pkt[ScapyTCP]
                if raw_pkt.haslayer(Raw):
                    payload_len = len(raw_pkt[Raw].load)
        except Exception:
            pass

        flow  = self.tcp_flows[key]
        event = flow.transition(
            flags        = flags,
            src_endpoint = src,
            timestamp    = p["timestamp"],
            tcp_seq      = p.get("tcp_seq"),
            tcp_ack      = p.get("tcp_ack"),
            payload_len  = payload_len,
        )

        if event:
            print(f"  * {event}")
            if flow.state == TCPState.ESTABLISHED:
                self.summary_data["tcp_connections"] += 1
            if flow.state == TCPState.CLOSED and "RST" in flags:
                self._rst_count += 1

        # Window sample
        win = p.get("tcp_window")
        if win is not None:
            self._win_samples.append(win)


    def _analyze_arp(self, p: dict):
        summary = p.get("summary", "")
        src_ip  = p.get("src_ip")
        src_mac = p.get("src_mac")

        if "Request" in summary:
            self.arp_pending[p["dst_ip"]] = p["timestamp"]
            print(f"  * [ARP] Request: quem tem {p['dst_ip']}? (de {src_ip})")

        elif "Reply" in summary:
            if src_ip and src_mac:
                self.arp_table[src_ip] = src_mac
            if src_ip in self.arp_pending:
                print(f"  * [ARP] Reply: {src_ip} está em {src_mac} (troca completa)")
                self.arp_completed.append((src_ip, src_mac, p.get("dst_ip"), p["timestamp"]))
                del self.arp_pending[src_ip]
                self.summary_data["arp_exchanges"] += 1


    def _analyze_icmp(self, p: dict):
        icmp_type = p.get("icmp_type")
        icmp_id   = p.get("icmp_id")
        icmp_seq  = p.get("icmp_seq")

        if icmp_type == 8:
            key = (p.get("src_ip"), p.get("dst_ip"), icmp_id)
            self.icmp_sessions[key] = p["timestamp"]
            print(f"  * [ICMP] Echo Request {p.get('src_ip')} -> {p.get('dst_ip')} id={icmp_id} seq={icmp_seq}")

        elif icmp_type == 0:
            key = (p.get("dst_ip"), p.get("src_ip"), icmp_id)
            if key in self.icmp_sessions:
                print(f"  * [ICMP] Echo Reply {p.get('src_ip')} -> {p.get('dst_ip')} id={icmp_id} seq={icmp_seq} (par completo)")
                self.icmp_completed.append((p.get("dst_ip"), p.get("src_ip"), icmp_id, icmp_seq, p["timestamp"]))
                del self.icmp_sessions[key]
                self.summary_data["icmp_exchanges"] += 1

        elif icmp_type == 11:
            print(f"  * [ICMP] Time Exceeded de {p.get('src_ip')} (possível traceroute)")

        elif icmp_type == 3:
            print(f"  * [ICMP] {p.get('summary', 'Dest Unreachable')}")


    def _analyze_icmpv6(self, p: dict):
        """
        ICMPv6 Echo Request (type=128) / Reply (type=129) pairing.
        Uses the same icmp_sessions dict as ICMPv4, keyed by
        (src_ip, dst_ip, icmp_id).  IPv6 addresses are distinct from
        IPv4 so there is no collision risk.
        """
        icmp_type = p.get("icmp_type")
        icmp_id   = p.get("icmp_id")
        icmp_seq  = p.get("icmp_seq")

        if icmp_type == 128:
            key = (p.get("src_ip"), p.get("dst_ip"), icmp_id)
            self.icmp_sessions[key] = p["timestamp"]
            print(f"  * [ICMPv6] Echo Request {p.get('src_ip')} -> {p.get('dst_ip')} id={icmp_id} seq={icmp_seq}")

        elif icmp_type == 129:
            key = (p.get("dst_ip"), p.get("src_ip"), icmp_id)
            if key in self.icmp_sessions:
                print(f"  * [ICMPv6] Echo Reply {p.get('src_ip')} -> {p.get('dst_ip')} id={icmp_id} seq={icmp_seq} (par completo)")
                self.icmp_completed.append((p.get("dst_ip"), p.get("src_ip"), icmp_id, icmp_seq, p["timestamp"]))
                del self.icmp_sessions[key]
                self.summary_data["icmp_exchanges"] += 1


    def print_summary(self):
        self._print_diagrams()
        self._print_resumo_geral()

    # ====================================================================
    # DIAGRAMAS POR PROTOCOLO
    # ====================================================================

    def _print_diagrams(self):
        L = 70
        cor_header = _cor("ciano")
        reset = _COR["reset"]
        print(f"\n\n{cor_header}" + "=" * L + f"{reset}")
        print(f"{cor_header}  DIAGRAMAS DE PROTOCOLO -- reconstruidos da captura{reset}")
        print(f"{cor_header}" + "=" * L + f"{reset}")

        self._diag_tcp()
        self._diag_udp()
        self._diag_arp()
        self._diag_icmp()
        self._diag_frag()
        self._diag_http()
        self._diag_dns()
        self._diag_dhcp()

    # -- TCP --

    def _diag_tcp(self):
        cor = _cor(_COR_PROTO.get("TCP", "reset"))
        
        # Se há fluxos TCP rastreados
        if self.tcp_flows:
            grupos = defaultdict(list)
            for flow in self.tcp_flows.values():
                grupos[flow.group_key()].append(flow)

            print(f"\n┌──────────────────────────────────────────────────────────┐")
            print(f"│  {cor}TCP{_COR['reset']} - Fluxos de Conexão                              │")
            print(f"├──────────────────────────┬──────────┬────────┬────────┤")
            print(f"│  Fluxo                   │  Estado  │  Tempo │ Dados  │")
            print(f"├──────────────────────────┼──────────┼────────┼────────┤")
            
            for (client_ip, server_ip, server_port), flows in sorted(grupos.items()):
                for flow in sorted(flows, key=lambda f: f.start_time):
                    card = flow.summary_card(1)
                    estado = card['state'][:8].ljust(8)
                    tempo = card['duration'][:6].ljust(6)
                    dados = card['data'][:6].ljust(6)
                    fluxo_str = f"{client_ip}→{server_ip}:{server_port}"[:24].ljust(24)
                    print(f"│ {fluxo_str} │ {estado} │ {tempo} │ {dados} │")
            
            print(f"└──────────────────────────┴──────────┴────────┴────────┘")
        else:
            # Fallback: mostrar fluxos TCP de _flow_stats
            tcp_flows = [(k, v) for k, v in self._flow_stats.items() if k[2] == "TCP"]
            if tcp_flows:
                print(f"\n┌──────────────────────────────────────────────────────────┐")
                print(f"│  {cor}TCP{_COR['reset']} - Fluxos Observados                           │")
                print(f"├────────────────────────────────────┬───────┬──────────┤")
                print(f"│  Fluxo                             │ Pkts  │  Bytes   │")
                print(f"├────────────────────────────────────┼───────┼──────────┤")
                
                for (src, dst, proto), stats in sorted(tcp_flows, key=lambda x: -x[1]["pkts"]):
                    fluxo_str = f"{src}→{dst}"[:34].ljust(34)
                    print(f"│ {fluxo_str} │ {stats['pkts']:>5} │ {_fmt_bytes(stats['bytes']):>8} │")
                
                print(f"└────────────────────────────────────┴───────┴──────────┘")

    # -- UDP --

    def _diag_udp(self):
        # Filtrar fluxos UDP do _flow_stats
        udp_flows = [(k, v) for k, v in self._flow_stats.items() if k[2] == "UDP"]
        if not udp_flows:
            return
        
        cor = _cor(_COR_PROTO.get("UDP", "reset"))
        
        print(f"\n┌──────────────────────────────────────────────────────────┐")
        print(f"│  {cor}UDP{_COR['reset']} - Fluxos de Datagramas                            │")
        print(f"├────────────────────────────────────┬───────┬──────────┤")
        print(f"│  Fluxo                             │ Pkts  │  Bytes   │")
        print(f"├────────────────────────────────────┼───────┼──────────┤")
        
        for (src, dst, proto), stats in sorted(udp_flows, key=lambda x: -x[1]["pkts"]):
            fluxo_str = f"{src}→{dst}"[:34].ljust(34)
            print(f"│ {fluxo_str} │ {stats['pkts']:>5} │ {_fmt_bytes(stats['bytes']):>8} │")
        
        print(f"└────────────────────────────────────┴───────┴──────────┘")

    # -- ARP --

    def _diag_arp(self):
        if not self.arp_completed and not self.arp_table:
            return
        
        cor = _cor(_COR_PROTO.get("ARP", "reset"))
        print(f"\n┌──────────────────────────────────────────────────────────┐")
        print(f"│  {cor}ARP{_COR['reset']} - Resolução de Endereços                         │")
        print(f"├────────────────────────────────┬────────────────────────┤")
        print(f"│  Endereço IP                   │  Endereço MAC          │")
        print(f"├────────────────────────────────┼────────────────────────┤")
        
        for src_ip, src_mac, dst_ip, ts in self.arp_completed:
            print(f"│ {src_ip:<30} │ {src_mac:<22} │")
        
        if self.arp_table:
            for ip, mac in sorted(self.arp_table.items()):
                print(f"│ {ip:<30} │ {mac:<22} │")
        
        print(f"└────────────────────────────────┴────────────────────────┘")

    # -- ICMP --

    def _diag_icmp(self):
        if not self.icmp_completed and not self.icmp_sessions:
            return
        
        cor = _cor(_COR_PROTO.get("ICMP", "reset"))
        
        # Agrupar por (src, dst, icmp_id)
        grupos = {}
        for src, dst, icmp_id, seq, ts in self.icmp_completed:
            k = (src, dst, icmp_id)
            grupos.setdefault(k, []).append(seq)

        print(f"\n┌──────────────────────────────────────────────────────────┐")
        print(f"│  {cor}ICMP{_COR['reset']} Echo - Request/Reply                           │")
        print(f"├────────────────────────────────┬─────────┬────────────┤")
        print(f"│  Fluxo                         │ Seqs    │ Respostas  │")
        print(f"├────────────────────────────────┼─────────┼────────────┤")

        for (src, dst, icmp_id), seqs in sorted(grupos.items()):
            total = len(seqs)
            perdas = len([k for k in self.icmp_sessions if k[0]==src and k[2]==icmp_id])
            fluxo_str = f"{src}→{dst} id={icmp_id}"[:30].ljust(30)
            seq_str = f"{len(set(seqs))}"[:7].ljust(7)
            resp_str = f"{total}/{total+perdas}"[:10].ljust(10)
            print(f"│ {fluxo_str} │ {seq_str} │ {resp_str} │")
        
        print(f"└────────────────────────────────┴─────────┴────────────┘")

    # -- Fragmentacao IP --

    def _diag_frag(self):
        completed = self.frag_tracker.frag_completed
        pending   = self.frag_tracker.pending_count()
        if not completed and not pending:
            return
        
        cor = _cor(_COR_PROTO.get("IPv4", "reset"))
        print(f"\n┌──────────────────────────────────────────────────────────┐")
        print(f"│  {cor}IP{_COR['reset']} - Fragmentação de Datagramas                     │")
        print(f"├───────┬────────────────────────┬────────┬──────────────┤")
        print(f"│  ID   │  Fluxo                 │  Frags │  Total Bytes │")
        print(f"├───────┼────────────────────────┼────────┼──────────────┤")
        
        for d in sorted(completed, key=lambda x: x['frag_id']):
            fluxo_str = f"{d['src']}→{d['dst']}"[:22].ljust(22)
            print(f"│ {d['frag_id']:<5} │ {fluxo_str} │ {d['n']:>6} │ {_fmt_bytes(d['total']):>12} │")
        
        print(f"└───────┴────────────────────────┴────────┴──────────────┘")
        
        if pending:
            print(f"  ⚠  {pending} datagrama(s) incompleto(s) no fim da captura")

    # -- HTTP --

    def _diag_http(self):
        if self.http_tracker.paired == 0:
            return
        cor = _cor(_COR_PROTO.get("HTTP", "reset"))
        print(f"\n┌──────────────────────────────────────────────────────────┐")
        print(f"│  {cor}HTTP{_COR['reset']} - Pares Request/Response                       │")
        print(f"├──────────────────────────────────────────────────────────┤")
        print(f"│  Pares completos: {self.http_tracker.paired:<44}│")
        print(f"├──────────────────────────────────────────────────────────┤")
        print(f"│  Cliente ---- GET/POST /path HTTP/1.x ----→ Servidor     │")
        print(f"│  Cliente ←---- HTTP/1.x 200 OK ---------- Servidor       │")
        print(f"└──────────────────────────────────────────────────────────┘")

    # -- DNS --

    def _diag_dns(self):
        if self.dns_tracker.paired == 0:
            return
        cor = _cor(_COR_PROTO.get("DNS", "reset"))
        print(f"\n┌──────────────────────────────────────────────────────────┐")
        print(f"│  {cor}DNS{_COR['reset']} - Ciclo Query/Response                          │")
        print(f"├──────────────────────────────────────────────────────────┤")
        print(f"│  Pares completos: {self.dns_tracker.paired:<44}│")
        print(f"├──────────────────────────────────────────────────────────┤")
        print(f"│  Cliente ---- Query (tipo A/AAAA/...) ----→ Resolver     │")
        print(f"│  Cliente ←---- Response (NOERROR/NXDOMAIN) - Resolver    │")
        print(f"└──────────────────────────────────────────────────────────┘")

    # -- DHCP --

    def _diag_dhcp(self):
        if self.dhcp_tracker.completed == 0:
            return
        cor = _cor(_COR_PROTO.get("DHCP", "reset"))
        print(f"\n┌──────────────────────────────────────────────────────────┐")
        print(f"│  {cor}DHCP{_COR['reset']} - Sequência DORA                                 │")
        print(f"├──────────────────────────────────────────────────────────┤")
        print(f"│  Sequências DORA completas: {self.dhcp_tracker.completed:<38}│")
        print(f"├──────────────────────────────────────────────────────────┤")
        print(f"│  1. Cliente ---- Discover (broadcast) -------→ Servidor  │")
        print(f"│  2. Cliente ←---- Offer (IP oferecido) ------ Servidor   │")
        print(f"│  3. Cliente ---- Request (aceita oferta) ---→ Servidor   │")
        print(f"│  4. Cliente ←---- ACK (IP atribuído) ------- Servidor    │")
        print(f"└──────────────────────────────────────────────────────────┘")

    # ====================================================================
    # RESUMO GERAL
    # ====================================================================

    def _print_resumo_geral(self):
        L = 70
        print("\n" + "=" * L)
        print("  RESUMO GERAL DA CAPTURA")
        print("=" * L)

        self._resumo_distribuicao()
        self._resumo_top_flows()
        self._resumo_timeline()
        self._resumo_tcp_metricas()
        self._resumo_hosts()
        self._resumo_diagnostico()

        print("=" * L + "\n")

    # -- Distribuicao de trafego --

    def _resumo_distribuicao(self):
        if not self._proto_stats:
            return

        total_pkts  = sum(v["pkts"]  for v in self._proto_stats.values())
        total_bytes = sum(v["bytes"] for v in self._proto_stats.values())
        duracao     = time.monotonic() - self._capture_start

        print("\n┌──────────────────────────────────────────────────────────┐")
        print("│  DISTRIBUIÇÃO DE TRÁFEGO                                  │")
        print("├─────────────┬────────┬──────────┬────────────────────────┤")
        print("│  Protocolo  │  Pkts  │  Bytes   │  Distribuição          │")
        print("├─────────────┼────────┼──────────┼────────────────────────┤")
        
        for proto, v in sorted(self._proto_stats.items(), key=lambda x: -x[1]["pkts"]):
            pct = v["pkts"] / total_pkts * 100 if total_pkts else 0
            cor = _cor(_COR_PROTO.get(proto, "reset"))
            barra = _barra(pct, 14)
            proto_display = f"{cor}{proto:<11}{_COR['reset']}"
            print(f"│ {proto_display} │ {v['pkts']:>6} │ {_fmt_bytes(v['bytes']):>8} │ {barra}  {pct:>5.1f}%   │")
        
        print("├─────────────┴────────┴──────────┴────────────────────────┤")
        print(f"│  Total: {total_pkts} pacotes  │  {_fmt_bytes(total_bytes):>8}  │  Duração: {duracao:.1f}s        │")
        dominante = max(self._proto_stats, key=lambda k: self._proto_stats[k]["pkts"])
        pct_dom = self._proto_stats[dominante]["pkts"] / total_pkts * 100
        cor_dom = _cor(_COR_PROTO.get(dominante, "reset"))
        print(f"│  Protocolo dominante: {cor_dom}{dominante}{_COR['reset']} ({pct_dom:.1f}%){'':43}│")
        print("└──────────────────────────────────────────────────────────┘")

    # -- Top flows --

    def _resumo_top_flows(self):
        if not self._flow_stats:
            return
        top5 = sorted(self._flow_stats.items(), key=lambda x: -x[1]["pkts"])[:5]
        
        print("\n┌──────────────────────────────────────────────────────────┐")
        print("│  TOP 5 FLOWS (por volume de pacotes)                      │")
        print("├────┬──────────────────────────────┬───────┬──────────────┤")
        print("│ #  │  Flow                        │ Pkts  │  Bytes       │")
        print("├────┼──────────────────────────────┼───────┼──────────────┤")
        
        for i, ((src, dst, proto), v) in enumerate(top5, 1):
            cor = _cor(_COR_PROTO.get(proto, "reset"))
            flow_display = f"{src} → {dst}"[:28].ljust(28)
            print(f"│ {i:>2} │ {flow_display} │ {v['pkts']:>5} │ {_fmt_bytes(v['bytes']):>12} │")
        
        print("└────┴──────────────────────────────┴───────┴──────────────┘")

    # -- Timeline --

    def _resumo_timeline(self):
        if len(self._timeline) < 2:
            return
        max_t  = max(self._timeline)
        counts = [0] * (max_t + 1)
        for t in self._timeline:
            counts[t] += 1
        pico   = max(counts)
        pico_t = counts.index(pico)
        media  = sum(counts) / len(counts) if counts else 0

        print("\n┌──────────────────────────────────────────────────────────┐")
        print("│  TIMELINE DE ACTIVIDADE  (pacotes por segundo)            │")
        print("├──────────────────────────────────────────────────────────┤")
        
        spark = _sparkline(counts)
        print(f"│  {0:>2}s  {spark}  {max_t:<2}s     │")
        print(f"│       pico: {_cor('vermelho')}{pico} pkt/s{_COR['reset']} @ t={pico_t}s   média: {media:.1f} pkt/s{'':>11}│")
        print("└──────────────────────────────────────────────────────────┘")

    # -- Metricas TCP --

    def _resumo_tcp_metricas(self):
        if not self.tcp_flows:
            return

        abertas = sum(
            1 for f in self.tcp_flows.values()
            if f.state == TCPState.ESTABLISHED
        )

        cor_ok = _cor("verde")
        cor_warn = _cor("amarelo")
        reset = _COR["reset"]

        print("\n┌──────────────────────────────────────────────────────────┐")
        print("│  MÉTRICAS TCP                                             │")
        print("├──────────────────────────────────────────────────────────┤")
        
        conexoes = self.summary_data['tcp_connections']
        print(f"│  Ligações estabelecidas    :   {cor_ok}{conexoes}{reset:<34}│")
        if self._rst_count > 0:
            print(f"│  Ligações com RST          :   {cor_warn}{self._rst_count}{reset}  (encerramento abrupto){'':21}│")
        else:
            print(f"│  Ligações com RST          :   {cor_ok}0{reset}{'':48}│")
        if abertas > 0:
            print(f"│  Ligações ainda abertas    :   {cor_warn}{abertas}{reset}  (sem FIN/RST observado){'':18}│")
        else:
            print(f"│  Ligações ainda abertas    :   {cor_ok}0{reset}{'':48}│")
        
        if self._win_samples:
            min_w = _fmt_bytes(min(self._win_samples))
            max_w = _fmt_bytes(max(self._win_samples))
            med_w = _fmt_bytes(int(sum(self._win_samples)/len(self._win_samples)))
            print(f"│                                                          │")
            print(f"│  Janelas efectivas observadas:                           │")
            print(f"│    Mínima  :   {min_w:<44}│")
            print(f"│    Máxima  :   {max_w:<44}│")
            print(f"│    Média   :   {med_w:<44}│")
        
        if self._port_counter:
            _PORT_NAMES = {80:"HTTP", 443:"HTTPS", 22:"SSH", 21:"FTP",
                           25:"SMTP", 23:"Telnet", 53:"DNS", 8080:"HTTP-alt"}
            print(f"│                                                          │")
            print(f"│  Portas de destino mais usadas:                          │")
            for porta, n in self._port_counter.most_common(3):
                nome = _PORT_NAMES.get(porta, "")
                cor_porta = _cor(_COR_PROTO.get(nome.upper(), "reset")) if nome else ""
                desc = " (TLS — conteúdo opaco)" if porta == 443 else ""
                espacos = " " * (24 - len(desc) - len(str(n)))
                print(f"│    :{porta:<3}  {cor_porta}{nome:<6}{reset}  →  {n} ligações{desc}{espacos}│")
        
        print("└──────────────────────────────────────────────────────────┘")

    # -- Hosts observados --

    def _resumo_hosts(self):
        if not self._seen_ips:
            return
        
        print("\n┌──────────────────────────────────────────────────────────┐")
        print("│  HOSTS OBSERVADOS                                         │")
        print("├──────────────────────────────┬───────────────────────────┤")
        print("│  IP                          │  MAC (via ARP)             │")
        print("├──────────────────────────────┼───────────────────────────┤")
        
        for ip in sorted(self._seen_ips):
            mac = self.arp_table.get(ip, "—")
            print(f"│  {ip:<28} │  {mac:<23} │")
        
        print("└──────────────────────────────┴───────────────────────────┘")

    # -- Diagnostico --

    def _resumo_diagnostico(self):
        cor_ok = _cor("verde")
        cor_warn = _cor("amarelo")
        cor_info = _cor("ciano")
        reset = _COR["reset"]

        print("\n┌──────────────────────────────────────────────────────────┐")
        print("│  DIAGNÓSTICO DE REDE                                      │")
        print("├──────────────────────────────────────────────────────────┤")
        
        # ARP
        if not self.arp_pending:
            print(f"│  {cor_ok}[OK]{reset}   ARP cache estável — sem conflitos IP/MAC          │")
        else:
            print(f"│  {cor_warn}[WARN]{reset} ARP - {len(self.arp_pending)} request(s) sem reply{' ':37}│")

        # Fragmentação
        pendentes = self.frag_tracker.pending_count()
        completos = len(self.frag_tracker.frag_completed)
        if pendentes == 0 and completos > 0:
            print(f"│  {cor_ok}[OK]{reset}   Fragmentação IP — todos os datagramas completos   │")
        elif pendentes == 0:
            print(f"│  {cor_ok}[OK]{reset}   Fragmentação IP — sem fragmentos observados       │")
        else:
            print(f"│  {cor_warn}[WARN]{reset} Fragmentação IP — {pendentes} datagrama(s) incompletos{' ':25}│")

        # TCP RST
        if self._rst_count == 0:
            print(f"│  {cor_ok}[OK]{reset}   TCP — sem ligações terminadas por RST             │")
        else:
            print(f"│  {cor_warn}[WARN]{reset} {self._rst_count} ligação(ões) TCP encerrada(s) por RST{' ':30}│")

        # ICMP sem reply
        sem_reply = len(self.icmp_sessions)
        if sem_reply == 0:
            print(f"│  {cor_ok}[OK]{reset}   ICMP — todos os Echo Requests têm Reply           │")
        else:
            print(f"│  {cor_warn}[WARN]{reset} {sem_reply} ICMP Requests sem Reply correspondente{' ':26}│")

        # Ligações TCP abertas
        abertas = sum(1 for f in self.tcp_flows.values() if f.state == TCPState.ESTABLISHED)
        if abertas:
            print(f"│  {cor_info}[INFO]{reset} {abertas} ligação TCP ainda aberta no fim da captura{' ':24}│")

        # HTTPS
        if self._port_counter.get(443, 0) > 0:
            print(f"│  {cor_info}[INFO]{reset} Tráfego HTTPS presente — payloads cifrados        │")
        
        print("└──────────────────────────────────────────────────────────┘")