class FilterManager:
    """
    Filtro passivo puro: só lê, nunca injeta nem altera pacotes.

    Hierarquia de decisão (short-circuit):
      1. Exclusões   False imediato se qualquer exclusão corresponder
      2. Inclusões   False se nenhuma inclusão corresponder
      3. Default     True (aceitar)
    """

    SUPPORTED_PROTOS = {
        "ARP", "ICMP", "ICMPV6", "TCP", "UDP",
        "IPv4", "IPv6", "HTTP", "DNS", "DHCP",
    }

    _PROTO_GROUP = {
        "TCP": {"TCP", "HTTP"},
        "UDP": {"UDP", "DNS", "DHCP"},
    }

    _BPF_MAP = {
        "ARP":   "arp",
        "ICMP":  "icmp",
        "ICMPV6":"icmp6",
        "TCP":   "tcp",
        "UDP":   "udp",
        "IPv4":  "ip",
        "IPv6":  "ip6",
        "HTTP":  "tcp port 80",
        "DNS":   "udp port 53",
        "DHCP":  "udp port 67 or udp port 68",
    }

    def __init__(self, ip=None, mac=None, proto=None, port=None,
                 exclude_ip=None, exclude_proto=None):
        self.ip           = ip.strip()           if ip           else None
        self.mac          = mac.strip().lower()  if mac          else None
        self.proto        = proto.strip().upper() if proto        else None
        self.port         = int(port)            if port         else None
        self.exclude_ip   = exclude_ip.strip()   if exclude_ip   else None
        self.exclude_proto= exclude_proto.strip().upper() if exclude_proto else None

        for p in (self.proto, self.exclude_proto):
            if p and p not in self.SUPPORTED_PROTOS:
                print(f"[!] Aviso: protocolo '{p}' não reconhecido. "
                      f"Suportados: {', '.join(sorted(self.SUPPORTED_PROTOS))}")

        if self.proto and self.exclude_proto:
            grp = self._PROTO_GROUP.get(self.exclude_proto, {self.exclude_proto})
            if self.proto in grp:
                    print(f"[!] Aviso: --proto {self.proto} e --exclude-proto "
                        f"{self.exclude_proto} sao contraditorios - nenhum pacote passara.")


    def is_active(self) -> bool:
        return any([self.ip, self.mac, self.proto,
                    self.port, self.exclude_ip, self.exclude_proto])

    def summary(self) -> str:
        parts = []
        if self.ip:            parts.append(f"IP={self.ip}")
        if self.mac:           parts.append(f"MAC={self.mac}")
        if self.proto:         parts.append(f"PROTO={self.proto}")
        if self.port:          parts.append(f"PORT={self.port}")
        if self.exclude_ip:    parts.append(f"EXCLUIR_IP={self.exclude_ip}")
        if self.exclude_proto: parts.append(f"EXCLUIR_PROTO={self.exclude_proto}")
        return ", ".join(parts)


    def match(self, parsed: dict) -> bool:
        """
        Retorna True se o pacote deve ser ACEITE, False se deve ser DROPADO.

        Anti-leakage garantido:
          - Exclusão de TCP descarta HTTP (TCP no porto 80).
          - Exclusão de UDP descarta DNS e DHCP.
          - Inclusão de TCP NÃO aceita UDP/DNS mesmo que porto coincida.
        """
        pkt_proto = parsed.get("proto", "")
        src_ip    = parsed.get("src_ip")
        dst_ip    = parsed.get("dst_ip")
        src_port  = parsed.get("src_port")
        dst_port  = parsed.get("dst_port")

        if self.exclude_ip:
            if src_ip == self.exclude_ip or dst_ip == self.exclude_ip:
                return False

        if self.exclude_proto:
            excluir_grupo = self._PROTO_GROUP.get(
                self.exclude_proto, {self.exclude_proto}
            )
            if pkt_proto in excluir_grupo:
                return False

        if self.ip:
            if src_ip != self.ip and dst_ip != self.ip:
                return False

        if self.mac:
            src_mac = (parsed.get("src_mac") or "").lower()
            dst_mac = (parsed.get("dst_mac") or "").lower()
            if src_mac != self.mac and dst_mac != self.mac:
                return False

        if self.proto:
            incluir_grupo = self._PROTO_GROUP.get(self.proto, {self.proto})
            if pkt_proto not in incluir_grupo:
                return False

        if self.port:
            if src_port != self.port and dst_port != self.port:
                return False

        return True


    def to_bpf(self) -> str:
        """
        Gera string BPF válida para libpcap/scapy.

        Coerência com filtro Python:
          - Mesmo pacote que passa no BPF também passa no filtro Python.
          - Exclusões BPF espelham a expansão de grupos do filtro Python.

        Nota: BPF não suporta lógica de estado; apenas filtra por campos
        estáticos do cabeçalho (proto, IP, porto, MAC).
        """
        include_parts = []
        exclude_parts = []

        if self.proto and self.proto in self._BPF_MAP:
            include_parts.append(f"({self._BPF_MAP[self.proto]})")
        if self.ip:
            include_parts.append(f"host {self.ip}")
        if self.mac:
            include_parts.append(f"ether host {self.mac}")
        if self.port:
            include_parts.append(f"port {self.port}")

        if self.exclude_proto and self.exclude_proto in self._BPF_MAP:
            bpf_excl = self._BPF_MAP[self.exclude_proto]
            exclude_parts.append(f"not ({bpf_excl})")
        if self.exclude_ip:
            exclude_parts.append(f"not host {self.exclude_ip}")

        all_parts = include_parts + exclude_parts
        return " and ".join(all_parts) if all_parts else None
