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

    def __init__(self, ip=None, src_ip=None, dst_ip=None, mac=None, proto=None, port=None,
                 exclude_ip=None, exclude_proto=None):
        # Backwards-compatible generic ip + optional specific src/dst
        self.ip           = ip.strip()           if ip           else None
        self.src_ip       = src_ip.strip()       if src_ip       else None
        self.dst_ip       = dst_ip.strip()       if dst_ip       else None
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        self.mac          = mac.strip().lower()  if mac          else None
        self.proto        = proto.strip().upper() if proto        else None
        self.port         = int(port)            if port         else None
        self.exclude_ip   = exclude_ip.strip()   if exclude_ip   else None
        # Parse exclude_proto as comma-separated list
        self.exclude_proto_list = [
            p.strip().upper() for p in exclude_proto.split(',') if p.strip()
        ] if exclude_proto else []
        # Keep single value for backwards compatibility in summary/logging
        self.exclude_proto = self.exclude_proto_list[0] if self.exclude_proto_list else None

        # Validate proto
        if self.proto and self.proto not in self.SUPPORTED_PROTOS:
            print(f"[!] Aviso: protocolo '{self.proto}' não reconhecido. "
                  f"Suportados: {', '.join(sorted(self.SUPPORTED_PROTOS))}")
        
        # Validate each exclude_proto
        for p in self.exclude_proto_list:
            if p not in self.SUPPORTED_PROTOS:
                print(f"[!] Aviso: protocolo '{p}' não reconhecido. "
                      f"Suportados: {', '.join(sorted(self.SUPPORTED_PROTOS))}")

        if self.proto and self.exclude_proto_list:
            for excl_p in self.exclude_proto_list:
                grp = self._PROTO_GROUP.get(excl_p, {excl_p})
                if self.proto in grp:
                    print(f"[!] Aviso: --proto {self.proto} e --exclude-proto "
                        f"{excl_p} sao contraditorios - nenhum pacote passara.")


    def is_active(self) -> bool:
        return any([self.ip, self.src_ip, self.dst_ip, self.mac, self.proto,
                    self.port, self.exclude_ip, self.exclude_proto])

    def summary(self) -> str:
        parts = []
        if self.ip:            parts.append(f"IP={self.ip}")
        if self.src_ip:        parts.append(f"SRC_IP={self.src_ip}")
        if self.dst_ip:        parts.append(f"DST_IP={self.dst_ip}")
        if self.mac:           parts.append(f"MAC={self.mac}")
        if self.proto:         parts.append(f"PROTO={self.proto}")
        if self.port:          parts.append(f"PORT={self.port}")
        if self.exclude_ip:    parts.append(f"EXCLUIR_IP={self.exclude_ip}")
        if self.exclude_proto: parts.append(f"EXCLUIR_PROTO={self.exclude_proto}")
        return ", ".join(parts)


    def match(self, parsed: dict) -> bool:
        """
        Retorna True se o pacote deve ser ACEITE, False se deve ser DROPPED.

        Anti-leakage garantido:
          - Exclusão de TCP descarta HTTP (TCP no porto 80).
          - Exclusão de UDP descarta DNS e DHCP.
          - Inclusão de TCP NÃO aceita UDP/DNS mesmo que porto coincida.
        """
        pkt_proto = (parsed.get("proto", "") or "").strip().upper()
        src_ip    = parsed.get("src_ip")
        dst_ip    = parsed.get("dst_ip")
        src_port  = parsed.get("src_port")
        dst_port  = parsed.get("dst_port")

        if self.exclude_ip:
            if src_ip == self.exclude_ip or dst_ip == self.exclude_ip:
                return False

        if self.exclude_proto_list:
            for excl_p in self.exclude_proto_list:
                excluir_grupo = self._PROTO_GROUP.get(excl_p, {excl_p})
                if pkt_proto in excluir_grupo:
                    return False

        # Specific source/destination IP filters
        if self.src_ip:
            if src_ip != self.src_ip:
                return False
        if self.dst_ip:
            if dst_ip != self.dst_ip:
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

        if self.exclude_proto_list:
            bpf_parts = []
            for excl_p in self.exclude_proto_list:
                if excl_p in self._BPF_MAP:
                    bpf_parts.append(f"({self._BPF_MAP[excl_p]})")
            if bpf_parts:
                bpf_excl = " or ".join(bpf_parts)
                exclude_parts.append(f"not ({bpf_excl})")
        if self.exclude_ip:
            exclude_parts.append(f"not host {self.exclude_ip}")

        all_parts = include_parts + exclude_parts
        return " and ".join(all_parts) if all_parts else None
