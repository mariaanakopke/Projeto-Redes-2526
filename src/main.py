import argparse
import sys
from scapy.all import get_if_list, get_if_addr, get_if_hwaddr, conf

from capture import CaptureEngine
from filters import FilterManager
from logger import Logger
from analyzer import ProtocolAnalyzer


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
_HEADER_WIDTH = 115


def _fit(text: str, width: int) -> str:
    value = str(text)
    if len(value) <= width:
        return value
    if width <= 3:
        return value[:width]
    return value[: width - 3] + "..."


def parse_args():
    parser = argparse.ArgumentParser(
        description="Packet Sniffer - UMinho RC 2025/2026",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Exemplos:
  sudo python3 main.py -i eth0
  sudo python3 main.py -i eth0 --proto TCP --analyze
  sudo python3 main.py -i eth0 --ip 192.168.1.1 --log csv
  sudo python3 main.py -i eth0 --exclude-proto TCP
  sudo python3 main.py --pcap ficheiro.pcap --analyze
  sudo python3 main.py --list-ifaces
        """
    )

    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("-i", "--iface",     help="Interface de rede (ex: eth0, wlan0)")
    src.add_argument("--pcap",            help="Ficheiro .pcap para analise offline")
    src.add_argument("--list-ifaces",     action="store_true",
                     help="Listar interfaces disponiveis e sair")

    parser.add_argument("--ip",    help="Filtrar por IP (origem ou destino)")
    parser.add_argument("--mac",   help="Filtrar por MAC (origem ou destino)")
    parser.add_argument("--proto", help="Filtrar por protocolo: ARP, ICMP, TCP, UDP, IPv4, IPv6, HTTP, DNS, DHCP")
    parser.add_argument("--port",  type=int, help="Filtrar por porto (origem ou destino)")

    parser.add_argument("--exclude-ip",    help="Ignorar pacotes deste IP")
    parser.add_argument("--exclude-proto", help="Ignorar pacotes deste protocolo")

    parser.add_argument("-n", "--count", type=int, default=0,
                        help="Nr de pacotes a capturar (0 = infinito)")

    parser.add_argument("--log",    choices=["txt", "csv", "json"],
                        help="Formato de exportacao de logs")
    parser.add_argument("--output", default="captura",
                        help="Nome base do ficheiro de saida (sem extensao)")
    parser.add_argument("--analyze", action="store_true",
                        help="Activar analise de fases de protocolo")

    return parser.parse_args()


def listar_interfaces():
    interfaces = get_if_list()
    print(f"\n{'-'*65}")
    print(f"  Interfaces de rede disponiveis ({len(interfaces)} encontradas)")
    print(f"{'-'*65}")
    for nome in interfaces:
        try:    ip  = get_if_addr(nome)
        except: ip  = "N/D"
        try:    mac = get_if_hwaddr(nome)
        except: mac = "N/D"
        padrao = " <- (padrao)" if nome == conf.iface else ""
        print(f"  {nome:<15}  IP: {ip:<18}  MAC: {mac}{padrao}")
    print(f"{'-'*65}\n")


def validar_iface(iface: str):
    disponiveis = get_if_list()
    if iface not in disponiveis:
        print(f"\n[ERRO] Interface '{iface}' nao encontrada.")
        print(f"[*]   Interfaces disponiveis: {', '.join(disponiveis)}")
        print(f"[*]   Use --list-ifaces para ver detalhes (IP, MAC).")
        sys.exit(1)


def print_header():
    title = "Packet Capture"
    print(f"\n\033[96m{'=' * _HEADER_WIDTH}\033[0m")
    print(f"\033[1m\033[97m{title:^{_HEADER_WIDTH}}\033[0m")
    print(
        f"\033[1m"
        f"{'No.':<{_COL_NO}} "
        f"{'Time':<{_COL_TIME}} "
        f"{'Source':<{_COL_SRC}} "
        f"{'Destination':<{_COL_DST}} "
        f"{'Protocol':<{_COL_PROTO}} "
        f"{'TTL':<{_COL_TTL}} "
        f"{'Length':<{_COL_LEN}} "
        f"{'Id':<{_COL_FRAG}} "
        f"{'Off':<{_COL_OFF}} "
        f"{'F':<{_COL_FLAGS}} "
        f"Info\033[0m"
    )
    print(f"\033[90m{'-' * _HEADER_WIDTH}\033[0m")


def main():
    args = parse_args()

    if args.list_ifaces:
        listar_interfaces()
        sys.exit(0)

    if args.iface:
        validar_iface(args.iface)

    filters = FilterManager(
        ip=args.ip,
        mac=args.mac,
        proto=args.proto,
        port=args.port,
        exclude_ip=args.exclude_ip,
        exclude_proto=args.exclude_proto,
    )

    logger   = Logger(fmt=args.log, output_base=args.output) if args.log else None
    analyzer = ProtocolAnalyzer() if args.analyze else None

    engine = CaptureEngine(
        iface=args.iface,
        pcap_file=args.pcap,
        filters=filters,
        logger=logger,
        analyzer=analyzer,
        count=args.count,
    )

    origem = f"interface \033[1m{args.iface}\033[0m" if args.iface else f"ficheiro \033[1m{args.pcap}\033[0m"
    print(f"\n[*] A capturar em {origem}")
    if filters.is_active():
        print(f"[*] Filtros activos : {filters.summary()}")
    if logger:
        print(f"[*] Logging para    : {args.output}.{args.log}")
    if analyzer:
        print(f"[*] Analise activa  : TCP handshake, ARP, ICMP, fragmentacao IP")
    print("[*] Ctrl+C para parar\n")

    print_header()

    try:
        engine.start()
    except PermissionError:
        print("\n[ERRO] Permissoes insuficientes. Execute com: sudo python3 main.py ...")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n[*] Captura interrompida.")
    finally:
        if logger:
            logger.close()
        if analyzer:
            analyzer.print_summary()
        engine.print_stats()


if __name__ == "__main__":
    main()
