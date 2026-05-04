import csv
import json
import os
from datetime import datetime


_FIELDS_BASE = [
    "timestamp", "iface", "proto", "src_mac", "dst_mac",
    "src_ip", "dst_ip", "src_port", "dst_port",
    "ttl", "size", "payload_size", "flags", "summary",
]

_FIELDS_EXTRA = [
    "tcp_seq", "tcp_ack", "tcp_window",
    "frag_id", "frag_offset", "frag_mf", "frag_df",
    "icmp_type", "icmp_code", "icmp_id", "icmp_seq",
    "dns_id", "dns_qr", "dns_rcode", "dns_name", "dns_qtype",
    "dhcp_xid", "dhcp_msg_type", "dhcp_yiaddr", "dhcp_chaddr", "dhcp_siaddr",
]

FIELDS = _FIELDS_BASE + _FIELDS_EXTRA


class Logger:
    def __init__(self, fmt: str, output_base: str):
        self.fmt      = fmt
        ext           = "jsonl" if fmt == "json" else fmt
        self.filename = f"{output_base}.{ext}"
        self._fh         = None
        self._csv_writer = None
        self._setup()

    def _setup(self):
        self._fh = open(self.filename, "w", encoding="utf-8", newline="")

        if self.fmt == "csv":
            self._csv_writer = csv.DictWriter(
                self._fh, fieldnames=FIELDS, extrasaction="ignore"
            )
            self._csv_writer.writeheader()
            self._fh.flush()

        elif self.fmt == "txt":
            self._fh.write(f"# Packet Sniffer Log - {datetime.now().isoformat()}\n")
            self._fh.write(
                f"# {'Timestamp':<14} {'Iface':<8} {'Proto':<8} "
                f"{'Src':<20} {'Dst':<20} {'TTL':>4} {'Size':>6}  Info\n"
            )
            self._fh.write("-" * 110 + "\n")
            self._fh.flush()

        elif self.fmt == "json":
            header = {
                "_type":   "sniffer_log_header",
                "started": datetime.now().isoformat(),
                "format":  "jsonl",
                "fields":  FIELDS,
            }
            self._fh.write(json.dumps(header, ensure_ascii=False) + "\n")
            self._fh.flush()

    def write(self, parsed: dict):
        if self.fmt == "csv":
            row = {k: parsed.get(k, "") for k in FIELDS}
            if parsed.get("tcp_options"):
                row["tcp_options"] = str(parsed["tcp_options"])
            self._csv_writer.writerow(row)
            self._fh.flush()

        elif self.fmt == "txt":
            src     = parsed.get("src_ip") or parsed.get("src_mac", "?")
            dst     = parsed.get("dst_ip") or parsed.get("dst_mac", "?")
            ttl     = parsed.get("ttl")
            ttl_str = str(ttl) if ttl is not None else "-"

            line = (
                f"  {parsed.get('timestamp', ''):<14} "
                f"{parsed.get('iface', ''):<8} "
                f"{parsed.get('proto', ''):<8} "
                f"{src:<20} {dst:<20} "
                f"{ttl_str:>4} "
                f"{str(parsed.get('size', 0)):>5}B  "
                f"{parsed.get('summary', '')}\n"
            )
            self._fh.write(line)

            extras = []
            if parsed.get("tcp_seq") is not None:
                extras.append(
                    f"seq={parsed['tcp_seq']} ack={parsed['tcp_ack']} win={parsed['tcp_window']}"
                )
            if parsed.get("frag_mf") or parsed.get("frag_offset"):
                extras.append(
                    f"frag_id={parsed['frag_id']} offset={parsed['frag_offset']} MF={parsed['frag_mf']}"
                )
            if parsed.get("icmp_id") is not None:
                extras.append(f"icmp_id={parsed['icmp_id']} seq={parsed['icmp_seq']}")
            if parsed.get("dns_id") is not None:
                extras.append(
                    f"dns_id={parsed['dns_id']} rcode={parsed['dns_rcode']} qr={parsed['dns_qr']}"
                )
            if parsed.get("dhcp_xid") is not None:
                extras.append(
                    f"xid={parsed['dhcp_xid']:#010x} type={parsed['dhcp_msg_type']}"
                )
            if extras:
                self._fh.write(f"    [{' | '.join(extras)}]\n")
            self._fh.flush()

        elif self.fmt == "json":
            record = {k: parsed.get(k) for k in FIELDS}
            if parsed.get("tcp_options"):
                record["tcp_options"] = parsed["tcp_options"]
            self._fh.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
            self._fh.flush()

    def close(self):
        if self._fh and not self._fh.closed:
            self._fh.close()
        print(f"[*] Log guardado em: {os.path.abspath(self.filename)}")
