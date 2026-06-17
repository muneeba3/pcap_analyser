import re
import json
import argparse
from collections import defaultdict
from datetime import datetime, timezone
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, DNS, Raw

SIGNATURES = json.load(open("rules/signatures.json"))

SUSPICIOUS_USER_AGENTS = [
    "curl", "wget", "python-requests", "nikto",
    "sqlmap", "nmap", "masscan", "zgrab"
]

CRED_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"password=\w+", r"passwd=\w+", r"pwd=\w+",
        r"username=\w+", r"user=\w+", r"login=\w+"
    ]
]


def analyse_pcap(filepath):
    print(f"Loading {filepath}...")
    packets = rdpcap(filepath)
    print(f"Loaded {len(packets)} packets\n")

    alerts = []
    port_scan_tracker = defaultdict(set)
    icmp_tracker = defaultdict(int)
    dns_tracker = []

    for pkt in packets:
        if not pkt.haslayer(IP):
            continue

        src = pkt[IP].src
        dst = pkt[IP].dst

        # SIG-001: Port scan detection
        if pkt.haslayer(TCP):
            port_scan_tracker[src].add(pkt[TCP].dport)
            if len(port_scan_tracker[src]) > 15:
                alerts.append(make_alert("SIG-001", src, dst,
                    f"Source {src} hit {len(port_scan_tracker[src])} ports"))

        # SIG-002: DNS tunnelling
        if pkt.haslayer(DNS):
            try:
                qname = pkt[DNS].qd.qname.decode()
                if len(qname) > 50:
                    alerts.append(make_alert("SIG-002", src, dst,
                        f"Long DNS query: {qname[:60]}..."))
            except Exception:
                pass

        # SIG-003: Cleartext credentials in HTTP
        if pkt.haslayer(Raw):
            payload = pkt[Raw].load.decode(errors="ignore")
            for pattern in CRED_PATTERNS:
                if pattern.search(payload):
                    alerts.append(make_alert("SIG-003", src, dst,
                        f"Pattern matched: {pattern.pattern}"))
                    break

        # SIG-004: ICMP flood
        if pkt.haslayer(ICMP):
            icmp_tracker[src] += 1
            if icmp_tracker[src] == 50:
                alerts.append(make_alert("SIG-004", src, dst,
                    f"{icmp_tracker[src]} ICMP packets from {src}"))

        # SIG-005: Suspicious user agent
        if pkt.haslayer(Raw):
            payload = pkt[Raw].load.decode(errors="ignore")
            if "User-Agent:" in payload:
                for ua in SUSPICIOUS_USER_AGENTS:
                    if ua.lower() in payload.lower():
                        alerts.append(make_alert("SIG-005", src, dst,
                            f"User-Agent contains: {ua}"))

    return alerts


def make_alert(sig_id, src, dst, detail):
    sig = next(s for s in SIGNATURES if s["id"] == sig_id)
    alert = {
        "alert_id": sig_id,
        "name": sig["name"],
        "severity": sig["severity"],
        "mitre": sig["mitre"],
        "src_ip": src,
        "dst_ip": dst,
        "detail": detail,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    sev_symbol = {"high": "!!!", "medium": "!! ", "low": "!  "}
    print(f"[{sev_symbol.get(sig['severity'], '!')}] {sig['name']}")
    print(f"      {src} → {dst} | {detail}")
    print(f"      MITRE: {sig['mitre']}\n")
    return alert


def main():
    parser = argparse.ArgumentParser(description="PCAP IDS Analyser")
    parser.add_argument("pcap", help="Path to .pcap file")
    args = parser.parse_args()

    alerts = analyse_pcap(args.pcap)

    unique_alerts = {a["alert_id"]: a for a in alerts}
    summary = {
        "file": args.pcap,
        "total_alerts": len(alerts),
        "unique_signatures_triggered": len(unique_alerts),
        "by_severity": {
            "high": len([a for a in alerts if a["severity"] == "high"]),
            "medium": len([a for a in alerts if a["severity"] == "medium"]),
            "low": len([a for a in alerts if a["severity"] == "low"])
        },
        "alerts": alerts
    }

    out = f"output/alerts_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
    with open(out, "w") as f:
        json.dump(summary, f, indent=2)

    print(f"Total alerts: {len(alerts)}")
    print(f"Results saved to {out}")


if __name__ == "__main__":
    main()