# PCAP Network Analyser & IDS

A Python-based network intrusion detection tool that analyses PCAP 
files, detects suspicious traffic patterns using signature-based 
rules, and maps findings to MITRE ATT&CK techniques.

---

## Demo Results

Running against a real public PCAP file:

```
[!! ] Port Scan Detected
      185.129.49.19 → 10.11.14.101 | Source hit 48 ports
      MITRE: T1046

Total alerts: 829
Results saved to output/alerts_20260617_163237.json
```

---

## Features

- Parses real PCAP files using Scapy
- Signature-based detection across 5 threat categories
- MITRE ATT&CK technique mapping for every alert
- Severity-rated alerts (critical / high / medium)
- Auto-exports results to timestamped JSON files
- Tested against real public PCAP traffic captures

---

## Detection Signatures

| Sig ID | Name | Severity | MITRE |
|---|---|---|---|
| SIG-001 | Port Scan Detected | Medium | T1046 |
| SIG-002 | DNS Tunnelling Suspected | High | T1071.004 |
| SIG-003 | Cleartext Credentials | High | T1040 |
| SIG-004 | ICMP Flood | Medium | T1498 |
| SIG-005 | Suspicious User Agent | High | T1071.001 |

---

## Quick Start

```bash
pip install scapy pyshark

python analyser.py samples/your_file.pcap
```

## Getting Sample PCAP Files

All testing done using publicly available PCAP captures:
- malware-traffic-analysis.net
- netresec.com/pcapfiles
- Wireshark sample captures wiki

No malware files are stored in this repository.

---

## Project Structure

```
pcap-analyser/
├── rules/
│   └── signatures.json         # Detection signature definitions
├── samples/
│   └── (place .pcap files here)
├── output/
│   └── (alert results saved here automatically)
├── analyser.py                 # Main IDS analyser
└── README.md
```

---

## Author

Muneeba Sajjad — MSc Cyber Security, University of Hertfordshire
GitHub: github.com/muneeba3
