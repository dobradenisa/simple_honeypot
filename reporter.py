import json
import glob
from collections import Counter
from datetime import datetime

ips = Counter()
paths = Counter()
sigs = Counter()
uas = Counter()

for file in sorted(glob.glob("Logs/honeypot-*.jsonl")):
    for line in open(file, "r", encoding="utf-8"):
        e = json.loads(line)
        ip = e.get("ip") or e.get("src_ip")
        if ip:
            ips[ip] += 1
        paths[e["path"]] += 1
        uas[e["user_agent"]] += 1
        for s in e["signatures"]:
            sigs[s] += 1

with open("report.md", "w", encoding="utf-8") as r:
    r.write(f"# Honeypot Report\nGenerated: {datetime.utcnow()}\n\n")

    r.write("## Top IPs\n")
    for ip, c in ips.most_common(10):
        r.write(f"- {ip}: {c}\n")

    r.write("\n## Top Endpoints\n")
    for p, c in paths.most_common(10):
        r.write(f"- {p}: {c}\n")

    r.write("\n## Attack Types\n")
    for s, c in sigs.most_common():
        r.write(f"- {s}: {c}\n")

    r.write("\n## User Agents\n")
    for ua, c in uas.most_common(10):
        r.write(f"- {ua}: {c}\n")