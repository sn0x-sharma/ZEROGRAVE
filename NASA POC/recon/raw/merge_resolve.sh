#!/bin/bash
set -e
cd /home/sn0x/bb/targets/NASA

# 1. merge + dedupe all discovered hostnames
cat recon/raw/nasa-seed-hosts.txt \
    recon/raw/subfinder-nasa.gov.txt \
    recon/raw/subfinder-globe.gov.txt \
    recon/raw/subfinder-usgeo.gov.txt \
    recon/raw/subfinder-scijinks.gov.txt \
    2>/dev/null | tr 'A-Z' 'a-z' | sed 's/\.$//' | sort -u > recon/raw/all-hosts-merged.txt
echo "nasa.gov" >> recon/raw/all-hosts-merged.txt
echo "www.nasa.gov" >> recon/raw/all-hosts-merged.txt
echo "usgeo.gov" >> recon/raw/all-hosts-merged.txt
echo "www.usgeo.gov" >> recon/raw/all-hosts-merged.txt
echo "globe.gov" >> recon/raw/all-hosts-merged.txt
echo "www.globe.gov" >> recon/raw/all-hosts-merged.txt
echo "scijinks.gov" >> recon/raw/all-hosts-merged.txt
sort -u -o recon/raw/all-hosts-merged.txt recon/raw/all-hosts-merged.txt
echo "MERGED: $(wc -l < recon/raw/all-hosts-merged.txt) unique hosts"

# 2. resolve via dnsx against public resolvers, capture A records
dnsx -l recon/raw/all-hosts-merged.txt \
     -r /home/sn0x/bb/tools/pentest-agents-suite/wordlists/resolvers.txt \
     -a -resp -silent -retry 2 -t 100 -rl 2000 \
     -o recon/raw/dnsx-resolved.txt 2>recon/raw/dnsx.err
echo "RESOLVED: $(wc -l < recon/raw/dnsx-resolved.txt) records"

# 3. filter out RFC1918/loopback/link-local -> keep only public-IP hosts
python3 - << 'PYEOF'
import ipaddress, re

priv_nets = [ipaddress.ip_network(n) for n in [
    "10.0.0.0/8","172.16.0.0/12","192.168.0.0/16",
    "127.0.0.0/8","169.254.0.0/16","0.0.0.0/8","100.64.0.0/10"
]]

def is_private(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in n for n in priv_nets)
    except ValueError:
        return True  # unparsable -> drop

public = []
private = []
with open("recon/raw/dnsx-resolved.txt") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        m = re.match(r"^([a-zA-Z0-9._-]+)\s*\[([0-9.]+)\]$", line)
        if not m:
            continue
        host, ip = m.group(1).rstrip('.'), m.group(2)
        if is_private(ip):
            private.append(f"{host} [{ip}]")
        else:
            public.append(host)

public = sorted(set(public))
with open("recon/raw/public-live-hosts.txt", "w") as f:
    f.write("\n".join(public) + "\n")
with open("recon/raw/internal-private-hosts.txt", "w") as f:
    f.write("\n".join(sorted(set(private))) + "\n")

print(f"PUBLIC: {len(public)} hosts -> recon/raw/public-live-hosts.txt")
print(f"PRIVATE/INTERNAL (excluded, out of scope): {len(private)} hosts -> recon/raw/internal-private-hosts.txt")
PYEOF
