#!/usr/bin/env bash
# Discover a Windows macvtap guest by MAC, then add its host-only macvlan route.
# Never edits the guest, its firewall, its IP settings, or Thessley configuration.
set -Eeuo pipefail

[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "Run with sudo: sudo bash $0 [DOMAIN]" >&2; exit 1; }
for tool in virsh ip arp-scan python3; do
    command -v "$tool" >/dev/null || { echo "Required tool missing: $tool" >&2; exit 1; }
done
parent=${THESSLEY_VM_PARENT:-enp1s0}
host_iface=${THESSLEY_VM_HOST_IFACE:-mvwin11}
host_ip=${THESSLEY_VM_HOST_IP:-192.168.1.250}
lan_cidr=${THESSLEY_VM_LAN_CIDR:-192.168.1.0/24}
domain=${1:-}
if [[ -z $domain ]]; then
    mapfile -t candidates < <(virsh -c qemu:///system list --state-running --name | awk 'tolower($0) ~ /^win/ {print}')
    [[ ${#candidates[@]} -eq 1 ]] || { echo 'Specify the Windows VM domain; there is not exactly one running Windows guest.' >&2; exit 1; }
    domain=${candidates[0]}
fi
[[ $(virsh -c qemu:///system domstate "$domain") == running ]] || { echo "VM is not running: $domain" >&2; exit 1; }
ip link show "$host_iface" >/dev/null 2>&1 || { echo "Host macvlan $host_iface is missing; see docs/TEST-VM-NETWORK.md." >&2; exit 1; }
ip -4 -o addr show dev "$host_iface" | awk '{print $4}' | cut -d/ -f1 | grep -Fxq "$host_ip" || {
    echo "$host_iface does not have expected host address $host_ip; refusing to change a route." >&2; exit 1;
}
metadata=$(virsh -c qemu:///system dumpxml "$domain" | python3 -c '
import sys,xml.etree.ElementTree as ET
root=ET.parse(sys.stdin).getroot()
lan=[]; nat=[]
for interface in root.findall("./devices/interface"):
    source=interface.find("source"); mac=interface.find("mac")
    if source is None or mac is None: continue
    if interface.get("type")=="direct" and source.get("dev")==sys.argv[1]:
        if source.get("mode")!="bridge": raise SystemExit("LAN adapter is not in macvtap bridge mode")
        lan.append(mac.get("address", "").lower())
    elif interface.get("type")=="network" and source.get("network")=="default":
        nat.append(mac.get("address", "").lower())
if len(lan)!=1: raise SystemExit("Expected one existing direct LAN adapter on "+sys.argv[1])
print(lan[0]); print(nat[0] if nat else "")
' "$parent")
lan_mac=$(printf '%s\n' "$metadata" | head -1)
nat_mac=$(printf '%s\n' "$metadata" | sed -n '2p')
echo "VM: $domain"
echo "LAN MAC: $lan_mac (direct bridge on $parent)"
# The parent physical NIC cannot reliably discover its own macvtap guests.
scan=$(arp-scan --interface="$host_iface" "$lan_cidr")
lan_ip=$(printf '%s\n' "$scan" | awk -v mac="$lan_mac" 'tolower($2)==mac {print $1; exit}')
if [[ -z $lan_ip ]]; then
    echo 'The LAN adapter has not answered ARP yet. Let Windows obtain DHCP, then rerun this command.' >&2
    exit 2
fi
python3 -c 'import ipaddress,sys; assert ipaddress.ip_address(sys.argv[1]) in ipaddress.ip_network(sys.argv[2],strict=False)' "$lan_ip" "$lan_cidr"
ip route replace "$lan_ip/32" dev "$host_iface" src "$host_ip"
echo "LAN address: $lan_ip"
ip route get "$lan_ip"
if [[ -n $nat_mac ]]; then
    nat_ip=$(virsh -c qemu:///system domifaddr "$domain" --source lease | awk -v mac="$nat_mac" 'tolower($2)==mac {print $4; exit}')
    echo "NAT management address: ${nat_ip:-not leased yet}"
fi
if command -v nc >/dev/null && nc -z -w 3 "$lan_ip" 22 >/dev/null 2>&1; then
    echo 'SSH TCP 22: reachable from the Ubuntu host'
else
    echo 'SSH TCP 22: not responding; guest firewall and sshd were not changed'
fi
echo 'Choose the adapter displaying the LAN address in the Windows installer.'
echo 'The host route is runtime-only. Rerun after DHCP changes or host reboot.'
