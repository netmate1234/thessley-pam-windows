# Windows test VM networking from the Ubuntu host

A QR approval link must contain an address reachable by the phone. Our Windows test guests have two adapters: libvirt NAT for host management and a direct/macvtap adapter in bridge mode on `enp1s0` for the home LAN. Keep both adapters. In the Thessley installer, choose the adapter with a `192.168.1.x` LAN address; the NAT address under `192.168.122.x` is not the phone address.

## Prepare each fresh clone

Run this on the Ubuntu hypervisor, after the Windows guest starts:

```sh
sudo bash scripts/prepare-test-vm-network.sh
```

When several Windows guests are running, specify the intended domain:

```sh
sudo bash scripts/prepare-test-vm-network.sh windows-pro-w-ssh-clone1
```

The helper identifies the guest from libvirt XML and matches its direct NIC's MAC to a LAN ARP response. It discovers the current DHCP address, adds only that guest's `/32` route through `mvwin11`, and checks TCP 22. It does not modify Windows, guest firewall rules, SSH authentication, or Thessley installation. If no DHCP address is visible, it stops and asks you to rerun after Windows brings Ethernet up.

## Why the host needs an extra route

Linux's macvtap arrangement normally prevents the parent host interface from talking directly to its own guest. Other LAN devices can still reach the guest. The host uses a sibling macvlan interface, `mvwin11`, at `192.168.1.250/32` to reach the guest through the same Ethernet network.

Discovery must use that sibling interface:

```sh
virsh -c qemu:///system domiflist VM_NAME
sudo arp-scan --interface=mvwin11 192.168.1.0/24
```

Match the MAC shown for the guest's direct adapter. Scanning `enp1s0` can miss the guest even when Windows already has a working DHCP address. Do not reuse an IP from an earlier clone.

The helper applies the equivalent of this command, using the discovered IP:

```sh
sudo ip route replace GUEST_LAN_IP/32 dev mvwin11 src 192.168.1.250
```

This route lasts until the host reboots or its interface is recreated. Rerun the helper after DHCP changes. The helper requires the existing `mvwin11` interface and its expected address; it refuses to invent a new host address.

If that host interface is missing after a reboot, first ensure `192.168.1.250` is still reserved for this host, then restore the documented interface:

```sh
sudo ip link add mvwin11 link enp1s0 type macvlan mode bridge
sudo ip address add 192.168.1.250/32 dev mvwin11
sudo ip link set mvwin11 up
sudo bash scripts/prepare-test-vm-network.sh VM_NAME
```

For another host, set `THESSLEY_VM_PARENT`, `THESSLEY_VM_HOST_IFACE`, `THESSLEY_VM_HOST_IP`, and `THESSLEY_VM_LAN_CIDR` when invoking the helper. Its defaults describe this test environment.

## Phone access through VPN

The phone's OpenVPN profile receives the route to `192.168.1.0/24`. OPI5 at `192.168.1.200` forwards and masquerades the VPN traffic into that LAN. Verify the LAN path from OPI5 without changing firewall rules:

```sh
ssh -p 50022 ubuntu@192.168.1.200 'timeout 3 bash -c "cat </dev/null >/dev/tcp/GUEST_LAN_IP/22" && echo reachable'
```

A successful host and OPI5 check verifies those network paths, not a direct phone connection. If ADB is available, a separate phone-side TCP check can verify the final client path. ICMP ping may be blocked by Windows and is not required.

The Thessley installer configures TCP 47810 and optional HTTPS 47820. Network preparation must not add those firewall rules manually. Keep the installer source types for local networks and VPN clients selected.

## SPICE clipboard

Keep SPICE guest tools in the clean template and the `com.redhat.spice.0` channel in the VM definition. The Windows SPICE agent must be running for clipboard transfer. Treat clipboard troubleshooting separately from network preparation; do not reinstall Thessley to fix clipboard support.
