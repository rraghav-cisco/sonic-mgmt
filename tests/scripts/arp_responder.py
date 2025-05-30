import binascii
import json
import argparse
import os.path
from collections import defaultdict
import logging
import scapy.all as scapy
import ipaddress
scapy.MTU = 1280
scapy.conf.use_pcap = True
# Callers: Expect to wait 10-15 seconds here, as scapy reinitializes everything to use libpcap
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


class ARPResponder(object):
    ARP_OP_REQUEST = 1
    ip_sets = {}
    sockets = {}

    @staticmethod
    def action(packet):
        if "ARP" in packet:  # IPv4
            return ARPResponder.reply_to_arp(packet)
        elif "ICMPv6ND_NS" in packet and "ICMPv6NDOptSrcLLAddr" in packet:  # IPv6
            return ARPResponder.reply_to_ndp(packet)
        else:
            # Handle other Ethernet types
            pass

    @staticmethod
    def reply_to_arp(data):
        remote_mac = data["ARP"].hwsrc
        remote_ip = data["ARP"].psrc
        request_ip = data["ARP"].pdst
        op_type = data["ARP"].op

        # Don't send ARP response if the ARP op code is not request
        if op_type != ARPResponder.ARP_OP_REQUEST:
            return

        interface = data.sniffed_on
        if interface not in ARPResponder.ip_sets:
            return
        if request_ip not in ARPResponder.ip_sets[interface]:
            return

        if 'vlan' in ARPResponder.ip_sets[interface]:
            vlan_list = ARPResponder.ip_sets[interface]['vlan']
        else:
            vlan_list = [None]

        for vlan_id in vlan_list:
            arp_reply = ARPResponder.generate_arp_reply(ARPResponder.ip_sets[interface][request_ip],
                                                        remote_mac, request_ip, remote_ip, vlan_id)
            scapy.sendp(arp_reply, socket=ARPResponder.sockets[interface])

    @staticmethod
    def reply_to_ndp(data):
        remote_mac = data["ICMPv6NDOptSrcLLAddr"].lladdr
        remote_ip = data["IPv6"].src
        request_ip = data["ICMPv6ND_NS"].tgt

        interface = data.sniffed_on
        if interface not in ARPResponder.ip_sets:
            return
        if request_ip not in ARPResponder.ip_sets[interface]:
            return

        ndp_reply = ARPResponder.generate_neigh_adv(ARPResponder.ip_sets[interface][request_ip],
                                                    remote_mac, request_ip, remote_ip)
        scapy.sendp(ndp_reply, socket=ARPResponder.sockets[interface])

    @staticmethod
    def generate_arp_reply(local_mac, remote_mac, local_ip, remote_ip, vlan_id):
        l2 = scapy.Ether(dst=remote_mac, src=local_mac, type=(0x8100 if vlan_id else 0x0806))
        l3 = scapy.ARP(op=2, hwsrc=local_mac, psrc=local_ip, hwdst=remote_mac, pdst=remote_ip)
        if vlan_id:
            l2 /= scapy.Dot1Q(vlan=vlan_id, type=0x0806)

        return l2 / l3

    @staticmethod
    def generate_neigh_adv(local_mac, remote_mac, target_ip, remote_ip):
        neigh_adv_pkt = scapy.Ether(src=local_mac, dst=remote_mac)
        neigh_adv_pkt /= scapy.IPv6(src=target_ip, dst=remote_ip)
        neigh_adv_pkt /= scapy.ICMPv6ND_NA(tgt=target_ip, R=0, S=1, O=1)
        neigh_adv_pkt /= scapy.ICMPv6NDOptDstLLAddr(lladdr=local_mac)

        return neigh_adv_pkt


def parse_args():
    parser = argparse.ArgumentParser(description='ARP autoresponder')
    parser.add_argument('--conf', '-c', type=str, dest='conf',
                        default='/tmp/from_t1.json', help='path to json file with configuration')
    parser.add_argument('--extended', '-e', action='store_true',
                        dest='extended', default=False, help='enable extended mode')
    args = parser.parse_args()

    return args


def main():
    args = parse_args()

    if not os.path.exists(args.conf):
        print(("Can't find file %s" % args.conf))
        return

    with open(args.conf) as fp:
        data = json.load(fp)

    # generate ip_sets. every ip address will have it's own uniq mac address
    ip_sets = {}
    sockets = {}
    inverse_sockets = {}
    for iface, ip_dict in list(data.items()):
        vlan = None
        iface = str(iface)
        if iface.find('@') != -1:
            iface, vlan = iface.split('@')
            vlan_tag = format(int(vlan), 'x')
            vlan_tag = vlan_tag.zfill(4)
        if iface not in ip_sets:
            ip_sets[iface] = defaultdict(list)
        if args.extended:
            for ip, mac in list(ip_dict.items()):
                ip_sets[iface][str(ip)] = binascii.unhexlify(str(mac))
        else:
            for ip in ip_dict:
                ip_sets[iface][str(ip)] = scapy.get_if_hwaddr(iface)
        if vlan is not None:
            ip_sets[iface]['vlan'].append(binascii.unhexlify(vlan_tag))

    for iface in ip_sets:
        arp_filter_entries = []
        icmp_filter_entries = []
        for ip in ip_sets[iface]:
            ip_address = ipaddress.ip_address(ip)
            if ip_address.version == 4:
                arp_filter_entries.append(f'arp[24:4] = 0x{int.from_bytes(ip_address.packed, "big"):0x}')  # noqa: E231
            else:
                ipv6_address_integer = int.from_bytes(ip_address.packed, "big")
                # libpcap on Buster doesn't support looking into ICMPv6 header directly, so look from the IPv6 header
                # instead. When the PTF container is upgraded to Bullseye or newer, then the commented filter syntax
                # below can be used instead.
                #
                # icmp_filter_entries.append(f'icmp6[20:4] = 0x{ipv6_address_integer & 0xffffffff:0x}')  # noqa: E231
                icmp_filter_entries.append(f'ip6[60:4] = 0x{ipv6_address_integer & 0xffffffff:0x}')  # noqa: E231
        pcap_filter = f"(arp and ({' or '.join(arp_filter_entries)})) or " + \
            f"(icmp6 and ({' or '.join(icmp_filter_entries)}))"
        sockets[iface] = scapy.conf.L2socket(iface=iface, filter=pcap_filter)
        inverse_sockets[sockets[iface]] = iface

    ARPResponder.ip_sets = ip_sets
    ARPResponder.sockets = sockets

    scapy.sniff(prn=ARPResponder.action, opened_socket=inverse_sockets, store=False)


if __name__ == '__main__':
    main()
