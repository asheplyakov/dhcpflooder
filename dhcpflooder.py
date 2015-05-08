#!/usr/bin/env python

import os
import random
import scapy.all
import sys
import time

from scapy.all import BOOTP
from scapy.all import DHCP
from scapy.all import Ether
from scapy.all import IP
from scapy.all import UDP
from scapy.all import mac2str
from scapy.all import str2mac
from scapy.all import srp1
from scapy.all import sendp

from optparse import OptionParser


MYSELF = os.path.basename(sys.argv[0])


def make_xid():
    return random.randint(1, 900000000)


def dhcp_discover_pkt(mac, hostname):
    pkt = Ether(src=mac, dst='ff:ff:ff:ff:ff:ff') / \
        IP(src='0.0.0.0', dst='255.255.255.255') / \
        UDP(sport=68, dport=67) / \
        BOOTP(xid=make_xid(), chaddr=mac2str(mac)) / \
        DHCP(options=[('message-type', 'discover'),
                      ('hostname', hostname), 'end'])
    return pkt


def dhcp_request_pkt(offer_pkt, hostname):
    mac = str2mac(offer_pkt[BOOTP].chaddr[:6])
    offered_ip = offer_pkt[BOOTP].yiaddr
    server_mac = offer_pkt[Ether].src
    server_ip = offer_pkt[BOOTP].siaddr
    pkt = Ether(src=mac, dst=server_mac) / \
        IP(src=offered_ip, dst=server_ip) / \
        UDP(sport=68, dport=67) / \
        BOOTP(xid=offer_pkt[BOOTP].xid,
              chaddr=offer_pkt[BOOTP].chaddr,
              ciaddr=offered_ip) / \
        DHCP(options=[('message-type', 'request'),
                      ('server_id', server_ip),
                      ('requested_addr', offered_ip),
                      ('hostname', hostname), 'end'])
    return pkt


def dhcp_release_pkt(request_pkt, hostname):
    my_mac = str2mac(request_pkt[BOOTP].chaddr[:6])
    my_ip = request_pkt[BOOTP].yiaddr
    server_mac = request_pkt[Ether].src
    server_ip = request_pkt[BOOTP].siaddr
    pkt = Ether(src=my_mac, dst=server_mac) / \
        IP(src=my_ip, dst=server_ip) / \
        UDP(sport=68, dport=67) / \
        BOOTP(xid=make_xid(),
              ciaddr=my_ip,
              chaddr=request_pkt[BOOTP].chaddr) / \
        DHCP(options=[('message-type', 'release'),
                      ('server_id', server_ip),
                      ('hostname', hostname), 'end'])
    return pkt


def get_dhcp_message_type(pkt):
    for opt in pkt[DHCP].options:
        if len(opt) > 1 and opt[0] == 'message-type':
            return opt[1]
    return None


def is_dhcp_ack(pkt):
    return get_dhcp_message_type(pkt) == 5


class AngryDHCPClient(object):

    def __init__(self, mac,
                 hostname=None,
                 timeout=0.1,
                 max_count=0,
                 iface=scapy.all.conf.iface):
        # Accept replies no matter what the dest IP is
        scapy.all.conf.checkIPaddr = False
        self.mac = mac
        self.timeout = timeout
        self.iface = iface
        self.obtained_ips = []
        self.hostname = hostname
        self.max_count = max_count
        if self.hostname is None:
            self.hostname = 'client%d' % random.randint(1, 100)

    def run(self):
        count = 0
        while True:
            count += 1
            if (self.max_count > 0) and (count > self.max_count):
                break
            disco_pkt = dhcp_discover_pkt(self.mac, self.hostname)
            disco_reply = srp1(disco_pkt, iface=self.iface, verbose=False)
            request_pkt = dhcp_request_pkt(disco_reply, self.hostname)
            request_reply = srp1(request_pkt, iface=self.iface, verbose=False)
            if is_dhcp_ack(request_reply):
                my_ip = request_reply[BOOTP].yiaddr
                if my_ip not in self.obtained_ips:
                    self.obtained_ips.append(my_ip)
                    print('got new IP for client %s: %s' % (self.mac, my_ip))
                release_pkt = dhcp_release_pkt(request_reply, self.hostname)
                if self.timeout > 0:
                    time.sleep(self.timeout)
                sendp(release_pkt, iface=self.iface, verbose=False)
        print('client %s obtained IPs: %s' % (self.hostname,
                                              ' '.join(self.obtained_ips)))


def main():
    parser = OptionParser()
    parser.add_option('-i', '--interface', default='lo', dest='iface')
    parser.add_option('-t', '--timeout', type=float, default=0.1, dest='timeout')
    parser.add_option('-c', '--request-count', type=int, default=0, dest='max_count')
    parser.add_option('-m', '--magic-mac', type=int, default=-1, dest='magic_mac')
    (options, mac) = parser.parse_args()
    magic_macs = ['0c:c4:7a:1d:91:64',
                  '0c:c4:7a:1d:93:da',
                  '0c:c4:7a:1d:90:fe',
                  '0c:c4:7a:1d:92:76']
    if (options.magic_mac >= 0) and (options.magic_mac < len(magic_macs)):
        mac = magic_macs[options.magic_mac]
    if mac is None:
        print('%s: no client MAC specified' % MYSELF)
        sys.exit(1)
    t = AngryDHCPClient(mac,
                        hostname='node-%s' % mac.split(':')[-1],
                        timeout=options.timeout,
                        iface=options.iface,
                        max_count=options.max_count)
    t.run()
    sys.exit(0)


if __name__ == '__main__':
    main()
