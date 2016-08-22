#!/usr/bin/env python

import sys
from dpkt import pcap
from dpkt import ethernet
from dpkt import ip
from dpkt import tcp
from dpkt import gre

if __name__ == "__main__":
	if len(sys.argv) <= 1:
		print "Usage:", sys.argv[0], " [packet files to write]"
		sys.exit(-1)

	outfile = open("tlsdata.pcap", 'wb')
	outpcap = pcap.Writer(outfile)


	isClient = 1
	clientseq = 1
	clientack = 1
	serverseq = 1
	serverack = 1
	for filename in sys.argv[1:]:
		print "Processing", filename

		f = open(filename, "rb")
		payload = f.read()[16:]
		f.close()

		#Ethernet
		pkt = "\x00" * 12 + "" + "\x08\x00"

		#TCP
		t = tcp.TCP()
		t.flags = tcp.TH_ACK
		t.data = payload
		t.sport = 1000 if isClient else 443
		t.dport = 443 if isClient else 1000

		if isClient == 1:
			t.ack = clientack
			t.seq = clientseq

			clientseq += len(payload)
			serverack += len(payload)

		else:
			t.ack = serverack
			t.seq = serverseq

			serverseq += len(payload)
			clientack += len(payload)

		#IP
		i = ip.IP()
		i.data = str(t)
		i.p = ip.IP_PROTO_TCP
		i.dst = ip.IP_ADDR_ANY if isClient else ip.IP_ADDR_LOOPBACK
		i.src = ip.IP_ADDR_LOOPBACK if isClient else ip.IP_ADDR_ANY

		#Data
		pkt += str(i)
		outpcap.writepkt(str(pkt))

		isClient += 1
		isClient %= 2