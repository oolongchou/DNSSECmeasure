#!/usr/bin/python
# coding: utf-8

# check if the RRSIG of SOA records match that in zone file.
import dpkt
import socket
import sys
# import dnslib
import dns.message
from IPy import IP
import binascii
import base64

try:
    import unittest2 as unittest
except ImportError:
    import unittest

try:
    import Crypto.Util.number  # pylint: disable=unused-import
    import_ok = True
except ImportError:
    import_ok = False


import dns.dnssec
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset

# pcap_file = sys.argv[1]
pcap_file = "1525291955.57_root_dnssec.pcap"
# zonef = sys.argv[2]
zonef = "1525281134.16.zone"
supposed_soa = "-"

# first, load zone file.
root = dns.name.from_text(".")
root_public_keys = {root: dns.rrset.from_text(
    '.', 172800, 'IN', 'DNSKEY',
    '256 3 8 AwEAAdU4aKlDgEpXWWpH5aXHJZI1Vm9Cm42mGAsqkz3akFctS6zsZHC3pNNMug99fKa7OW+tRHIwZEc//mX8Jt6bcw5bPgRHG6u2eT8vUpbXDPVs1ICGR6FhlwFWEOyxbIIiDfd7Eq6eALk5RNcauyE+/ZP+VdrhWZDeEWZRrPBLjByBWTHl+v/f+xvTJ3Stcq2tEqnzS2CCOr6RTJepprYhu+5Yl6aRZmEVBK27WCW1Zrk1LekJvJXfcyKSKk19C5M5JWX58px6nB1IS0pMs6aCIK2yaQQVNUEg9XyQzBSv/rMxVNNy3VAqOjvh+OASpLMm4GECbSSe8jtjwG0I78sfMZc=',
    '257 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjFFVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoXbfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaDX6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpzW5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relSQageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulqQxA+Uk1ihz0=',
    '257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU='
    )
}

root_ns_rrs = dns.rrset.from_text(".", 518400, 'IN', 'NS',
                                  "a.root-servers.net.",
                                  "b.root-servers.net.",
                                  "c.root-servers.net.",
                                  "d.root-servers.net.",
                                  "e.root-servers.net.",
                                  "f.root-servers.net.",
                                  "g.root-servers.net.",
                                  "h.root-servers.net.",
                                  "i.root-servers.net.",
                                  "j.root-servers.net.",
                                  "k.root-servers.net.",
                                  "l.root-servers.net.",
                                  "m.root-servers.net.",
                                  )

root_soa_rrs = dns.rrset.from_text(".", 86400, 'IN', 'SOA',
                                   'a.root-servers.net. nstld.verisign-grs.com. 2018050200 1800 900 604800 86400')

# print type(root_ns_rrs)

when = 1525261134

def process_thread(filename, name, supposed_soa):
    outputf = open(name.strip("") + "_rrsig.txt", "w")
    inputf = open(filename, "rb")

    pcap = dpkt.pcap.Reader(inputf)
    count = 0
    outline = []
    for ts, buf in pcap:
        count += 1
        if count % 500 == 0:
            print(count, "packets.")
            # break
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            resolver = socket.inet_ntoa(ip.src)
            ip_dst = socket.inet_ntoa(ip.dst)

            try:
                udp = ip.data
                dns_obj = dns.message.from_wire(udp.data)
                outline_soa = ""
                query_domain = ""
                for rr in dns_obj.question:
                    query_domain = rr.name.to_text().lower()

                for rr in dns_obj.answer:
                    qname = rr.name.to_text().lower()
                    if qname != ".":
                        continue
                    # check records in the authority section.
                    if rr.rdtype == dns.rdatatype.RRSIG:
                        qdata = rr.items
                        # print type(rr)
                        print(rr)
                       
                        dns.dnssec.validate(root_ns_rrs, rr, root_public_keys, None, when)
                        # print resolver

                for rr in dns_obj.authority:
                    qname = rr.name.to_text().lower()
                    if qname != ".":
                        continue
                    # check records in the authority section.
                    if rr.rdtype == dns.rdatatype.RRSIG:
                        qdata = rr.items[0]
                        if qdata.type_covered == dns.rdatatype.SOA:
                            # print type(rr)
                            print rr

                            dns.dnssec.validate(root_soa_rrs, rr, root_public_keys, None, None)
                            # print resolver
            except Exception as e:
                print("Error:", resolver, ip_dst, e)
                # continue

        except Exception as e:
            continue

    inputf.close()
    for line in sorted(outline):
        outputf.write(line + "\n")

print("******** 9: checking root records. ********")
#process_thread(pcap_file, zonef, supposed_soa)
print("******")
process_thread("1525281134.16_one_nxtld.pcap", zonef, supposed_soa)
# process_thread("../../nsec_test.pcap")
