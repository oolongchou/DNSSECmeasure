#!/usr/bin/env python
# coding: utf-8

import time
import os,sys
import datetime
import subprocess, time, datetime, sys
import dns.message
import threading
from multiprocessing import Process
from socket import socket, AF_INET, SOCK_DGRAM
import shutil
import random
import string

## send query of root. ##

def CreatDir():
    current_path = "./dns_packets/"
    try:
        os.makedirs(current_path)
    except Exception as e:
        print e
        pass

    return current_path


bind_ip = "202.112.51.112"  # My IP Addr
speed = 2000  # packets per second"

def start_sniffing(rule=None, iface=None, output=None, option=None):
    if not iface:
        iface = "eth0"
    if not rule:
        rule = ""
    if not option:
        option = ""
    if not output:
        global_time = datetime.datetime.now().strftime("%m%d-%H%M")
        output = "%s.pcap" % global_time
    print "Start sniffing Args OK!"
    cmd1 = "tcpdump -i %s %s -w %s %s" % (iface, rule, output, option)
    print cmd1
    print "TCPdump args OK!"
    # p = subprocess.Popen(cmd1.split())
    p = subprocess.Popen(cmd1, shell=True)
    print "Subprocess OK!"
    time.sleep(3)
    return p


def stop_sniffing(sniff_process, delay=20):
    time.sleep(20)
    sniff_process.terminate()
    time.sleep(delay)
    return


def ScanningOpenDNS(current_path, dnsf, domain_list, dump_file):
    # dump_file is the dir for save pcap file

    domainf = open(domain_list, 'r')
    tld_list = []
    for line in domainf:
        if not line.startswith("#"):
            tld_list.append(line.strip().lower())       # list of all TLDs
    # tld_list = tld_list[110:120]
    tld_list = ["."]

    dns_list = []
    for line in open(dnsf, "r"):
        dns_list.append(line.split("\t")[0])       # public DNS list

    port = random.randint(30000, 60000)

    p1 = start_sniffing(rule="udp and \\(\\(src port 53 and dst port %d\\) \\)" % port,
        output=dump_file, option="-s0 -n -nn -B 30000 ")
    print "Start sniffing ......"
    udp = socket(AF_INET, SOCK_DGRAM)
    udp.bind((bind_ip, port))

    print len(dns_list), "resolvers in total."
    print len(tld_list)
    i = 0
    num_tld = 0
    for tld in tld_list:
        num_tld += 1
        for open_dns in dns_list:
            # for every open DNS resolver, send tld NS query for all tlds.
            try:
                # rdm = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(4))
                query_A = dns.message.make_query(tld, rdtype='NS', want_dnssec=True).to_wire()
                udp.sendto(query_A, (open_dns, 53))

            except Exception as e:
                print "send %s error!\n" % tld, open_dns, e

            i += 1
            if not i % (speed / 5):
                time.sleep(0.2)
            if i % 2000 == 0:
                print i, "packets.", num_tld, "tlds."
        time.sleep(3)

    print "All packets are sent."
    stop_sniffing(p1)
    print "Stop sniffing ......"


def ip_into_int(ip):
    # (((((192 * 256) + 168) * 256) + 1) * 256) + 13
    return reduce(lambda x, y: (x << 8) + y, map(int, ip.split('.')))


def is_internal_ip(ip):
    # print ip
    ip = ip_into_int(ip)
    net_a = ip_into_int('10.255.255.255') >> 24
    net_b = ip_into_int('172.31.255.255') >> 20
    net_c = ip_into_int('192.168.255.255') >> 16
    return ip >> 24 == net_a or ip >> 20 == net_b or ip >> 16 == net_c


def main():
    ts = str(time.time())
    dns_list = "dnslist.txt"
    # get the tld list first
    # os.system("wget https://data.iana.org/TLD/tlds-alpha-by-domain.txt -O " + ts + ".tld")
    # get the root zone file
    os.system("wget https://www.internic.net/domain/root.zone -O zone_file/" + ts + ".zone")

    # get the tld list from the root zone file
    zonef = open("zone_file/" + ts + ".zone")
    tldf = open("tld_list/" + ts + ".tld", "w")
    tldlist = {}
    for line in zonef:
        line = line.strip()
        part = line.split("\t")
        rname = part[0].lower()
        part_new = []
        for item in part:
            if item != "":
                part_new.append(item)
        part = part_new
        rtype = part[3]

        if rtype == "SOA":
            # record the SOA serial.
            serial = part[4].split(" ")[2]
            tldf.write("# Version " + serial + ", Last Updated xxxx.\n")

        if rtype == "NS":
            if rname != "." and rname.count(".") == 1 and rname.endswith("."):
                # this is a tld.
                tldlist[rname.strip(".")] = 0

    for tld in sorted(tldlist.keys()):
        tldf.write(tld + "\n")
    zonef.close()
    tldf.close()

    domain_list = "tld_list/" + ts + ".tld"
    current_path = CreatDir()
    # print "0: Create dir!"

    dump_file = current_path + ts + "_root_dnssec.pcap"
    ScanningOpenDNS(current_path, dns_list, domain_list, dump_file)
    print "1: Scanning OpenDNS "

    os.system("python 9_check_root.py " + dump_file + " zone_file/" + ts + ".zone")

if __name__ == '__main__':
    #for i in range(0, 300):
    #    main()
    #   time.sleep(20)
    print "******** 8: querying root. ********"
    main()
