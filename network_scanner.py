#!/usr/bin/env python
import scapy.all as scapy
import argparse


def get_arr():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP / IP range. Ex.: name.py -t 192.168.0.1/24")
    option = parser.parse_args()
    return option


def scan(ip):
    arp_req = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_broadcast = broadcast / arp_req
    # print(arp_req_broadcast.summary())
    answered_list = scapy.srp(arp_req_broadcast, timeout=2)[0]
    users_list = []
    for elem in answered_list:
        user_dict = {"ip": elem[1].psrc, "mac": elem[1].hwsrc}
        users_list.append(user_dict)
    return users_list


def print_result(results_list):
    print("IP\t\t\tMAC Address\n-----------------------------------------")
    for user in results_list:
        print(user["ip"] + "\t\t" + user["mac"])


options = get_arr()
scan_result = scan(options.target)
print_result(scan_result)
