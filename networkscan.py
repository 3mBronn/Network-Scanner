#!/usr/bin/env python3
import scapy.all as scapy
import optparse


def get_user_info():
    object_parse = optparse.OptionParser()
    object_parse.add_option("-i", "--ipadd",dest = "ipadd" ,help="Enter IP address an its prefix length")

    (user_input, arguments) = object_parse.parse_args()

    if not user_input.ipadd:
        parser.error("[-]Please specify an IP address and prefix length. Use --help for more information")
    
    
    return user_input    


def net_scan(ip):
    arp_request = scapy.ARP(pdst = ip)
    
    print("[+]Network scanner has started!")
    broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    combine = broadcast/arp_request
    (answered_list, unanswered_list) = scapy.srp(combine, timeout=1)

    answered_list.summary()





user_ip_add = get_user_info()

net_scan(user_ip_add.ipadd)
