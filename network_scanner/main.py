# 1. User provides target subnet
# 2. Script sends ARP requests to all IPs
# 3. Devices reply with MAC addresses
# 4. Script collects responses
# 5. Results are printed
# ARP exists because devices need to map:
# IP address  →  MAC address
# devices ask:
# "Who has 192.168.1.5?"
# The owner replies:
# "I do. My MAC is AA:BB:CC:DD:EE:FF"
# That’s ARP summed up

#for this project to run, run ip config on your cmd to see your subnet and then run the command
# python main.py -t 192.168.1.0/24, replace the example subnet here with yours
import scapy.all as scapy
import argparse

#add known macs for testing

KNOWN_MACS=[
    "xx:xx:xx:xx:xx:xx:xx",
    "xx:xx:xx:xx:xx:xx:xx",
]
#fill out this, ask gpt or search it up
OUI_DATABASE = {
    "xx:xx:xx": "TP-Link Router",
    "xx:xx:xx": "Intel / Laptop NIC",
    "xx:xx:xx": "Samsung Device",
    "xx:xx:xx": "Xiaomi / Mobile Device"
}

def get_args():
    parser=argparse.ArgumentParser()
    parser.add_argument("-t","--target",dest="target",help="Target IP/ IP range")
    options=parser.parse_args()
    return options

# now using a function we will create an arp request
def scan(ip):
    arp_request=scapy.ARP(pdst=ip)
    #creates a arp packet instance
    #pdst labels the the ip we are looking for
    broadcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    #creates a ethernet object,sets destination MAC to broadcast MAC
    #dst sets the broadcast MAC Address
    arp_req_brd=broadcast/arp_request
    #combines the broadcast and arp request
    answered_list=scapy.srp(arp_req_brd,timeout=1, verbose=False)[0]
    #gives the first element of the two lists which is the answered lsit
    #Allows us to send packets with our own custom ether part
    #verbose keyword removes unneccesary information
    clients_list=[]
    for element in answered_list:
        client_dict={"ip":element[1].psrc,"mac":element[1].hwsrc}
        clients_list.append(client_dict)
        #psrc prints ip
        #hwsrc prints MAC Address
    return clients_list

def get_vendor(mac):
    prefix = mac.lower()[0:8]
    return OUI_DATABASE.get(prefix, "Unknown Vendor")

def printer(result_lists):
    print("IP\t\t\tMAC Address\n-----------------------------------")
    for client in result_lists :
        ip = client["ip"]
        mac = client["mac"]
        vendor = get_vendor(mac)
        print(client["ip"]+"\t\t"+client["mac"])

        if mac not in KNOWN_MACS:
            print("This is an unknown device:",ip,mac)
            print("the model of this device is:",vendor)


opts=get_args()
scan_list=scan(opts.target)
printer(scan_list)
#this will search all ip's in the subnet