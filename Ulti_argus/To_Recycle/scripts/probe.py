import argparse
import os

import scapy.all as scapy


def scan(ip):
    print(f"[*] Probing network range: {ip}")
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list

def print_result(results_list):
    print("IP Address\t\tMAC Address\t\tHostname (Simulated)")
    print("--------------------------------------------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"] + "\t\t" + "Argus-Node-" + client["mac"][-5:].replace(":",""))

if __name__ == "__main__":
    if os.name == 'nt':
        print("[!] Network probing requires Scapy and Npcap on Windows.")
        print("[!] Running in SIMULATION mode for demonstration.")
        results = [
            {"ip": "192.168.1.1", "mac": "00:de:ad:be:ef:01"},
            {"ip": "192.168.1.10", "mac": "00:de:ad:be:ef:0a"},
            {"ip": "192.168.1.15", "mac": "00:de:ad:be:ef:0f"},
        ]
        print_result(results)
    else:
        parser = argparse.ArgumentParser()
        parser.add_argument("-t", "--target", help="Target IP / IP Range (e.g. 192.168.1.1/24)", required=True)
        args = parser.parse_args()
        scan_result = scan(args.target)
        print_result(scan_result)
