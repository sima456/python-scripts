#!/usr/bin/env python3

import subprocess
import argparse
import re

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Interface to change its MAC Address")
    parser.add_argument("-m" , "--mac", dest="new_mac", help="New MAC Address")
    (options) = parser.parse_args()
    if not options.interface:
        parser.error("[-] Please specify an interface, use --help for more info.")
    elif not options.new_mac:
        parser.error("[-] Please specify a new mac, use --help for more info.")
    return options


def change_mac(interface, new_mac):
    print(f"[+] Changing MAC Address For Interface {interface} to {new_mac}")
    subprocess.call(f"ifconfig {interface} down", shell=True)
    subprocess.call(f"ifconfig {interface} hw ether {new_mac}", shell=True)
    subprocess.call(f"ifconfig {interface} up", shell=True)

def get_current_mac(interface):
    ifconfig_result = subprocess.check_output(f"ifconfig {interface}", shell=True)
    mac_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(ifconfig_result))

    if mac_result:
        return mac_result.group(0)
    else:
        print("[-] Could not read MAC Address.")

def main():
    options = get_arguments()
    current_mac = get_current_mac(options.interface)
    print(f"Current MAC = {str(current_mac)}")

    change_mac(options.interface, options.new_mac)

    current_mac = get_current_mac(options.interface)
    if current_mac == options.new_mac:
        print(f"[+] MAC Address was successsfully changed to {current_mac}")
    else:
        print("[-] MAC Address did not get changed.")

if __name__ == "__main__":
    main()
