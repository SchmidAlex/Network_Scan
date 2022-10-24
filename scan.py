#!/usr/bin/env python
# Author: Alex
import argparse
from functions import *

def main():
    parser = argparse.ArgumentParser(description="Port/Service enumaration tool.")
    parser.add_argument("IP",  help="IP address to scan.")
    parser.add_argument("-tp", "--tcp-ports", dest="tcp_ports", default="65535", help="List of ports/port ranges to scan (TCP only).")
    parser.add_argument("-up", "--udp-ports", dest="udp_ports", default="65535", help="List of ports/port ranges to scan (UDP only).")
    parser.add_argument("-r", "--max-rate", dest="max_rate", default=500, type=int, help="Send masscan packets no faster than <number> per second")
    parser.add_argument("-T", "--delay", dest="delay", default=3, type=int, help="Set nmap delay 0 - 5 (slow - fast)")
    parser.add_argument("-o", "--output", dest="name", help="Name to write output to.")
    parser.add_argument("-uo", "--under-output", dest="range", default="", help="IP range you want to scan if several with the same name are going to be scanned.")
    args = parser.parse_args()

    repoClaim()

    timestamp = getTimestamp()
    oldDirectory = getLastScanDirectory(timestamp, args.name, args.range)
    newDirectory = checkDirectories(args.name, args.range, timestamp.strftime("%d_%m_%Y--%H_%M_%S/"))


    ######### ISSUES AND DEBUGGING #########

    # 1. Masscan command isnt correct at all right now... also it doesnt find anything with the --top-ports argument -> fix this

    ############ END DEBUGGING ############


    masscan(args.IP, args.tcp_ports, args.udp_ports, args.max_rate, newDirectory)

    nmap(args.IP, args.tcp_ports, args.udp_ports, args.delay, newDirectory)

    testssl(newDirectory)

    openVasTest(newDirectory)

    if oldDirectory:
        compare(newDirectory, oldDirectory)

    print("If you found any SMTP-Services on Port 25, you need to test them extra with testssl!")
        
    
if __name__ == "__main__":
    main()
