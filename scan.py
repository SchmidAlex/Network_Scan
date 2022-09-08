#!/usr/bin/env python
# Author: Alex
import argparse
import re
import subprocess
import sys
import os
from datetime import datetime

######### lets the program get git repositories needed or updates #########
def repoClaim():
    #TODO: take it from main and pack it here
    print("TODO")

######### lets the program check for some directories and files #########
def checkDirectories():
    #TODO: take it from main and pack it here
    print("TODO")

######### lets the program run any commandline command #########
def run_command(command):
    print("\nRunning command: "+' '.join(command))
    sp = subprocess.Popen(command, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output = ""
    while True:
        out = sp.stdout.read(1).decode('utf-8')
        if out == '' and sp.poll() != None:
            break
        if out != '':
            output += out
            sys.stdout.write(out)
            sys.stdout.flush()
    return output

######### lets the programm scan with masscan (normal scan) #########
def masscan(ip, tcpPorts, udpPorts, max_rate, directory):
    cmd = ["sudo", "touch", directory+"masscan_result.txt"]
    run_command(cmd)
    cmd = ["sudo", "masscan", "-e", "eth0", "--top-ports" + tcpPorts + ",U:" + udpPorts, "--max-rate", str(max_rate), "--interactive", ip]
    output = run_command(cmd)
    outfile = open(directory+"masscan_result.txt", "at")
    for line in output.splitlines():
        if "rate:" not in line: # Don't write 'rate:' lines
            outfile.write(line + "\n")
    outfile.flush()
    outfile.close()

######### lets the programm scan with nmap (normal scan) #########
def nmap(ip, tcpPorts, udpPorts, delay, directory):
    cmd = ["sudo", "touch", directory+"nmap_result_tcp.txt"]
    cmd = ["sudo", "touch", directory+"nmap_result_fortestssl.txt"]
    cmd = ["sudo", "touch", directory+"nmap_result_udp.txt"]

    # Scan top given TCP ports with nmap
    cmd = ["sudo", "nmap", "-sV", "-Pn", "--top-ports", tcpPorts, "-T", str(delay), "-oN", directory+"nmap_result_tcp.txt", "-oG", directory+"nmap_result_fortestssl.txt", ip]
    run_command(cmd)

    # Scan top given UDP ports with nmap
    cmd = ["sudo", "nmap", "-sV", "-Pn", "-sU", "--top-ports", udpPorts, "-T", str(delay), "-oN", directory+"nmap_result_udp.txt", ip]
    run_command(cmd)

######### lets the programm check all ssl connections with the script testssl.sh #########
def testssl(directory):
    cmd = ["sudo", "/testssl/testssl.sh", "--file", directory+"nmap_result_fortestssl.txt", "-oL", directory+"testssl_result.txt"]
    run_command(cmd)





#
#            MAIN
#################################################################################

def main():

    if not os.path.exists("/Network_Scan"):
        os.mkdir("/Network_Scan")
        cmd = ["sudo", "git", "clone", "https://github.com/SchmidAlex/Network_Scan", "/Network_Scan"]
        run_command(cmd)
    else:
        cmd = ["sudo", "cd", "/Network_Scan"]
        run_command(cmd)
        cmd = ["sudo", "git", "pull"]
        run_command(cmd)

    stamp = datetime.now()

    timestamp = stamp.strftime("%d_%m_%Y--%H_%M_%S/")

    parser = argparse.ArgumentParser(description="Port/Service enumaration tool.")
    parser.add_argument("IP",  help="IP address to scan.")
    parser.add_argument("-tp", "--tcp-ports", dest="tcp_ports", default="1-65535", help="List of ports/port ranges to scan (TCP only).")
    parser.add_argument("-up", "--udp-ports", dest="udp_ports", default="1-65535", help="List of ports/port ranges to scan (UDP only).")
    parser.add_argument("-r", "--max-rate", dest="max_rate", default=500, type=int, help="Send massscan packets no faster than <number> per second")
    parser.add_argument("-T", "--delay", dest="delay", default=3, type=int, help="Set nmap delay 0 - 5 (slow - fast)")
    parser.add_argument("-o", "--output", dest="name", help="Name to write output to.")
    parser.add_argument("-uo", "--under-output", dest="range", default="", help="IP range you want to scan if several with the same name are going to be scanned.")
    args = parser.parse_args()

    if not os.path.exists("/results"):
        os.mkdir("/results")

    if "/" in args.range:
        iprange = re.sub("/", "_", args.range)
    else:
        iprange = args.range

    if args.name:
        if not os.path.exists("/results/"+args.name):
            os.mkdir("/results/"+args.name)
        if iprange:
            if not os.path.exitsts("/results/"+args.name+"/"+iprange):
                os.mkdir("/results/"+args.name+"/"+iprange)
            
            os.mkdir("/results/"+args.name+"/"+iprange+"/"+timestamp)
            directory = "/results/"+args.name+"/"+iprange+"/"+timestamp
        else:
            os.mkdir("/results/"+args.name+"/"+timestamp)
            directory = "/results/"+args.name+"/"+timestamp
    else:
        os.mkdir("/results/"+timestamp)
        directory = "/results/"+timestamp

    if not os.path.exists("/testssl"):
        os.mkdir("/testssl")
        cmd = ["sudo", "git", "clone", "https://github.com/drwetter/testssl.sh", "/testssl"]
        run_command(cmd)
    else:
        cmd = ["sudo", "cd", "/testssl"]
        run_command(cmd)
        cmd = ["sudo", "git", "pull"]
        run_command(cmd)

    if "," in args.IP:
        ipNmap = re.sub(",", " ", args.IP)
        # why cant nmap understand the new ip's?
    else:
        ipNmap = args.IP

    ######### A TRY -> lets try to give nmap ip's and craft them togheter for masscan .... worth a shot


    ######### ISSUES AND DEBUGGING #########

    # 1. nmap cant resolve its ip's, so it gets interrupted and that also means testssl wont run -> idk yet
    # 2. the git-repo of this file will be secured, so the "normal" user cant let it run -> theres a solution, well, a workaround -> untested

    #cmd = ["sudo", "touch", "/home/kali/Desktop/debug.txt"]
    #run_command(cmd)

    #outfile = open("/home/kali/Desktop/debug.txt", "at")
    #outfile.write("IP's nmap: " + ipNmap + "\nIP's: " + args.IP + "\n\n")
    #outfile.flush()
    #outfile.close()

    ############ END DEBUGGING ############


    # Construct ports string
    ports = ""
    tcp = args.tcp_ports and args.tcp_ports.lower() not in ["0", "None"]
    udp = args.udp_ports and args.udp_ports.lower() not in ["0", "None"]
    if tcp:
        ports += args.tcp_ports
    if tcp and udp:
        ports += ","
    if udp:
        ports += "U:" + args.udp_ports

    masscan(args.IP, args.tcp_ports, args.udp_ports, args.max_rate, directory)

    nmap(args.IP, args.tcp_ports, args.udp_ports, args.delay, directory)

    #testssl()
        
    
if __name__ == "__main__":
    main()
