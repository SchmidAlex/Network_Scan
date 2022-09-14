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
    print("\nFunction repoClaim is running. If there is a newer version of this script it will be updated:")
    if not os.path.exists("/Network_Scan"):
        os.mkdir("/Network_Scan")
        cmd = ["sudo", "git", "clone", "https://github.com/SchmidAlex/Network_Scan", "/Network_Scan"]
        run_command(cmd)
    else:
        cmd = ["sudo", "git", "-C", "/Network_Scan", "pull"]
        run_command(cmd)


######### lets the program check for some directories and files #########
def checkDirectories(name, range):
    print("\nCheckdirectories, we check if the directories exists or not and do them if needed:")
    stamp = datetime.now()
    timestamp = stamp.strftime("%d_%m_%Y--%H_%M_%S/")
    
    if not os.path.exists("/results"):
        os.mkdir("/results")

    if "/" in range:
        iprange = re.sub("/", "_", range)
    else:
        iprange = range

    if name:
        if not os.path.exists("/results/"+name):
            os.mkdir("/results/"+name)
        if iprange:
            if not os.path.exists("/results/"+name+"/"+iprange):
                os.mkdir("/results/"+name+"/"+iprange)
            
            os.mkdir("/results/"+name+"/"+iprange+"/"+timestamp)
            return "/results/"+name+"/"+iprange+"/"+timestamp
        else:
            os.mkdir("/results/"+name+"/"+timestamp)
            return "/results/"+name+"/"+timestamp
    else:
        os.mkdir("/results/"+timestamp)
        return "/results/"+timestamp

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
    print("\nRunning masscan 'normal' scan:")
    cmd = ["sudo", "touch", directory+"masscan_result.txt"]
    run_command(cmd)
    #those ports doesnt work :( maybe make two single scans like nmap -> TODO: Ask max
    cmd = ["sudo", "masscan", "-e", "eth0", "--top-ports " + tcpPorts + ",U:" + udpPorts, "--max-rate", str(max_rate), "--interactive", ip]
    output = run_command(cmd)
    outfile = open(directory+"masscan_result.txt", "at")
    for line in output.splitlines():
        if "rate:" not in line: # Don't write 'rate:' lines
            outfile.write(line + "\n")
    outfile.flush()
    outfile.close()


######### lets the programm scan with nmap (normal scan) #########
def nmap(ip, tcpPorts, udpPorts, delay, directory):
    print("\nrunning nmap's 'normal' scan:")
    cmd = ["sudo", "touch", directory+"nmap_result_tcp.txt"]
    cmd = ["sudo", "touch", directory+"nmap_result_fortestssl.txt"]
    cmd = ["sudo", "touch", directory+"nmap_result_udp.txt"]

    # Scan top given TCP ports with nmap
    cmd = ["sudo", "nmap", "-sV", "-Pn", "--top-ports", tcpPorts, "-T", str(delay), "-oN", directory+"nmap_result_tcp.txt", "-oG", directory+"nmap_result_fortestssl.txt", ip]
    run_command(cmd)

    # Scan top given UDP ports with nmap -> it takes ages to run this
    cmd = ["sudo", "nmap", "-sV", "-Pn", "-sU", "--top-ports", udpPorts, "-T", str(delay), "-oN", directory+"nmap_result_udp.txt", ip]
    run_command(cmd)


######### lets the programm check all ssl connections with the script testssl.sh #########
def testssl(directory):
    print("\nCheck if testssl exists and update it, so we can let it run:")
    if not os.path.exists("/testssl"):
        os.mkdir("/testssl")
        cmd = ["sudo", "git", "clone", "https://github.com/drwetter/testssl.sh", "/testssl"]
        run_command(cmd)
    else:
        cmd = ["sudo", "cd", "/testssl"]
        run_command(cmd)
        cmd = ["sudo", "git", "pull"]
        run_command(cmd)

    cmd = ["sudo", "/testssl/testssl.sh", "--file", directory+"nmap_result_fortestssl.txt", "-oL", directory+"testssl_result.txt"]
    run_command(cmd)


######### lets compare the result of the last scan on this system (if existent) with the result of this scan #########
def compare(directory):
    #TODO: make a comparer

    #1. find the old files with the date
    #2. read the old and the new files
    #3. extract the difference -> not just new, but also things that are missing
    #4. write those differences in a new file (something like diff.txt)

    print("TODO")



#
#            MAIN
#################################################################################

def main():
    parser = argparse.ArgumentParser(description="Port/Service enumaration tool.")
    parser.add_argument("IP",  help="IP address to scan.")
    parser.add_argument("-tp", "--tcp-ports", dest="tcp_ports", default="1-65535", help="List of ports/port ranges to scan (TCP only).")
    parser.add_argument("-up", "--udp-ports", dest="udp_ports", default="1-65535", help="List of ports/port ranges to scan (UDP only).")
    parser.add_argument("-r", "--max-rate", dest="max_rate", default=500, type=int, help="Send massscan packets no faster than <number> per second")
    parser.add_argument("-T", "--delay", dest="delay", default=3, type=int, help="Set nmap delay 0 - 5 (slow - fast)")
    parser.add_argument("-o", "--output", dest="name", help="Name to write output to.")
    parser.add_argument("-uo", "--under-output", dest="range", default="", help="IP range you want to scan if several with the same name are going to be scanned.")
    args = parser.parse_args()

    repoClaim()

    directory = checkDirectories(args.name, args.range)

    #get all directories within /result/[name]/ or /result/[name]/[range]


    ######### ISSUES AND DEBUGGING #########

    # 1. nmap cant resolve its ip's, so it gets interrupted and that also means testssl wont run -> idk yet

    cmd = ["sudo", "ls", "/results/" + args.name + "/" + args.range]
    result = run_command(cmd)
    print(result)

    ############ END DEBUGGING ############

    #fast check for ip's
    #masscan(args.IP, args.tcp_ports, args.udp_ports, args.max_rate, directory)

    #nmap(args.IP, args.tcp_ports, args.udp_ports, args.delay, directory)

    #testssl(directory)

    #compare(directory)
        
    
if __name__ == "__main__":
    main()
