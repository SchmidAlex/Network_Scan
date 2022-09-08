#!/usr/bin/env python
# Author: Alex
import argparse
import re
import subprocess
import sys
import os
from datetime import datetime


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
 

def enum(ip, ports, max_rate, speed, directory, ipNmap, nmapPorts, nmapUPorts):
    # Running masscan
    cmd = ["sudo", "touch", directory+"masscan_result.txt"]
    output = run_command(cmd)
    outfile = open(directory+"masscan_result.txt", "at")

    cmd = ["sudo", "masscan", "-e", "eth0", "-p" + ports,
           "--max-rate", str(max_rate), "--interactive", ip]
    output = run_command(cmd)

    for line in output.splitlines():
        if "rate:" not in line: # Don't write 'rate:' lines
            outfile.write(line + "\n")
    outfile.flush()
    outfile.close()

    # Get discovered TCP ports from the masscan output, sort them and run nmap for those
    resultsTCP = re.findall('port (\d*)/tcp', output)
    resultsUDP = re.findall('port (\d*)/udp', output)

    cmd = ["sudo", "touch", directory+"nmap_result_tcp.txt"]
    output = run_command(cmd)
    cmd = ["sudo", "touch", directory+"nmap_result_fortestssl.txt"]
    output = run_command(cmd)
    cmd = ["sudo", "touch", directory+"nmap_result_udp.txt"]
    output = run_command(cmd)

    # ↓ would be the correct way to approve masscans result
    cmd = ["sudo", "nmap", "-sV", "-Pn", "--top-ports", nmapPorts, "-T", str(speed), "-oN", directory+"nmap_result_tcp.txt", "-oG", directory+"nmap_result_fortestssl.txt", ipNmap]
    #run_command(cmd)
    subprocess.run(cmd,shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    # ↓ is a faster way to confirm masscans result
    #if resultsTCP:
    #    tcp_ports = list({int(port) for port in resultsTCP})
    #    tcp_ports.sort()
    #    tcp_ports = ''.join(str(tcp_ports)[1:-1].split())
    #    # Running nmap
    #    cmd = ["sudo", "nmap", "-sV", "-p", tcp_ports, str(ipNmap), "-T", str(speed), "-oN", directory+"nmap_result_tcp.txt", "-oG", directory+"nmap_result_fortestssl.txt"]
    #    output = run_command(cmd)
    #else:
    #    outfile = open(directory+"nmap_result_tcp.txt", "at")
    #    outfile.write("Because we didnt got any TCP-results in masscan, we wont do an nmap on TCP-ports")
    #    outfile.flush()
    #    outfile.close()

    # ↓ would be the correct way to approve masscans result
    cmd = ["sudo", "nmap", "-sV", "--top-ports", nmapUPorts, ipNmap, "-T", str(speed), "-oN", directory+"nmap_result_tcp.txt", "-oG", directory+"nmap_result_fortestssl.txt"]
    run_command(cmd)

    # ↓ is a faster way to confirm masscans result
    #if resultsUDP:
    #    udp_ports = list({int(port) for port in resultsUDP})
    #    udp_ports.sort()
    #    udp_ports = ''.join(str(udp_ports)[1:-1].split())
    #    # Running nmap
    #    cmd = ["sudo", "nmap", "-sV", "-sU", "-p", udp_ports, ipNmap, "-T", str(speed), "-oN", directory+"nmap_result_tcp.txt"]
    #    output = run_command(cmd)
    #else:
    #    outfile = open(directory+"nmap_result_udp.txt", "at")
    #    outfile.write("Because we didnt got any UDP-results in masscan, we wont do an nmap on UDP-ports")
    #    outfile.flush()
    #    outfile.close()

    # Test all scanned and open tcp-ports nmap found with testssl
    if resultsTCP:
        cmd = ["sudo", "/testssl/testssl.sh", "--file", directory+"nmap_result_fortestssl.txt", "-oL", directory+"testssl_result.txt"]
        output = run_command(cmd)
    else:
        cmd = ["sudo", "touch", directory+"testssl_result.txt"]
        output = run_command(cmd)
        outfile = open(directory+"testssl_result.txt", "at")
        outfile.write("No test was made because no open TCP-port was found")
        outfile.flush()
        outfile.close()



def main():

    if not os.path.exists("/Network_Scan"):
        os.mkdir("/Network_Scan")
        cmd = ["sudo", "git", "clone", "https://github.com/SchmidAlex/Network_Scan", "/Network_Scan"]
        run_command(cmd)
        cmd = ["sudo", "chmod", "777", "/Network_Scan/scan.py"]
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
    parser.add_argument("-tpnm", "--udp-ports-nmap", dest="udp_portsnmap", default="10000", help="Top ports to scan (UDP).")
    parser.add_argument("-upnm", "--udp-ports-nmap", dest="udp_portsnmap", default="10000", help="Top ports to scan (UDP).")
    parser.add_argument("-r", "--max-rate", dest="max_rate", default=500, type=int, help="Send massscan packets no faster than <number> per second")
    parser.add_argument("-T", "--delay", dest="delay", default=3, type=int, help="Set nmap delay 0 - 5 (slow - fast)")
    parser.add_argument("-o", "--output", dest="name", help="Name to write output to.")
    parser.add_argument("-uo", "--under-output", dest="range", default="", help="IP range you want to scan if several with the same name are going to be scanned.")
    args = parser.parse_args()

    if not os.path.exists("/results"):
        os.mkdir("/results")

    if args.name:
        if not os.path.exists("/results/"+args.name):
            os.mkdir("/results/"+args.name)
        if args.uo:
            if not os.path.exitsts("/results/"+args.name+args.uo):
                os.mkdir("/results/"+args.name+args.uo)
            
            os.mkdir("/results/"+args.name+args.uo+"/"+timestamp)
            directory = "/results/"+args.name+args.uo+"/"+timestamp
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
        
    enum(args.IP, ports, args.max_rate, args.delay, directory, ipNmap, args.tcp_portsnmap, args.udp_portsnmap)
        
    
if __name__ == "__main__":
    main()
