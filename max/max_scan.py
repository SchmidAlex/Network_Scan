#!/usr/bin/env python
# Author: Alex
# Version: Betaversion Masscan and over found port with nmap
import argparse
import re
import subprocess
import sys


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
 

def enum(ip, ports, max_rate, speed, directory):
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

    if resultsTCP:
        tcp_ports = list({int(port) for port in resultsTCP})
        tcp_ports.sort()
        tcp_ports = ''.join(str(tcp_ports)[1:-1].split())
        # Running nmap
        cmd = ["sudo", "nmap", "-sV", "-p", tcp_ports, ip, "-T", str(speed), "-oN", directory+"nmap_result_tcp.txt", "-oG", directory+"nmap_result_fortestssl.txt"]
        output = run_command(cmd)
    else:
        outfile = open(directory+"nmap_result_tcp.txt", "at")
        outfile.write("Because we didnt got any TCP-results in masscan, we wont do an nmap on TCP-ports")
        outfile.flush()
        outfile.close()

    # Get discovered UDP ports from the masscan output, sort them and run nmap for those
    if resultsUDP:
        udp_ports = list({int(port) for port in resultsUDP})
        udp_ports.sort()
        udp_ports = ''.join(str(udp_ports)[1:-1].split())
        # Running nmap
        cmd = ["sudo", "nmap", "-sV", "-sU", "-p", udp_ports, ip, "-T", str(speed), "-oN", directory+"nmap_result_tcp.txt"]
        output = run_command(cmd)
    else:
        outfile = open(directory+"nmap_result_udp.txt", "at")
        outfile.write("Because we didnt got any UDP-results in masscan, we wont do an nmap on UDP-ports")
        outfile.flush()
        outfile.close()

    # Test all scanned and open tcp-ports nmap found with testssl

    if resultsTCP:
        with open(directory + "nmap_result_fortestssl.txt", "r") as file :
            filedata = file.read()

        #Replace the filedata with regex somehow from 25 to , TODO:
        filedata = re.sub("\s25.*,", "", filedata)

        with open(directory + "nmap_result_fortestssl.txt", "w") as file :
            file.write(filedata)

        cmd = ["sudo", "/testssl/testssl.sh", "--file", directory + "nmap_result_fortestssl.txt", "-oH", directory + "testssl_result.html"]
        run_command(cmd)
        print("if you got a port 25* you need to scan those ports again because of an issue")
    else:
        cmd = ["sudo", "touch", directory+"testssl_result.txt"]
        output = run_command(cmd)
        outfile = open(directory+"testssl_result.txt", "at")
        outfile.write("No test was made because no open TCP-port was found")
        outfile.flush()
        outfile.close()



def main():
    parser = argparse.ArgumentParser(description="Port/Service enumaration tool.")
    parser.add_argument("IP",  help="IP address to scan.")
    parser.add_argument("-tp", "--tcp-ports", dest="tcp_ports", default="1-65535", help="List of ports/port ranges to scan (TCP only).")
    parser.add_argument("-up", "--udp-ports", dest="udp_ports", default="1-65535", help="List of ports/port ranges to scan (UDP only).")
    parser.add_argument("-r", "--max-rate", dest="max_rate", default=500, type=int, help="Send packets no faster than <number> per second")
    parser.add_argument("-T", "--delay", dest="delay", default=3, type=int, help="Set Delay 0 - 5 (slow - fast)")
    parser.add_argument("-o", "--output", dest="directory", default="", help="Directory to write output to.")
    args = parser.parse_args()
    
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
        
    enum(args.IP, ports, args.max_rate, args.delay, args.directory)
        
    
if __name__ == "__main__":
    main()
