#!/usr/bin/env python
# Author: Alex
import argparse
#import difflib
import re
import subprocess
import sys
import os
from datetime import datetime
import xml.etree.ElementTree as elementTree

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


######### check for needed dependencies #########
def getDependencies():
    print('TODO: dependenciechecker when needed so just maybe')



######### needed to compare differences between the scans #########
def getTimestamp():
    print("\nCreate a timestamp we will need")
    return datetime.now()


######### lets the program check for some directories and files #########
def checkDirectories(name, range, timestamp):
    print("\nCheckdirectories, we check if the directories exists or not and do them if needed:")
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
def masscan(ip, tcpPorts, udpPorts, max_rate, newDirectory):
    print("\nRunning masscan 'normal' scan:")
    cmd = ["sudo", "touch", newDirectory+"masscan_result.txt"]
    run_command(cmd)
    #those ports (udp/tcp) doesnt work :( maybe make two single scans like nmap -> TODO: Ask max
    cmd = ["sudo", "masscan", "-e", "eth0", "--top-ports " + tcpPorts + ",U:" + udpPorts, "--max-rate", str(max_rate), "--interactive", ip]
    output = run_command(cmd)
    outfile = open(newDirectory+"masscan_result.txt", "at")
    for line in output.splitlines():
        if "rate:" not in line: # Don't write 'rate:' lines
            outfile.write(line + "\n")
    outfile.flush()
    outfile.close()


######### lets the programm scan with nmap (normal scan) #########
def nmap(ip, tcpPorts, udpPorts, delay, newDirectory):
    print("\nrunning nmap's 'normal' scan:")
    cmd = ["sudo", "touch", newDirectory+"nmap_result_tcp.txt"]
    cmd = ["sudo", "touch", newDirectory+"nmap_result_fortestssl.txt"]
    cmd = ["sudo", "touch", newDirectory+"nmap_result_udp.txt"]

    # # Scan top given TCP ports with nmap
    # cmd = ["sudo", "nmap", "-sV", "-Pn", "--top-ports", tcpPorts, "-T", str(delay), "-oN", newDirectory+"nmap_result_tcp.txt", "-oG", newDirectory+"nmap_result_fortestssl.txt", ip]
    # run_command(cmd)

    # # Scan top given UDP ports with nmap -> it takes ages to run this TODO: uncomment it when testing is done
    # # cmd = ["sudo", "nmap", "-sV", "-Pn", "-sU", "--top-ports", udpPorts, "-T", str(delay), "-oN", newDirectory+"nmap_result_udp.txt", ip]
    # # run_command(cmd)


    # the lines above works correct, i commented it out and made a new one for testing xml output
    cmd = ["sudo", "nmap", "-sV", "-Pn", "--top-ports", tcpPorts, "-T", str(delay), "-oN", newDirectory+"nmap_result_tcp.txt", "-oG", newDirectory+"nmap_result_fortestssl.txt", "-oX", newDirectory+"nmap_result_xml.xml", ip]
    run_command(cmd)




######### lets the programm check all ssl connections with the script testssl.sh #########
def testssl(newDirectory):
    print("\nCheck if testssl exists and update it, so we can let it run:")
    if not os.path.exists("/testssl"):
        os.mkdir("/testssl")
        cmd = ["sudo", "git", "clone", "https://github.com/drwetter/testssl.sh", "/testssl"]
        run_command(cmd)
    else:
        cmd = ["sudo", "git", "-C", "/testssl", "pull"]
        run_command(cmd)

    cmd = ["sudo", "/testssl/testssl.sh", "--file", newDirectory+"nmap_result_fortestssl.txt", "-oL", newDirectory+"testssl_result.txt"]
    run_command(cmd)


def ovaTest(newDirectory):
    #TODO: let OVA test the ip's and output the result into a file
    print("todo")


######### I need the directory of the last Scan made to this customer and ip-range #########
def getLastScanDirectory(timestamp, name, range):
    print("Get the directory of the last scan made:")
    customer = "/results/" + name + "/" + range + "/"
    cmd = ["sudo", "ls", customer]
    result = run_command(cmd)

    if result:
        datearrayString = result.split()
        datearrayInt = []

        for val in datearrayString:
            datearrayInt.append(datetime.strptime(val, "%d_%m_%Y--%H_%M_%S"))

        return customer + min(datearrayInt, key=lambda sub: abs(sub - timestamp)).strftime("%d_%m_%Y--%H_%M_%S/")
    else:
        return None


def compare(newDirectory, oldDirectory):
    # cmd = ["sudo", "touch", newDirectory + "nmap_result_difference.txt"]
    # run_command(cmd)

    # diffFile = open(newDirectory+"nmap_result_difference.txt", "at")

    # with open(newDirectory+"nmap_result_tcp.txt", 'r') as newFile:
    #         newFileText = newFile.readlines()
    # with open(oldDirectory+"nmap_result_tcp.txt", 'r') as oldFile:
    #         oldFileText = oldFile.readlines()

    # diff = difflib.unified_diff(
    #     oldFileText, newFileText, fromfile="file1.txt", tofile="file2.txt", lineterm=''
    # )

    # for line in diff:
    #     if line.startswith("-"):
    #         diffFile.write(line + "\n")
    #     elif line.startswith("+"):
    #         diffFile.write(line + "\n")
    #     else:
    #         print("not written: " + line + "\n")

    # diffFile.flush()
    # diffFile.close()

    # The code above works... but it isnt really beatifull, thats why i try it with XML below
    ##########################################################################################

    cmd = ["sudo", "touch", newDirectory + "nmap_result_difference.txt"]
    run_command(cmd)

    newTree = elementTree.parse(newDirectory+"nmap_result_xml.xml")
    newTreeFinding = []

    oldTree = elementTree.parse(oldDirectory+"nmap_result_xml.xml")
    oldTreeFinding = []

    i = 0
    tempHost = None

    newRoot = newTree.getroot()
    for child in newRoot.findall("host"):
        for host in child.findall("address"):
            if host.attrib['addrtype'] == 'ipv4':
                newTreeFinding.append({'host': str(host.attrib['addr']), str(host.attrib['addr']): []})
                tempHost = str(host.attrib['addr'])
        for ports in child.findall('ports'):
            for port in ports.findall('port'):
                print(str(port.attrib['protocol']) + "/" + str(port.attrib['portid']))
                if port.find('state').attrib['state'] == 'open':
                    # i was working here
                    newTreeFinding[i][tempHost] = {
                        'port': str(port.attrib['portid']),
                        'protocol': str(port.attrib['protocol']),
                        'state': str(port.find('state').attrib['state']),
                        'name': str(port.find('service').attrib['name'])
                    }
        i += 1
    print(newTreeFinding)
        



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

    timestamp = getTimestamp()
    oldDirectory = getLastScanDirectory(timestamp, args.name, args.range)
    newDirectory = checkDirectories(args.name, args.range, timestamp.strftime("%d_%m_%Y--%H_%M_%S/"))


    ######### ISSUES AND DEBUGGING #########

    # 1. nmap cant resolve its ip's, so it gets interrupted and that also means testssl wont run -> idk yet
    # 2. testssl stops after testing SMTP ports...

    ############ END DEBUGGING ############


    masscan(args.IP, args.tcp_ports, args.udp_ports, args.max_rate, newDirectory)

    nmap(args.IP, args.tcp_ports, args.udp_ports, args.delay, newDirectory)

    testssl(newDirectory)

    ovaTest(newDirectory)

    if oldDirectory:
        compare(newDirectory, oldDirectory)
        
    
if __name__ == "__main__":
    main()
