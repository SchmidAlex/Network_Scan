# Network_Scan

## Manual

### Basic usage: 
/Network_Scan/scan.py -tp [top ports tco] -up [top ports udp] -o [Mainfolder] -uo [subfolder] [IP]

### Options:

**[IP]** -> The IP or IP-Range you want to scan. It can just be one IP or one IP-Range at the moment. Example: 127.0.0.0/24

**-tp** -> The top TCP-Ports you want to scan. Defined as Integer, default is 65535 at the moment. Example: -tp 1000

**-up** -> The top UDP-Ports you want to scan. Defined as Integer, default is 65535 at the moment. Example: -up 1000

**-r** -> The masscan --max-rate option. Send masscan packets no faster than <number> per second. Defined as Integer, default is 500. Example: -r 1000

**-T** -> The nmap -T option. Default is 3. Range is from 0 to 5 (other will throw an nmap error). Example: -T 4

**-o** -> The mainfolder to store the results. Every result will be stored in /results/[-o option]/[timestamp]. Its to sort the results. Example: -o firsttry

**-uo** -> The subfolder to store the results. Every results will be stored in /results/[-o option]/[-uo option]/[timestamp]. Its to sort the results even more. Example: -uo subfolder
