# Nmap Parse info

## What type of file can you parse:
Only nmap xml files<br>
```
#Generate xml file with nmap:
nmap [NAMP OPTIONS] -oX scan
```

## What do you need:
```
pip install argparse
pip install PrettyTable
```

## Usage:
```
nmapParse.py [-h] [-v] [-f [FILE [FILE ...]]]

Process nmap xml for pre-scanning with Nessus.

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         print detailed table
  -f [FILE [FILE ...]], --file [FILE [FILE ...]]
                        file or directory to parse
```

## What can you do:
1. Normal usage:<br>
```
python nmapParse.py -f [FILE [FILE ...]] or python nmapParse.py -f [DIRECTORY] <br>
cat host_information
+------+----------------+-------+--------------------------+--------------------------+
| Name |     Target     | ip up |        Start time        |       Finish time        |
+------+----------------+-------+--------------------------+--------------------------+
|  -   | 192.168.1.0/24 |   5   | Sat Jan 12 10:18:07 2019 | Sat Jan 12 10:18:08 2019 |
+------+----------------+-------+--------------------------+--------------------------+
+------------------------+
| Total up hosts founded |
+------------------------+
|           5            |
+------------------------+
```
2. Verbose usage:
```
python nmapParse.py -v -f [FILE [FILE ...]] or python nmapParse.py -v -f [DIRECTORY] <br>
cat host_information
+------+----------------+-------+--------------------------+--------------------------+
| Name |     Target     | ip up |        Start time        |       Finish time        |
+------+----------------+-------+--------------------------+--------------------------+
|  -   | 192.168.1.0/24 |   5   | Sat Jan 12 10:18:18 2019 | Sat Jan 12 10:18:40 2019 |
+------+----------------+-------+--------------------------+--------------------------+

+--------+---------------+--------------------------------------------------------------------------------+
| Number |       ip      |                           status:portNumber:service                            |
+--------+---------------+--------------------------------------------------------------------------------+
|   1    |  192.168.1.1  |                      o:53:domain, o:80:http, o:443:https                       |
|   2    |  192.168.1.2  | o:21:ftp, o:22:ssh, o:23:telnet, o:80:http, o:5431:park-agent, o:50000:ibm-db2 |
|   3    |  192.168.1.6  |                                                                                |
|   4    |  192.168.1.11 | o:21:ftp, o:22:ssh, o:53:domain, o:80:http, o:5900:vnc, o:9091:xmltec-xmlmail  |
|   5    | 192.168.1.113 | o:21:ftp, o:22:ssh, o:53:domain, o:80:http, o:5900:vnc, o:9091:xmltec-xmlmail  |
+--------+---------------+--------------------------------------------------------------------------------+

+------------------------+
| Total up hosts founded |
+------------------------+
|           5            |
+------------------------+
```
