#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###############################################################################
# 128T session table analysis tool
# 26-Sep-2020 Patrick Timmons
###############################################################################

VERSION = "0.3"

import sys
import json
import requests
import ipaddress
import getopt
import math
from collections import Counter
from tabulate import tabulate
from ascii_graph import Pyasciigraph

def isIncluded(list_a, list_b):
    for i in list_a:
        if i in list_b:
            return True
    return False

def withinPrefix(address, networkList):
    addressPlusMask = ipaddress.ip_network(address + "/32")
    for n in networkList:
        if addressPlusMask.overlaps(n):
            return True
    return False

def makeQuery(routerName, nodeName, last):
    qry = '{allRouters(name: "' + routerName + '") {nodes {nodes'
    if nodeName is not "":
        qry += '(name: "' + nodeName + '")'
    qry += ' {nodes {flowEntries(after: "' + last + '") {nodes {destIp destPort deviceInterfaceName devicePort encrypted forward inactivityTimeout natIp natPort networkInterfaceName protocol serviceName sessionUuid sourceIp sourcePort startTime tenant vlan} pageInfo { endCursor hasNextPage }}}}}}}'
    # print(qry)
    return qry

def jsonToList(jSession):
    if jSession['forward']:
        direction = "fwd"
    else:
        direction = "rev"
    lSession = [jSession['sessionUuid'], direction, jSession['serviceName'], jSession['tenant'], jSession['networkInterfaceName'], jSession['vlan'], jSession['protocol'], jSession['sourceIp'], jSession['sourcePort'], jSession['destIp'], jSession['destPort'], jSession['natIp'], jSession['natPort'], jSession['encrypted'], jSession['inactivityTimeout'], jSession['startTime']]
    return lSession

def convertToString(session):
    result = ""
    for s in session:
       result += str(s) + ' ' 
    result += '\n'
    return result

def main(argv):

    excludeList = []
    serviceList = []
    addressList = []
    prefixList = []
    serviceFilterList = []
    prefixFilterList = []
    portList = []
    filterByService = False
    filterByAddress = False
    filterByPort = False
    filterByPrefix = False
    filterOutPrefix = False
    doGraphQL = True
    drawGraph = False
    histBins = 10
    histMax = 0
    histInterval = 0
    histValues = []
    histList = []
    routerName = ""
    nodeName = ""
    topX = 10
    outfile = ""

    try:
        opts, args = getopt.getopt(argv,"ghva:b:i:n:o:p:r:s:t:x:A:S:X:",["graph","help","version","address=","bins=","input=","node=","output=","port=","router=","service=","top=","prefix=","exclude-address=","exclude-service=","exclude-prefix="])
    except getopt.GetoptError:
        print('analyzer.py -i <inputfile> -x <excludeIPs>')
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-g", "--graph"):
            drawGraph = True
        elif opt in ("-h", "--help"):
            helptext = """Syntax:

  analyzer.py -h 
  analyzer.py -r <routerName> [-n nodeName] [-a <addressList> -A <addressList> -s <serviceList> -S <serviceList> -t <top>]
  analyzer.py -i <inputFile> [-a <addressList> -A <addressList> -s <serviceList> -S <serviceList> -t <top>]

     -i, --input:
             read session table contents from a file (expected format is as provided by the PCLI's 'show sessions')
     -o, --output:
             write session table back into a space-delimited file (can be read in later using '-i'). This is helpful for
             use with extremely busy systems, where it is impractical to repeatedly query the system's session table
             using GraphQL
     -g, --graph:
             produces a histogram output rather than tabular output, grouping flows by expiry time; useful for tuning session-type timers
     -r, --router:
             router name (mandatory when not using -i). Must be run locally on the 128T Conductor, running 4.5.0 or newer
     -n, --node:
             node name (optional; when excluded, analyzer will collect all sessions from all nodes in the specified router)
     -h, --help:
             prints this help text
     -v, --version:
             prints the current version number
     -a, --address:
             when followed by a comma-separated list of addresses, will filter the results to only entries containing that address
     -A, --exclude-address:
             when followed by a comma-separated list of addresses, will filter out any results containing that address
     -s, --service:
             when followed by a comma-separated list of service names, will filter the results to only entries containing that service
     -S, --exclude-service:
             will filter the results and exclude any services supplied as a comma-separated list
     -x, --prefix:
             when followed by a comma-separated list of prefixes, will filter the results to only include sessions with addresses within that prefix
     -X, --exclude-prefix:
             will filter the results to exclude any sessions containing IP addresses within the prefixes supplied as a comma-separated list
     -p, --port:
             will filter the results to include only those containing the port(s) specified as a comma-separated list
     -t, --top:
             (default: 10) sets the number of entries to display per category
     -b, --bins:
             (default: 10) when producing a histogram, the default number of bins is ten; using this parameter can override that default
"""
            print(helptext)
            sys.exit()
        elif opt in ("-v", "--version"):
            print("analyzer version " + VERSION)
            sys.exit()
        elif opt in ("-i", "--input"):
            sessionFile = arg
            doGraphQL = False
        elif opt in ("-A", "--exclude-address"):
            excludeList = arg.split(',')
        elif opt in ("-s", "--service"):
            serviceList = arg.split(',')
            filterByService = True
        elif opt in ("-a", "--address"):
            addressList = arg.split(',')
            filterByAddress = True
        elif opt in ("-p", "--port"):
            portList = arg.split(',')
            filterByPort = True
        elif opt in ("-r", "--router"):
            routerName = arg
        elif opt in ("-n", "--node"):
            nodeName = arg
        elif opt in ("-o", "--output"):
            outfile = arg
        elif opt in ("-S", "--exclude-service"):
            serviceFilterList = arg.split(",")
        elif opt in ("-t", "--top"):
            topX = int(arg)
        elif opt in ("-x", "--prefix"):
            p = ""
            for p in arg.split(','):
                prefixList.append(ipaddress.ip_network(p, False))
            filterByPrefix = True
        elif opt in ("-X", "--exclude-prefix"):
            p = ""
            for p in arg.split(','):
                prefixFilterList.append(ipaddress.ip_network(p, False))
            filterOutPrefix = True
        elif opt in ("-b", "--bins"):
            histBins = int(arg)

    # input validation here
    if doGraphQL and not routerName:
        print("Error: must specify a router name when using GraphQL.")
        sys.exit()
    if not doGraphQL and routerName:
        print("Error: cannot use both input file and GraphQL.")
        sys.exit()

    last = ""
    sessions = []
    udpServices = []
    tcpServices = []
    fwdDestinations = []
    revDestinations = []
    svcDestinations = []
    headers = []

    if doGraphQL:
        done = False
        url = "http://127.0.0.1:31517/api/v1/graphql"
        while not done:
            query = makeQuery(routerName, nodeName, last)
            raw = requests.post(url, json = {'query': query}, headers = headers)
            loopSessions = json.loads(raw.text)
            if loopSessions['data']['allRouters']['nodes'][0]['nodes']['nodes'][0]['flowEntries']['pageInfo']['hasNextPage']:
                last = loopSessions['data']['allRouters']['nodes'][0]['nodes']['nodes'][0]['flowEntries']['pageInfo']['endCursor']
            else:
                done = True
            for jSession in loopSessions['data']['allRouters']['nodes'][0]['nodes']['nodes'][0]['flowEntries']['nodes']:
                session = jsonToList(jSession)
                sessions.append(session)
    else:
        with open(sessionFile) as fin:
            for line in fin:
                if line == "\n":
                    continue
                sessionEntry = line.split()
                if sessionEntry[0][0] not in "0123456789abcdef":
                    # skip over anything that doesn't look like a session ID
                    continue
                sessions.append(sessionEntry)

    """
    This is where we tabulate stuff. For reference, the field mappings are:
     0: session ID (not used)
     1: flow direction, 'fwd' or 'rev'
     2: service name
     3: tenant name (not currently used)
     4: device name (not used)
     5: VLAN (not used)
     6: protocol (TCP or UDP only)
     7: source IP
     8: source port
     9: destination IP
    10: destination port
    11: NAT IP (not used)
    12: NAT port (not used)
    13: Is encrypted (True or False) (not used)
    14: timeout value (not used)
    15+ not used, if present
    """

    for session in sessions:
        if len(session) < 10:
            continue
        if filterByService and (session[2] not in serviceList):
            continue
        if (session[2] in serviceFilterList):
            continue
        if filterByAddress and not isIncluded(addressList, session):
            continue
        if isIncluded(excludeList, session):
            continue
        if filterByPort:
            sessionPorts = []
            sessionPorts.append(str(session[8]))
            sessionPorts.append(str(session[10]))
            if not isIncluded(portList, sessionPorts):
                continue
        if filterByPrefix:
            if not (withinPrefix(session[7],prefixList) or withinPrefix(session[9],prefixList)):
                continue
        if filterOutPrefix:
            if (withinPrefix(session[7], prefixFilterList) or withinPrefix(session[9], prefixFilterList)):
                continue
        svcDestinations.append(session[2])
        if drawGraph:
            histValues.append(int(session[14]))
        if session[1] == 'fwd': 
            fwdDestinations.append(session[9])
            if session[6].upper() == "TCP":
                tcpServices.append(session[10])
            elif session[6].upper() == "UDP":
                udpServices.append(session[10])
        else:
            revDestinations.append(session[7])
            if session[6].upper() == "TCP":
                tcpServices.append(session[8])
            elif session[6].upper() == "UDP":
                udpServices.append(session[8])

    cs = Counter(svcDestinations)
    cf = Counter(fwdDestinations)
    cr = Counter(revDestinations)
    ct = Counter(tcpServices)
    cu = Counter(udpServices)

    if drawGraph:
        histMax = max(histValues)
        # print("histMax: " + str(histMax))
        if histMax < 10:
            histBins = 5
            histInterval = 2
        else:
            histInterval = int(round(histMax, -1) / histBins)
        i = 0
        entry = []
        # seed the histogram
        while i < histBins:
            entry = [str(histInterval * (histBins - 1 - i) + 1) + "-" + str(histInterval * (histBins - i)),0]
            histList.append(entry)
            i += 1
        for x in histValues:
            myBin = min(histBins - math.ceil(x / histInterval), histBins - 1)
            # print("bin: " + str(int(math.ceil(x / histInterval))) + ", histValue: " + str(x) + ", myBin: " + str(myBin))
            histList[myBin][1] += 1
        graph = Pyasciigraph()
        for line in graph.graph('Expiry times', histList):
            print(line)    
        exit()

    output = []

    for x in range (0,topX):
        unified = []
        haveMore = True
        if len(cs.most_common(topX)) < (x + 1):
            unified = unified + [None, None]
            haveMore = False
        else:
            unified = unified + list(cs.most_common(topX)[x])
            haveMore = True
        if len(cf.most_common(topX)) < (x + 1):
            unified = unified + [None, None]
        else:
            unified = unified + list(cf.most_common(topX)[x])
            haveMore = True
        if len(cr.most_common(topX)) < (x + 1):
            unified = unified + [None, None]
        else:
            unified = unified + list(cr.most_common(topX)[x])
            haveMore = True
        if len(ct.most_common(topX)) < (x + 1):
            unified = unified + [None, None]
        else:
            unified = unified + list(ct.most_common(topX)[x])
            haveMore = True
        if len(cu.most_common(topX)) < (x + 1):
            unified = unified + [None, None]
        else:
            unified = unified + list(cu.most_common(topX)[x])
        if (not haveMore):
            break
        output.append(unified)
    tblHeadings = ['Service Name', 'Count', 'Fwd Dest', 'Count', 'Rev Dest', 'Count', 'TCP Port', 'Count', 'UDP Port', 'Count']
    print(tabulate(output, tblHeadings, tablefmt="rst"))
    if outfile:
        with open(outfile, 'w') as file:
            for ses in sessions:
                file.write(convertToString(ses))

if __name__ == '__main__':
    main(sys.argv[1:])
