#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###############################################################################
# 128T session table analysis tool
# 26-Sep-2020 Patrick Timmons
###############################################################################

__version__ = "0.4"

import sys
import json
import requests
import ipaddress
import argparse
import math
import logging
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
    if nodeName is not None:
        qry += '(name: "' + nodeName + '")'
    qry += ' {nodes {flowEntries(after: "' + last + '") {nodes {destIp destPort ' \
           + 'deviceInterfaceName devicePort encrypted forward inactivityTimeout natIp ' \
           + 'natPort networkInterfaceName protocol serviceName sessionUuid sourceIp ' \
           + 'sourcePort startTime tenant vlan} pageInfo { endCursor hasNextPage }}}}}}}'
    # print(qry)
    return qry


def jsonToList(jSession):
    if jSession['forward']:
        direction = "fwd"
    else:
        direction = "rev"
    lSession = [jSession['sessionUuid'], direction, jSession['serviceName'], 
                jSession['tenant'], jSession['networkInterfaceName'], jSession['vlan'], 
                jSession['protocol'], jSession['sourceIp'], jSession['sourcePort'], 
                jSession['destIp'], jSession['destPort'], jSession['natIp'], 
                jSession['natPort'], jSession['encrypted'], jSession['inactivityTimeout'], 
                jSession['startTime']]
    return lSession


def convertToString(session):
    result = ""
    for s in session:
       result += str(s) + ' ' 
    result += '\n'
    return result


def main(argv):

    logger = logging.getLogger()
    handler = logging.FileHandler("/var/log/128technology/analyzer.log")
    formatter = logging.Formatter('%(asctime)s %(levelname)-8s %(message)s')
    formatter.default_msec_format = '%s.%03d'
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    logger.info("Starting analyzer.py")

    parser = argparse.ArgumentParser(description = '128T session table analyzer')

    get_data_source_group = parser.add_mutually_exclusive_group(required = True)
    get_data_source_group.add_argument('--input', '-i', metavar = '<filename>',
                                       type = str, help = "use <filename> for data source")
    get_data_source_group.add_argument('--router', '-r', metavar = "<router>", type = str, 
                                       help = "retrieve sessions from router <router>")
    get_data_source_group.add_argument('--version', '-v', action = 'store_true', 
                                       help = 'print version information and exit')

    parser.add_argument('--log', '-l', metavar = '<loglevel>', type = str, default = 'INFO', 
                        help = 'set log level (default: INFO)')

    parser.add_argument('--node', '-n', metavar = '<nodename>', type = str, 
                        help = 'limit results to the specific node')
    parser.add_argument('--output', '-o', metavar = '<filename>', 
                        help = 'store session table in a local file for future re-use')
    parser.add_argument('--graph', '-g', action = 'store_true', 
                        help = 'draw histogram instead of tabular output')
    parser.add_argument('--address', '-a', nargs = '+',
                        help = 'limit results to only include specified addresses')
    parser.add_argument('--exclude-address', '-A', nargs = '+', 
                        help = 'IP addresses to filter out from results')
    
    service_group = parser.add_mutually_exclusive_group()
    service_group.add_argument('--service', '-s', nargs = '+',
                               help = 'limit results to specified services')
    service_group.add_argument('--exclude-service', '-S', nargs = '+',
                               help = 'exclude specified services from results')

    parser.add_argument('--prefix', '-x', nargs = '+', 
                        help = 'limit results to only those that contain the prefix(es)')
    parser.add_argument('--exclude-prefix', '-X', nargs = '+', 
                        help = 'filter results that include addresses within the prefix(es)')

    parser.add_argument('--port', '-p', metavar='+', nargs = '+', type = int, 
                        help = 'limit results to those that reference the specific port(s)')

    parser.add_argument('--top', '-t', metavar = '<n>', type = int, default = 10,
                        help = 'show top <n> values in tabular output (default: 10)')
    parser.add_argument('--bin', '-b', metavar = '<n>', type = int, default = 10, 
                        help = 'render histogram with <n> bins (default: 10)')

    args = parser.parse_args()
    logger.setLevel(args.log.upper())
    logger.info("Set log level to " + args.log.upper())

    if args.version:
        print("analyzer version " + __version__)
        exit()

    prefixList = []
    if args.prefix is not None:
        for pfx in args.prefix:
            prefixList.append(ipaddress.ip_network(pfx, False))

    excludePrefixList = []
    if args.exclude_prefix is not None:
        for pfx in args.exclude_prefix:
            excludePrefixList.append(ipaddress.ip_network(pfx, False))

    histBins = args.bin
    histMax = 0
    histInterval = 0
    histValues = []
    histList = []

    """Syntax:

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

    last = ""
    sessions = []
    udpServices = []
    tcpServices = []
    fwdDestinations = []
    revDestinations = []
    fwdSources = []
    revSources = []
    svcDestinations = []
    headers = []

    if args.router:
        logger.info("Retrieving sessions via GraphQL")
        done = False
        url = "http://127.0.0.1:31517/api/v1/graphql"
        while not done:
            query = makeQuery(args.router, args.node, last)
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
        logger.info("Retrieving sessions from " + args.input)
        with open(args.input) as fin:
            if args.input.endswith('json'):
                # this is a total hack...
                # assume it's a profiles dataset because the filename ends with json
                profiles = json.loads(fin.read())
                for address in profiles:
                    for sessionID in profiles[address]:
                        jsession = profiles[address][sessionID]
                        jsession['sourceIp'] = address
                        jsession['sessionUuid'] = sessionID
                        session = jsonToList(jsession)
                        sessions.append(session)
            else:
                for line in fin:
                    if line == "\n":
                        continue
                    sessionEntry = line.split()
                    if sessionEntry[0][0] not in "0123456789abcdef":
                        # skip over anything that doesn't look like a session ID
                        continue
                    sessions.append(sessionEntry)
    logger.info("Loaded " + str(len(sessions)) + " entries")

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
        if args.service is not None and (session[2] not in args.service):
            continue
        if args.exclude_service is not None and (session[2] in args.exclude_service):
            continue
        if args.address is not None and not isIncluded(args.address, session):
            continue
        if args.exclude_address is not None and isIncluded(args.exclude_address, session):
            continue
        if args.port is not None:
            if not (session[8] in args.port or session[10] in args.port):
                logger.debug("Port filter not satisfied: " + str(args.port) + ", " + session[8] + ", " + session[10])
                continue
        if args.prefix is not None:
            if not (withinPrefix(session[7], prefixList) or withinPrefix(session[9], prefixList)):
                continue
        if args.exclude_prefix is not None:
            if (withinPrefix(session[7], excludePrefixList) or withinPrefix(session[9], excludePrefixList)):
                continue
        # TODO: fix this so we don't double count
        svcDestinations.append(session[2])
        if args.graph:
            histValues.append(int(session[14]))
        if session[1] == 'fwd': 
            fwdSources.append(session[7])
            fwdDestinations.append(session[9])
            if session[6].upper() == "TCP":
                tcpServices.append(session[10])
            elif session[6].upper() == "UDP":
                udpServices.append(session[10])
        else:
            revSources.append(session[7])
            revDestinations.append(session[9])
            if session[6].upper() == "TCP":
                tcpServices.append(session[8])
            elif session[6].upper() == "UDP":
                udpServices.append(session[8])
    logger.info("Svc: " + str(len(svcDestinations)))

    cs = Counter(svcDestinations)
    cf = Counter(fwdDestinations)
    cfs = Counter(fwdSources)
    crs = Counter(revSources)
    cr = Counter(revDestinations)
    ct = Counter(tcpServices)
    cu = Counter(udpServices)

    if args.graph:
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

    for x in range (0,args.top):
        unified = []
        haveMore = True
        if len(cs.most_common(args.top)) < (x + 1):
            unified = unified + [None, None]
            haveMore = False
        else:
            unified = unified + list(cs.most_common(args.top)[x])
            haveMore = True
        if len(cfs.most_common(args.top)) < (x + 1):
            unified = unified + [None, None]
        else:
            unified = unified + list (cfs.most_common(args.top)[x])
            haveMore = True
        if len(cf.most_common(args.top)) < (x + 1):
            unified = unified + [None, None]
        else:
            unified = unified + list(cf.most_common(args.top)[x])
            haveMore = True
        if len(crs.most_common(args.top)) < (x + 1):
            unified = unified + [None, None]
        else:
            unified = unified + list(crs.most_common(args.top)[x])
            haveMore = True
        if len(cr.most_common(args.top)) < (x + 1):
            unified = unified + [None, None]
        else:
            unified = unified + list(cr.most_common(args.top)[x])
            haveMore = True
        if len(ct.most_common(args.top)) < (x + 1):
            unified = unified + [None, None]
        else:
            unified = unified + list(ct.most_common(args.top)[x])
            haveMore = True
        if len(cu.most_common(args.top)) < (x + 1):
            unified = unified + [None, None]
        else:
            unified = unified + list(cu.most_common(args.top)[x])
        if (not haveMore):
            break
        output.append(unified)
    tblHeadings = ['Service Name', 'Count', 
                   'Fwd Src', 'Count', 'Fwd Dest', 'Count', 
                   'Rev Src', 'Count', 'Rev Dest', 'Count', 
                   'TCP Port', 'Count', 'UDP Port', 'Count']
    print(tabulate(output, tblHeadings, tablefmt="rst"))
    if args.output is not None:
        with open(args.output, 'w') as file:
            for ses in sessions:
                file.write(convertToString(ses))

if __name__ == '__main__':
    main(sys.argv[1:])
