#!/usr/bin/python

import os
import sys
from subprocess import *
from smb import *
from smb.SMBConnection import SMBConnection
import argparse
import datetime
from datetime import datetime
import logging
from persistence import Database
from persistence import DatabaseSMBSR
from ldaphelper import LDAPHelper
import random
import string
import re
import ipaddress
import masscan
from threading import Lock
from worker import rsmbiworker


def listShares(serverName, options):
    connection = SMBConnection(options.username, options.password, options.fake_hostname,
                               'netbios-server-name', options.domain, use_ntlm_v2=True, is_direct_tcp=True)
    try:
        connection.connect(serverName, 445)
    except Exception as e:
        logger.error("Error connecting to: " + serverName +
                     ", with exception: " + str(e))
    try:
        shares = connection.listShares()
    except Exception as e:
        logger.error("Error while listing shares from: " +
                     serverName + ", with exception: " + str(e))
    connection.close()
    return shares


def setUpLogging(options):
    # cleaning the handlers
    logging.getLogger().handlers = []
    logger.handlers = []

    logger.setLevel(logging.INFO)
    # creating log file handler
    handler = logging.FileHandler(options.logfile)
    handler.setLevel(logging.INFO)
    # creating stdout handler

    stdoutHandler = logging.StreamHandler(sys.stdout)
    stdoutHandler.setLevel(logging.INFO)

    # creating a common formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    # setting the formatter for each handler
    handler.setFormatter(formatter)
    stdoutHandler.setFormatter(formatter)
    # add handlers to logger
    logger.addHandler(handler)
    logger.addHandler(stdoutHandler)


def setUpLoggingDebug(options):

    # cleaning the handlers
    logging.getLogger().handlers = []
    logger.handlers = []

    logger.setLevel(logging.DEBUG)
    # creating log file handler
    handler = logging.FileHandler(options.logfile)
    handler.setLevel(logging.DEBUG)
    # creating stdout handler

    stdoutHandler = logging.StreamHandler(sys.stdout)
    stdoutHandler.setLevel(logging.DEBUG)

    # creating a common formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    # setting the formatter for each handler
    handler.setFormatter(formatter)
    stdoutHandler.setFormatter(formatter)
    # add handlers to logger
    logger.addHandler(handler)
    logger.addHandler(stdoutHandler)


def setupPersistence(options):
    dbs = {}
    if (options.mode.upper() == "SMBSR"):
        if (options.dbfile == './rsmbi.db'):
            options.dbfile = './smbsr.db'
        dbs["SMBSR"] = DatabaseSMBSR(options.dbfile)
        if not os.path.exists(options.dbfile):

            logger.info("Database not found, creating [SMBSR]")
            dbs["SMBSR"].create_database()
            logger.info("Database created successfully [SMBSR]")
            dbs["SMBSR"].connect_database()
        else:
            logger.info("Database already existing [SMBSR]")
            dbs["SMBSR"].connect_database()
    elif (options.mode.upper() == "RSMBI"):
        dbs["RSMBI"] = Database(options.dbfile)
        if not os.path.exists(options.dbfile):

            logger.info("Database not found, creating")
            dbs["RSMBI"].create_database()
            logger.info("Database created successfully")
            dbs["RSMBI"].connect_database()
        else:
            logger.info("Database already existing")
            dbs["RSMBI"].connect_database()
    else:
        dbs["SMBSR"] = DatabaseSMBSR("./smbsr.db")
        if not os.path.exists("./smbsr.db"):

            logger.info("Database not found, creating [SMBSR]")
            dbs["SMBSR"].create_database()
            logger.info("Database created successfully [SMBSR]")
            dbs["SMBSR"].connect_database()
        else:
            logger.info("Database already existing [SMBSR]")
            dbs["SMBSR"].connect_database()

        dbs["RSMBI"] = Database("./rsmbi.db")
        if not os.path.exists("./rsmbi.db"):

            logger.info("Database not found, creating")
            dbs["RSMBI"].create_database()
            logger.info("Database created successfully")
            dbs["RSMBI"].connect_database()
        else:
            logger.info("Database already existing")
            dbs["RSMBI"].connect_database()

    return dbs


def retrieveComputerObjects(options):
    ldaphelperQ = LDAPHelper(options)
    ldap_targets = ldaphelperQ.retrieveComputerObjectsNTLM()
    return ldap_targets


def massScan(toscan):
    mass = masscan.PortScanner()
    final = []
    try:
        mass.scan(','.join(toscan), ports=445, arguments='--rate 1000')
    except Exception as e:
        logger.error("masscan failed with error: " + str(e))
        sys.exit(1)
    for key in mass.scan_result['scan']:
        if mass.scan_result['scan'][key]['tcp'][445]['state'] == 'open':
            final.append(key)

    return final


def setupTagRun(tag):
    if tag == "NOLABEL":
        now = datetime.now()
        date = now.strftime("%d-%m-%Y")
        return "RUN-" + date + "-" + \
            ''.join((random.choice(string.ascii_lowercase) for x in range(8)))
    return tag


def extractCIDR(tempTarget):
    cidr = []
    for target in tempTarget:

        ipcheck = re.match(
            "^([0-9]{1,3}\.){3}[0-9]{1,3}(\/([0-9]{1,2}))$", target)
        if ipcheck:
            cidr.append(target)
    return cidr


def fromCIDRtoIPs(toexpand):

    iplist = [str(ip) for ip in ipaddress.IPv4Network(toexpand)]
    return iplist


def addUncPaths(targetDict, options):

    try:
        with open(options.uncpaths) as f:
            uncpaths = [line.rstrip() for line in f]
            f.close()
    except Exception as e:
        logger.error("Error while reading the uncpaths file: " + str(e))

    for uncpath in uncpaths:
        server = uncpath.split('/')[2]
        path = '/'.join(uncpath.split('/')[3:])
        if server not in targetDict.keys():
            targetDict[server] = []
            targetDict[server].append(path)
        else:
            targetDict[server].append(path)

    return targetDict


def parseTargets(options):
    final = []
    # reading target from file if set
    if options.target_list != "unset":
        try:
            with open(options.target_list) as f:
                targetsraw = [line.rstrip() for line in f]
            f.close()
        except Exception as e:
            logger.error("Error while reading the target list file: " + str(e))
        # extracting CIDRs from the list, if any
        cidrs = extractCIDR(targetsraw)

        # cleaning the targetsraw list from the CIDRs found
        for cidr in cidrs:
            final = final + fromCIDRtoIPs(cidr)
            if cidr in targetsraw:
                targetsraw.remove(cidr)

        final = final + targetsraw

    # retrieving targets from ldap if required
    if (options.ldap):
        computerObjects = retrieveComputerObjects(options)
        final = final + computerObjects
    # take target from single IP
    if (options.target):
        if len(extractCIDR(options.target)) > 0:
            # here the function to extract ip list from CIDR
            final = final + fromCIDRtoIPs([options.target])
        else:
            final.append(options.target)
    # filtering the targets basing on masscan output
    if (options.masscan):
        final = massScan(final)

    if len(final) == 0 and options.uncpaths == "UNSET":
        logger.info("List of targets is empty, exiting ...")
        sys.exit(1)

    return final


def unleashThreads(options, scope, db, targetDict, lock, targetIPs, wordListDict):

    threads = []
    # workername, options, targetdict, db, lock, scope, targets

    logger.info("Starting with threads")
    for thread in range(options.T):
        try:
            worker = rsmbiworker("Worker-" + str(thread+1),
                                 options, targetDict, db, lock, scope, targetIPs, wordListDict)
            worker.start()
            threads.append(worker)
        except Exception as e:
            logger.error("Error while multithreading: " + str(e))
            sys.exit(1)
    for thread in threads:
        thread.join()


def readMatches(options):

    filepath = options.wordlist
    file_regular = options.regular_exp
    lines = []
    if filepath != 'unset':
        try:
            with open(filepath) as f:
                lines = [line.rstrip() for line in f]
            f.close()
            # return lines
        except Exception as e:
            logger.error("Exception while reading the file " + str(e))
            sys.exit(1)

    rlines = []
    if file_regular != 'unset':

        try:
            with open(file_regular) as r:
                rlines = [line.rstrip() for line in r]
            r.close()
        except Exception as e:
            logger.error(
                "Exception while reading the regular expression file " + str(e))

    to_match_dict = {

        "words": lines,
        "regex": rlines
    }
    return to_match_dict


# getting global logger for rSMBI
logger = logging.getLogger('rSMBi')

if __name__ == '__main__':

    if not os.geteuid() == 0:
        sys.exit("\nOnly root can run this script\n")
    parser = argparse.ArgumentParser(
        add_help=True, description="SMB @udit Tool")
    parser.add_argument('-username', action='store', default='anonymous',
                        type=str, help='Username for authenticated scan')
    parser.add_argument('-password', action='store', default='s3cret',
                        type=str, help='Password for authenticated scan')
    parser.add_argument('-domain', action='store',
                        default='SECRET.LOCAL', help='Domain for authenticated scan, please use FQDN')
    parser.add_argument('-fake-hostname', action='store', default='localhost',
                        help='Computer hostname SMB connection will be from')
    parser.add_argument('-multithread', action='store_true',
                        default=False, help="Assign a thread to any share to check")
    parser.add_argument('-logfile', action='store',
                        default='rsmbi.log', type=str, help='Log file path')
    parser.add_argument('-dbfile', action='store',
                        default='./rsmbi.db', type=str, help='DB file path')
    parser.add_argument('-share-black', action='store', type=str, default='none',
                        help='Blacklist of shares')
    parser.add_argument('-local-path', action='store', type=str, default='/tmp',
                        help='Path to folder where to mount the shares, default set to /tmp')
    parser.add_argument('-debug', action='store_true', default=False,
                        help='Verbose logging debug mode on')
    # might be needed to change this
    parser.add_argument('-target', action="store",
                        help='IP address, CIDR or hostname')
    parser.add_argument('-target-list', action="store", default='unset',
                        help='Path to file containing a list of targets')
    parser.add_argument('-tag', action='store',
                        default="NOLABEL", type=str, help='Label the run')
    parser.add_argument('-ldap', action='store_true', default=False,
                        help='Query LDAP to retrieve the list of computer objects in a given domain')
    parser.add_argument('-dc-ip', action='store',
                        help='DC IP of the domain you want to retrieve computer objects from')
    parser.add_argument('-T', action='store', default=10,
                        type=int, help="Define the number of thread to use, default set to 10")
    parser.add_argument('-masscan', action='store_true', default=False,
                        help="Scan for 445 before trying to analyze the target")
    parser.add_argument('-smbcreds', action='store',
                        type=str, help='Path to the file containing the SMB credential')
    parser.add_argument('-uncpaths', action='store', default="UNSET",
                        type=str, help='Path to the file containing the list of UNCPATHS you want to scan')
    parser.add_argument('-csv', action='store_true', default=False,
                        help='Export results to CSV files in the project folder')
    parser.add_argument('-mode', action='store',
                        default='both', help="Choose between SMBSR,RSMBI and Both")
    parser.add_argument('-regulars', action="store", default='unset',
                        type=str, help="File containing regex expression to match [SMBSR]")
    parser.add_argument('-wordlist', action="store", default='unset',
                        type=str, help="File containing the string to look for [SMBSR]")
    parser.add_argument('-hits', action='store', default=5000,
                        type=int, help='Max findings per file [SMBSR]')
    parser.add_argument('-file-interesting', action='store', default='none', type=str,
                        help='Comma separated file extensions you want to be notified about [SMBSR]')
    parser.add_argument('-max-size', action="store", default=50000, type=int,
                        help="Maximum size of the file to be considered for scanning (bytes) [SMBSR]")
    parser.add_argument('-file-extensions-black', action='store', type=str, default='none',
                        help='Comma separated file extensions to skip while secrets harvesting [SMBSR]')
    parser.add_argument('-regular-exp', action="store", default='unset',
                        type=str, help="File containing regex expression to match [SMBSR]")

    options = parser.parse_args()

    if options.debug:
        setUpLoggingDebug(options)
    else:
        setUpLogging(options)

    dbs = setupPersistence(options)
    options.tag = setupTagRun(options.tag)
    targetIPs = parseTargets(options)
    targetDict = {}
    lock = Lock()

    if options.mode.upper() == "SMBSR" or options.mode.upper() == "BOTH":
        wordlistDict = readMatches(options)
    else:
        wordlistDict = []

    if options.multithread is True:

        logger.info("I'm Speed")
        if len(targetIPs) > 0:
            unleashThreads(options, "Enum", None,
                           targetDict, lock, targetIPs, None)
        if options.uncpaths != "UNSET":
            logger.info("Adding UNCPATHS to the target dictionary")
            targetDict = addUncPaths(targetDict, options)

        unleashThreads(options, "Action", dbs, targetDict,
                       lock, None, wordlistDict)

    else:
        logger.info("Starting solo worker")
        options.T = 1
        if len(targetIPs) > 0:
            unleashThreads(options, "Enum", None,
                           targetDict, lock, targetIPs, None)
        if options.uncpaths != "UNSET":
            logger.info("Adding UNCPATHS to the target dictionary")
            targetDict = addUncPaths(targetDict, options)

        unleashThreads(options, "Action", dbs, targetDict,
                       lock, None, wordlistDict)

    if options.csv:
        if options.mode.upper() == "SMBSR":
            dbs["SMBSR"].exportToCSV(options.tag)
        elif options.mode.upper() == "RSMBI":
            dbs["RSMBI"].exportToCSV(options.tag)
        else:
            dbs["SMBSR"].exportToCSV(options.tag)
            dbs["RSMBI"].exportToCSV(options.tag)

    logger.info("SMB@ has finished, cheers")
