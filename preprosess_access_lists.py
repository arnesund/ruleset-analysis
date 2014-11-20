#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Preprosess Cisco firewall config to extract access-list rules
#
import os
import re
import sys
import shelve
import logging
import optparse
from IPy import IP
from datetime import datetime
from ciscoconfparse import CiscoConfParse
from firewallrule import FirewallRule

CONFIGFILE = 'config.py'

# Load config file
try:
    config = {}
    execfile(CONFIGFILE, config)
except:
    sys.stderr.write('Unable to load config file ({0})! Aborting.\n'.format(CONFIGFILE))
    sys.exit(1)


def parse_port_spec_to_list(parts, protocol, name2num):
    '''
    Parse port specifications to list of single port numbers.

    Args:
        parts: List of Strings specifying the port range, for example ['eq', '80']
        protocol: String with name of protocol for port specification
        name2num: Dictionary for translation of port names to numbers.

    Returns:
        List of port numbers as Integers. Empty list if an error occurred.
    '''

    ports = []

    # Validate input
    if len(parts) < 2:
        # Return empty list
        return ports
    if protocol not in name2num:
        # Create empty list matching the protocol name to avoid failures below
        name2num[protocol] = {}

    # Parse spec based on prefix
    if parts[0] in ['eq', 'neq']: 
        if parts[0] == 'eq':
            if parts[1] in name2num[protocol]:
                ports.append(name2num[protocol][parts[1]])
            else:
                ports.append(int(parts[1]))
        elif parts[0] == 'neq':
            ports = range(0, 65536)
            if parts[1] in name2num[protocol]:
                ports.remove(name2num[protocol][parts[1]])
            else:
                ports.remove(int(parts[1]))

    elif parts[0] in ['range', 'gt', 'lt']:
        if parts[0] == 'range':
            if parts[1] in name2num[protocol]:
                start = name2num[protocol][parts[1]]
            else:
                start = int(parts[1])
            if parts[2] in name2num[protocol]:
                end = name2num[protocol][parts[2]]
            else:
                end = int(parts[2])
        elif parts[0] == 'gt':
            end = 65535
            if parts[1] in name2num[protocol]:
                start = name2num[protocol][parts[1]]
            else:
                start = int(parts[1])
        elif parts[0] == 'lt':
            start = 0
            if parts[1] in name2num[protocol]:
                end = name2num[protocol][parts[1]]
            else:
                end = int(parts[1])

        # Expand range to list of port numbers
        ports = range(start, end+1)

    return ports


def parse_cisco_fw_access_list_entry(line, name2num, icmptype2num, networkgroups, servicegroups, verbose):
    '''
    Parse an access list line in Cisco Firewall syntax (ASA, FWSM) and return FirewallRule objects representing the rule.

    Args:
        line: Access list line as a String.
        name2num: Dictionary for translation of port names to numbers.
        icmptype2num: Dictionary for translation of ICMP type names to numbers.
        networkgroups: Dictionary used to expand object group names to actual network objects (IP addresses/networks)
        servicegroups: Dictionary used to expand object group names to actual port numbers
        verbose: Debug level as integer, where zero is no debugging, 1 is some debugging and >1 is all.

    Returns:
        List of FirewallRule objects (one or more).

    Throws:
        ValueError if unable to parse input.
    '''

    # Validate input
    if not isinstance(line, basestring):
        raise ValueError('Input must be an access list line as a string')

    # Preprocess input
    line = line.strip()

    # Regex for Cisco firewall ACL syntax
    RE_ACL = re.compile(r'access-list ([A-Za-z0-9_-]+) extended (permit|deny) ([a-zA-Z0-9]+) (.+)')

    # Temporary lists of port objects to parse
    sourceports = []
    destinationports = []

    # Parse input line
    match = re.search(RE_ACL, line)
    if match:
        data = match.groups()
        # Validate number of elements
        if len(data) != 4:
            raise ValueError('Access-list line is malformed, unable to parse it: ' + line)

        # Get action and protocol
        action = data[1]
        protocol = data[2]
        allow = True if action == 'permit' else False

        # Split and parse source-dest-part
        parts = data[3].split()
        # Source part
        if parts[0] == 'any':
            src = [parts[0]]
            # Remove source part, leaving only unparsed parts
            parts = parts[1:]
        elif parts[0] == 'host':
            # Source is a single host, only keep IP address
            src = [parts[1]]
            # Remove source part, leaving only unparsed parts
            parts = parts[2:]
        elif parts[0] == 'object-group':
            src = networkgroups[parts[1]]
            # Remove source part, leaving only unparsed parts
            parts = parts[2:]
        else:
            # Save source as "address/mask"
            src = ['/'.join(parts[0:2])]
            # Remove source part, leaving only unparsed parts
            parts = parts[2:]


        # Source port: First check for object group, then for other port specifications
        if parts[0] == 'object-group':
            # Check if this is a service port group or just the destination part of the rule
            if protocol in servicegroups:
                if parts[1] in servicegroups[protocol]:
                    # Expand object group to port specifications
                    for item in servicegroups[protocol][parts[1]]:
                        sourceports.append(item.split())
        elif parts[0] in ['eq', 'neq', 'gt', 'lt']:
            sourceports.append(parts[0:2])
            parts = parts[2:]
        elif parts[0] == 'range':
            sourceports.append(parts[0:3])
            parts = parts[3:]
        elif protocol == 'icmp':
            if parts[0] in icmptype2num:
                sourceports.append(icmptype2num[parts[0]])
                parts = parts[1:]


        # Destination part
        if parts[0] == 'any':
            dst = [parts[0]]
            # Remove destination part, leaving only unparsed parts
            parts = parts[1:]
        elif parts[0] == 'host':
            # Destination is a single host, only keep IP address
            dst = [parts[1]]
            # Remove destination part, leaving only unparsed parts
            parts = parts[2:]
        elif parts[0] == 'object-group':
            dst = networkgroups[parts[1]]
            # Remove destination part, leaving only unparsed parts
            parts = parts[2:]
        else:
            # Save destination as "address/mask"
            dst = ['/'.join(parts[0:2])]
            # Remove destination part, leaving only unparsed parts
            parts = parts[2:]


        # Check for optional destination port specification
        if len(parts) > 1:
            # First check for object group, then for other port specifications
            if parts[0] == 'object-group':
                # Check if this is a service port group or just the destination part of the rule
                if protocol in servicegroups:
                    if parts[1] in servicegroups[protocol]:
                        # Expand object group to port specifications
                        for item in servicegroups[protocol][parts[1]]:
                            destinationports.append(item.split())
                parts = parts[2:]
            elif parts[0] in ['eq', 'neq', 'gt', 'lt']:
                destinationports.append(parts[0:2])
                parts = parts[2:]
            elif parts[0] == 'range':
                destinationports.append(parts[0:3])
                parts = parts[3:]
        elif protocol == 'icmp' and len(parts) == 1:
            if parts[0] in icmptype2num:
                destinationports.append(icmptype2num[parts[0]])
                parts = parts[1:]
        

        # Expand port specifications to port lists
        if protocol != 'icmp':
            sport = []
            dport = []
            for portspec in sourceports:
                res = parse_port_spec_to_list(portspec, protocol, name2num)
                for item in res:
                    sport.append(item)
            for portspec in destinationports:
                res = parse_port_spec_to_list(portspec, protocol, name2num)
                for item in res:
                    dport.append(item)
        else:
            # No need to expand port specifications for ICMP rules
            sport = sourceports
            dport = destinationports

        if verbose > 1:
            logging.debug('PARSED LINE: ' + line)
            logging.debug('proto : ' + str(protocol))
            logging.debug('source: ' + str(src))
            logging.debug('sports: ' + str(sport))
            logging.debug('dest  : ' + str(dst))
            logging.debug('dports: ' + str(dport))
            if len(parts) > 0:
                logging.debug('REST: ' + str(parts))
            logging.debug('')

        # Create FirewallRule objects and return results
        res = []
        try:
            if dport:
                for dp in dport:
                    for dest in dst:
                        if sport:
                            for sp in sport:
                                for source in src:
                                    res.append(FirewallRule(allow, protocol, line, source, dest, sp, dp))
                        else:
                            for source in src:
                                res.append(FirewallRule(allow, protocol, line, source, dest, sport, dp))
            else:
                for dest in dst:
                    if sport:
                        for sp in sport:
                            for source in src:
                                res.append(FirewallRule(allow, protocol, line, source, dest, sp, dport))
                    else:
                        for source in src:
                            res.append(FirewallRule(allow, protocol, line, source, dest, sport, dport))
        except ValueError as e:
            # Log error and abort processing
            logging.error('Unable to convert line to FirewallRule object. Reason: {0}'.format(e))
            logging.error('The line is: {0}'.format(line))
            sys.exit(1)

        # Return results
        return res


    elif line.find('remark') != -1:
        # Comments are handled outside this function
        return False
    else:
        raise ValueError('Unable to parse access-list entry: ' + line)


def main(configfile, verbose):
    # Initialize data structures
    networkgroups = {}
    servicegroups = {}
    hostname = ''

    # Open config files and pre-initialized data structures
    shelvefile = config['NAME_NUMBER_MAPPING']
    try:
        # Name-number mappings
        db = shelve.open(shelvefile)
        name2num = db['cisco_port_name_to_number']
        num2name = db['cisco_port_number_to_name']
        icmptype2num = db['icmp_type_name_to_number']
        db.close()
    except KeyError as e:
        logging.error('Unable to find database entry {0} in shelve file {1}'.format(e, shelvefile))
        sys.exit(1)

    # Check that path to accesslist database exists, try to create it if not
    shelvefile = config['ACCESSLIST_DATABASE']
    if not os.path.isfile(shelvefile):
        if not os.path.dirname(shelvefile) == '' and not os.path.isdir(os.path.dirname(shelvefile)):
            try:
                os.makedirs(os.path.dirname(shelvefile))
            except OSError as e:
                logging.error('Path to accesslist DB file "{0}" does not exists, '.format(shelvefile) + \
                    'and I\'m unable to create it. Aborting.')
                sys.exit(1)
    try:
        db = shelve.open(shelvefile)
    except:
        logging.error('Unable to open or create access-list database "{0}"'.format(shelvefile))
        sys.exit(1)

    try:
        # Firewall metadata
        if 'firewalls' in db:
            firewalls = db['firewalls']
        else:
            firewalls = {}
        db.close()
    except KeyError as e:
        logging.error('Unable to find database entry {0} in shelve file {1}'.format(e, shelvefile))
        sys.exit(1)

    # Get config file name and try to initialize CiscoConfParse object
    try:
        conf = CiscoConfParse(configfile)
    except Exception, e:
        logging.error('Unable to initialize CiscoConfParse object. Reason: {0}'.format(e))
        sys.exit(1)

    # Get timestamp as last modification time of config file
    try:
        statinfo = os.stat(configfile)
        timestamp = statinfo.st_mtime
    except Exception as e:
        logging.exception('Unable to get file modification time of config file. Reason: {0}'.format(e))
        sys.exit(1)

    # Parse config file
    for line in open(configfile):
        # Extract object group names
        if line[:12] == 'object-group':
            parts = line.split()
            if len(parts) < 3:
                continue
            if parts[1] == 'network':
                # Save object group name
                networkgroups[parts[2]] = []
            elif parts[1] == 'service':
                # Save protocol first
                if parts[3] not in servicegroups:
                    servicegroups[parts[3]] = {}
                # Save object group name
                servicegroups[parts[3]][parts[2]] = []
        elif line[:8] == 'hostname':
            # Get hostname
            hostname = line[9:].strip()
        elif line[:12] == 'access-group':
            # Save info about which access-list is in use on which interface
            parts = line.split()
            if hostname != '':
                if hostname not in firewalls:
                    firewalls[hostname] = {}
                if parts[4] not in firewalls[hostname]:
                    firewalls[hostname][parts[4]] = {}
                # Format: firewalls[<hostname>][<interface>][<direction>] = <access-list name>
                firewalls[hostname][parts[4]][parts[2]] = parts[1]
            else:
                logging.warning('Hostname unknown when parsing access-group line, unable to parse line. This may result in incomplete info about which access-list is used on which interface.')

    if hostname == '':
        logging.error('Config file does not contain hostname of firewall')
        sys.exit(1)

    # For each object group, find all member objects
    for grp in networkgroups:
        lines = conf.find_all_children('^object-group network ' + grp + '$')
        for line in lines:
            line = line.strip()
            if line.find('network-object') != -1:
                address = line[15:]
                if address[:4] == 'host':
                    networkgroups[grp].append(address[5:])
                else:
                    networkgroups[grp].append(address.replace(' ', '/'))

    for protocol in servicegroups:
        for grp in servicegroups[protocol]:
            lines = conf.find_all_children('^object-group service ' + grp + ' ' + protocol + '$')
            for line in lines:
                line = line.strip()
                if line.find('port-object') != -1:
                    if protocol not in servicegroups:
                        servicegroups[protocol] = {}
                    # Convert port names to numbers
                    obj = line[12:]
                    if protocol == 'tcp-udp':
                        for p in ['tcp', 'udp']:
                            for portname in name2num[p]:
                                if obj.find(portname) != -1:
                                    obj = obj.replace(portname, str(name2num[p][portname]))
                    else:
                        for portname in name2num[protocol]:
                            if obj.find(portname) != -1:
                                obj = obj.replace(portname, str(name2num[protocol][portname]))
                    # Add object to object group
                    servicegroups[protocol][grp].append(obj)


    # Print contents of group dictionaries
    if verbose > 1:
        logging.debug('NETWORK')
        for grp in networkgroups:
            logging.debug(' ' + grp)
            for item in networkgroups[grp]:
                logging.debug('  ' + item)
        logging.debug('SERVICE')
        for proto in servicegroups:
            for grp in servicegroups[proto]:
                logging.debug(' ' + grp + ' (' + proto + ')')
                for item in servicegroups[proto][grp]:
                    logging.debug('  ' + item)


    # Initialize intermediate storage variables
    accesslists = {}
    comments = []
    comments_used = False
    linecount = {}
    proto2rule = {'ip': []}

    # Parse config file to extract all access-lists
    for line in open(configfile):
        if line[:12] == 'access-list ':
            parts = line.split()
            # If access-list name is unknown, add it to dict
            acl = parts[1]
            if acl not in accesslists:
                accesslists[acl] = []
            # Initialize line counter for this access-list, if necessary
            if acl not in linecount:
                linecount[acl] = 0
            # Check for comment and save it for later reference
            if parts[2] == 'remark':
                if comments_used:
                    # Reset list of comments
                    comments = [line.strip()]
                    comments_used = False
                else:
                    comments.append(line.strip())
            # Count line
            linecount[acl] += 1

            # Add FirewallRule objects to access-list structure
            try:
                rules = parse_cisco_fw_access_list_entry(line, name2num, icmptype2num, networkgroups, servicegroups, verbose)
            except ValueError as e:
                logging.error('Unable to parse one of the lines in the config, aborting.')
                logging.error('The line is: {0}'.format(line.strip()))
                sys.exit(1)

            if rules:
                for rule in rules:
                    # Add extra info to rule object
                    rule.comments = comments
                    rule.rulenum = linecount[acl]
                    # Save object to list
                    accesslists[acl].append(rule)
                    # Get index of expanded rule and add it to saved rule object
                    ruleindex = accesslists[acl].index(rule)
                    accesslists[acl][ruleindex].ruleindex = ruleindex
                    # Append rule to lists of rules for this protocol
                    if acl not in proto2rule:
                        proto2rule[acl] = {}
                    if rule.protocol not in proto2rule[acl]:
                        proto2rule[acl][rule.protocol] = [ruleindex]
                    else:
                        proto2rule[acl][rule.protocol].append(ruleindex)
                comments_used = True
            
    if verbose > 1:
        for acl in accesslists:
            logging.debug(acl)
            for rule in accesslists[acl]:
                logging.debug(rule.comments)
                logging.debug(rule)
            for proto in proto2rule[acl]:
                logging.debug('access-list {0}, protocol {1}, rulelist: {2}'.format(acl, proto, proto2rule[acl][proto]))
            logging.debug(' ')


    # Check for rules which never get hits
    if o.verbose > 0:
        for acl in accesslists:
            for rule in accesslists[acl]:
                index = accesslists[acl].index(rule)
                i = 0
                while (i < index):
                    if rule in accesslists[acl][i]:
                        logging.info('Found rule which never gets hits since it is covered by a more generic rule above it in access-list {0}.'.format(acl))
                        logging.info('Specific rule ' + str(index) + ': ' + str(rule))
                        logging.info('Generic rule ' + str(i) + ': ' + str(accesslists[acl][i]))
                        # Do not look for more hits, the first hit is sufficient
                        break
                    i += 1


    # Open output database
    shelvefile = config['ACCESSLIST_DATABASE']
    try:
        db = shelve.open(shelvefile)
        if 'accesslists' in db:
            acldb = db['accesslists']
        else:
            acldb = {}
        # Save firewall metadata
        db['firewalls'] = firewalls
    except KeyError as e:
        logging.error('Unable to find database entry {0} in shelve file {1}'.format(e, shelvefile))
        sys.exit(1)

    # Save each access-list to output database
    if hostname not in acldb:
        acldb[hostname] = {}
    for acl in accesslists:
        if acl not in acldb[hostname]:
            acldb[hostname][acl] = {}
        acldb[hostname][acl]['rules'] = accesslists[acl]
        acldb[hostname][acl]['timestamp'] = timestamp
        acldb[hostname][acl]['protocols'] = proto2rule[acl]

    # Close output database
    db['accesslists'] = acldb
    db.close()

    # Return dict for easier testing and debugging in ipython
    return accesslists


if __name__ == '__main__':
    prog = os.path.basename(sys.argv[0])
    usage = """%prog [-h] [-v] [-v] -f <firewall config file>"""
    description = """%prog processes a Cisco firewall config file to extract access-lists, object groups and other relevant info used by the RulesetAnalysis Hadoop jobs."""
    epilog = "2013 - Arne Sund"
    version = "%prog 1.0"

    p = optparse.OptionParser(usage=usage, version=version, description=description, epilog=epilog)
    p.add_option('-v', "--verbose", dest='verbose', action='count', default=0, help='turn on verbose output, apply twice for debug')
    p.add_option('-f', help="Cisco firewall config file", metavar="FILE")
    o, args = p.parse_args()

    # Determine log level from verbose flag
    if o.verbose > 1:
        # Debug logging
        logging.BASIC_FORMAT = "%(levelname)s - %(funcName)s:%(lineno)d - %(message)s"
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.BASIC_FORMAT = "%(levelname)s - %(message)s"
        if o.verbose:
            logging.basicConfig(level=logging.INFO)
        else:
            logging.basicConfig(level=logging.WARNING)

    # File argument is mandatory
    if not o.f:
        p.print_usage()
        sys.exit(1)

    accesslists = main(o.f, o.verbose)

