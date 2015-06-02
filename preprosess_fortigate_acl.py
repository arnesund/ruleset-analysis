#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Preprosess FortiGate firewall config to extract access-list rules
#
import os
import re
import sys
import shelve
import logging
import optparse
import socket
from IPy import IP
from pprint import pprint
from datetime import datetime
from firewallrule import FirewallRule

CONFIGFILE = 'config.py'


# Load config file
try:
    config = {}
    execfile(CONFIGFILE, config)
except:
    sys.stderr.write('Unable to load config file ({0})! Aborting.\n'.format(CONFIGFILE))
    sys.exit(1)


def expand_addr(entry, obj, verbose):
    if verbose > 1:
        print('Expanding address {}...'.format(entry))

    res = []
    for match in re.finditer(r'(\".*?\")', entry):
        name = match.groups()[0]
        if name in obj['addr']:
            if 'subnet' in obj['addr'][name]:
                res.append(obj['addr'][name]['subnet'])
            elif 'fqdn' in obj['addr'][name]:
                fqdn = obj['addr'][name]['fqdn'].replace('"', '')
                ip_lookup = None
                try:
                    ip_lookup = socket.gethostbyname_ex(fqdn)
                except:
                    sys.stderr.write('Unable to lookup {0}. Skipping it. \n'.format(fqdn))
                if ip_lookup:
                    res = res + ip_lookup[2]
                
            else:
                sys.stderr.write('Unable to expand address "{}" to a subnet. Skipping it.\n'.format(name))
        else:
            # Must be an address group, expand it recursively
            for member in re.finditer(r'(\".*?\")', obj['addrgrp'][name]['member']):
                res = res + expand_addr(member.groups()[0], obj, verbose)

    return res


def expand_service(entry, obj, verbose):
    if verbose > 1:
        print('Expanding service {}...'.format(entry))

    res = []

    if entry in obj['service']:
        o = obj['service'][entry]
        if o['protocol'] == 'TCP/UDP/SCTP':
            for key in ['tcp-portrange', 'udp-portrange']:
                if key in o:
                    # Valid syntax includes '53', '161-162' and '19100 19300 19400' for destination port only,
                    # and '15003:15002' + '514:512-1023' for dstport:srcport, respectively

                    protocol = key[:3]
                    data = {}
                    data['src'] = False
                    data['dst'] = False
                    data['srcobj'] = []
                    data['dstobj'] = []

                    if o[key].find(':') != -1:
                        # Both source and destination port
                        data['dst'], data['src'] = o[key].split(':')
                    else:
                        data['dst'] = o[key]
                    
                    for direction in ['src', 'dst']:
                        if data[direction]:
                            if data[direction].find('-') != -1:
                                # Port range
                                start, end = data[direction].split('-')

                                # Handle exception
                                if int(start) == 1 and int(end) == 65535:
                                    data[direction + 'obj'].append({'protocol': protocol, 'port': FirewallRule.NO_PORT, 'direction': direction})
                                else:
                                    for port in xrange(int(start), int(end)+1):
                                        if verbose > 1:
                                            print('Found {} {} port {} for entry {}'.format(protocol, direction, port, entry))
                                        data[direction + 'obj'].append({'protocol': protocol, 'port': port, 'direction': direction})

                            elif data[direction].find(' ') != -1:
                                # List of ports, space-delimited
                                for port in data[direction].split(' '):
                                    if verbose > 1:
                                        print('Found {} {} port {} for entry {}'.format(protocol, direction, port, entry))
                                    data[direction + 'obj'].append({'protocol': protocol, 'port': port, 'direction': direction})

                            else:
                                # Single port
                                if verbose > 1:
                                    print('Found {} {} port {} for entry {}'.format(protocol, direction, data[direction], entry))
                                data[direction + 'obj'].append({'protocol': protocol, 'port': data[direction], 'direction': direction})

                    if data['src']:
                        for src in data['srcobj']:
                            for dst in data['dstobj']:
                                res.append({'protocol': dst['protocol'], 'srcport': src['port'], 'dstport': dst['port']})

                    else:
                        for dst in data['dstobj']:
                            res.append({'protocol': dst['protocol'], 'srcport': FirewallRule.NO_PORT, 'dstport': dst['port']})


        elif o['protocol'] == 'ICMP':
            res.append({'protocol': o['protocol'].lower()})

        elif o['protocol'] == 'IP':
            res.append({'protocol': o['protocol'].lower()})

        else:
            sys.stderr.write('Unknown protocol {} in service object {}, skipping it.\n'.format(o['protocol'], entry))

    elif entry in obj['srvcgrp']:
        # Expand service group recursively
        for member in obj['srvcgrp'][entry]['member'].split(' '):
            res = res + expand_service(member, obj, verbose)

    # Return list of services
    return res


def parse_fg_policy_entry(entry, obj, verbose):
    '''
    Parse a policy entry in FortiGate syntax and return FirewallRule objects representing the policy entry.

    Args:
        entry: Dictionary representing the policy entry as found in the config.
        obj: Dictionary with all address and service objects found in the config.
        verbose: Debug level as integer, where zero is no debugging, 1 is some debugging and >1 is all.

    Returns:
        List of FirewallRule objects (one or more).

    Throws:
        ValueError if unable to parse input.
    '''

    # List of FirewallRule objects to return
    res = []

    if verbose:
        print('parse_fg_policy_entry: Processing the following entry...')
        pprint(entry)

    data = {}
    data['srcaddr'] = []
    data['dstaddr'] = []
    for key in entry.keys():
        if key.find('addr') != -1:
            for match in re.finditer(r'(\".*?\")', entry[key]):
                data[key] = data[key] + expand_addr(match.groups()[0], obj, verbose)

    if 'service' in entry:
        data['service'] = []
        for part in entry['service'].split(' '):
            data['service'] = data['service'] + expand_service(part, obj, verbose)

    if verbose:
        print('Parsed fields:')
        pprint(data)
        print('')

    for src in data['srcaddr']:
        for dst in data['dstaddr']:
            for svc in data['service']:
                # Build comment and original access-list line
                p = entry
                original = 'access-list {}-in {} {} to {} service {}'.format(p['srcintf'].lower(), p['action'], p['srcaddr'], 
                                                             p['dstaddr'], p['service'])
                original = original.replace('"', '')
                original = original.replace('accept', 'permit')
                
                if p['comments'] != "''":
                    comment = 'access-list {}-in remark {}: {}'.format(p['srcintf'].lower(), p['global-label'], p['comments'])
                else:
                    comment = 'access-list {}-in remark {}'.format(p['srcintf'].lower(), p['global-label'])
                comment = comment.replace('"', '')

                if entry['action'] == 'accept':
                    permit = True
                else:
                    permit = False

                rule = None
                try:
                    if svc['protocol'] in ['tcp', 'udp']:
                        rule = FirewallRule(permit, svc['protocol'], original, src, dst, svc['srcport'], svc['dstport'], [comment], entry['policy_id'])
                    else:
                        rule = FirewallRule(permit, svc['protocol'], original, src, dst, FirewallRule.NO_PORT, FirewallRule.NO_PORT, [comment], entry['policy_id'])
                except ValueError, e:
                    raise
                
                if rule:
                    res.append(rule)

    return res


def main(configfile, verbose):
    # Initialize data structures
    networkgroups = {}
    servicegroups = {}

    # Open config files and pre-initialized data structures
    shelvefile = config['NAME_NUMBER_MAPPING']
    try:
        # Name-number mappings
        db = shelve.open(shelvefile)
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

        
    # Get timestamp as last modification time of config file
    try:
        statinfo = os.stat(configfile)
        timestamp = statinfo.st_mtime
    except Exception as e:
        logging.exception('Unable to get file modification time of config file. Reason: {0}'.format(e))
        sys.exit(1)
    
    # Object storage in memory
    obj = {}

    # Track current element ID
    elem = False

    # Track state
    section = False
    
    # Container for accesslists
    accesslists = {}
    # Container for mapping of protocol to rules
    proto2rule = {}

    # Configure interesting parts of each object
    titles = {}
    titles['policy'] = ['srcintf', 'dstintf', 'srcaddr', 'dstaddr', 'action', 'status', 'service', 'comments', 'global-label']
    titles['addr'] = ['type', 'comment', 'subnet', 'start-ip', 'end-ip', 'fqdn']
    titles['addrgrp'] = ['comment', 'member']
    titles['service'] = ['category', 'protocol', 'comment', 'protocol-number', 'tcp-portrange', 'udp-portrange', 'icmptype', 'icmpcode']
    titles['srvcgrp'] = ['comment', 'member']
    titles['router'] = ['hostname']

    # Parse config file to extract all accesslists, addresses and addressgroups
    for line in open(configfile, 'r').readlines():
        line = line.strip()

        # Track where in config file we are
        if line == 'config firewall policy':
            section = 'policy'
            obj[section] = {}
        elif line == 'config firewall address':
            section = 'addr'
            obj[section] = {}
        elif line == 'config firewall addrgrp':
            section = 'addrgrp'
            obj[section] = {}
        elif line == 'config firewall service custom':
            section = 'service'
            obj[section] = {}
        elif line == 'config firewall service group':
            section = 'srvcgrp'
            obj[section] = {}
        elif line == 'config router setting':
            section = 'router'
            obj[section] = {}

        # Detect end of config section
        if section and line == 'end':
            section = False

        # Skip all other parts of config
        if not section:
            # Skip line
            continue
        
        # Detect new objects and initialize storage
        if line[:4] == 'edit':
            match = re.search(r'edit (.*)', line)
            if match:
                elem = str(match.groups()[0])
                obj[section][elem] = {}
        
        if section == 'router' and line[:12] == 'set hostname':
            obj[section]['hostname'] = line.split()[2]
            contents = obj[section]['hostname']
            # Remove "" from hostname
            contents = contents.replace("'", '')
            contents = contents.replace('"', '')
            obj[section]['hostname'] = contents

        elif line == 'next':
            elem = False
        
        # Detect object contents
        elif line[:3] == 'set' and elem:
            for title in titles[section]:
                if line.split()[1] == title:
                    contents = ' '.join(line.split()[2:])
                    obj[section][elem][title] = contents
                    break

            # Convert space to slash in address objects
            if section == 'addr' and line.split()[1] == 'subnet':
                contents = obj[section][elem][title]
                contents = contents.replace(' ', '/')
                obj[section][elem][title] = contents

    
    # Postprocess policy entries to FirewallRule objects
    for policy_id in obj['policy'].keys():
        if obj['policy'][policy_id]['status'] == 'enable':
            acl = ""
            if obj['policy'][policy_id]['srcintf'] == '"Outside"':
                acl = "outside-in"
            elif obj['policy'][policy_id]['srcintf'] == '"Inside"' or obj['policy'][policy_id]['srcintf'] == '"Guest-Inside"':
                acl = "inside-in"
            if acl not in accesslists:
                accesslists[acl] = []
            obj['policy'][policy_id]['policy_id'] = policy_id
            accesslists[acl] = accesslists[acl] + parse_fg_policy_entry(obj['policy'][policy_id], obj, verbose)

    # Process accesslist rules to map protocol to rule IDs
    for acl in accesslists:
        for rule in accesslists[acl]:
            ruleindex = accesslists[acl].index(rule)
            accesslists[acl][ruleindex].ruleindex = ruleindex
            if acl not in proto2rule:
                proto2rule[acl] = {}
            if rule.protocol not in proto2rule[acl]:
                proto2rule[acl][rule.protocol] = [ruleindex]
            else:
                proto2rule[acl][rule.protocol].append(ruleindex)
                
    # Populate firewall metadata
    hostname = obj['router']['hostname']
    if hostname not in firewalls:
        firewalls[hostname] = {}
    for acl in accesslists:
        intf = '-'.join([hostname.split('-')[1], acl.split('-')[0]])
        firewalls[hostname][intf] = {'in': acl}


    # Debug print            
    if verbose > 1:        
        pprint(obj)    
        print(proto2rule)
        pprint(firewalls)
        for acl in accesslists:
            for rule in accesslists[acl]:
                print(rule.ruleindex, acl, str(rule))


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
    description = """%prog processes a FortiGate firewall config file to extract accesslists, address objects, service objects and other relevant info. Each policy is saved as a FirewallRule object in a shelve database."""
    epilog = "2015 - Arne Sund"
    version = "%prog 1.0"

    p = optparse.OptionParser(usage=usage, version=version, description=description, epilog=epilog)
    p.add_option('-v', "--verbose", dest='verbose', action='count', default=0, help='turn on verbose output, apply twice for debug')
    p.add_option('-f', help="FortiGate firewall config file", metavar="FILE")
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
