#!/usr/bin/env python
# coding: utf-8
import sys
import shelve
import optparse
from IPy import IP

CONFIGFILE = 'config.py'

# Load config file
try:
    config = {}
    execfile(CONFIGFILE, config)
except:
    sys.stderr.write('Unable to load config file ({0})! Aborting.\n'.format(CONFIGFILE))
    sys.exit(1)

# Command line option parsing info
usage = '%prog [-a|--address IPv4-ADDRESS] [-f|--firewall FIREWALL] [-l|--list ACCESS-LIST] [-h|--help] [--version]'
description = """Find firewall rules which apply for a given host (IPv4 address)."""
epilog = 'Author: Arne Sund'
version = '%prog 1.0'

# Initialize command line parsing
p = optparse.OptionParser(usage=usage, version=version, description=description, epilog=epilog)
p.add_option('-a', "--address", dest='address', metavar="IPv4-ADDRESS", help='The address of the host')
p.add_option('-f', "--firewall", dest='firewall', metavar="FIREWALL", help='Name of firewall')
p.add_option('-d', "--direction", dest='direction', metavar="DIRECTION", help='Direction of traffic (out/in)')

# Parse command line options
options, args = p.parse_args()
if not options.address:
    print('ERROR: IP address not supplied.\n')
    p.print_help()
    sys.exit(1)
else:
    address = options.address

if not options.firewall:
    print('ERROR: Name of firewall not supplied.\n')
    p.print_help()
    sys.exit(1)
else:
    firewall = options.firewall

if not options.direction:
    print('ERROR: Direction (out/in) not supplied.\n')
    p.print_help()
    sys.exit(1)
else:
    direction = options.direction

# Open database of firewall rules
try:
    acldb = shelve.open(config['ACCESSLIST_DATABASE'])
except:
    sys.stderr.write('Unable to open access-list database ' + \
        '("{0}"). '.format(config['ACCESSLIST_DATABASE']) + \
        'Did you remember to run preprocessor?\n')
    sys.exit(1)

# Read from database and close file
try:
    accesslists = acldb['accesslists']
    firewalls = acldb['firewalls']
    acldb.close()
except KeyError as e:
    sys.stderr.write('Unable to load key {0} from access-list database. '.format(e) + \
        'Did you remember to run preprocessor?\n')
    sys.exit(1)

# Validate firewall name
if firewall not in accesslists:
    print('ERROR: Firewall {0} not in access-list database. Run preprocessing-script to add it.'.format(firewall))
    sys.exit(1)

# Parse direction to access-list name
if direction == 'in':
    acl = 'outside-in'
elif direction == 'out':
    acl = 'inside-in'
else:
    print('ERROR: Direction is something else than "in" or "out", please try again.')
    sys.exit(1)

# Validate access-list name
if acl not in accesslists[firewall]:
    print('ERROR: Access-list {0} not in access-list database for firewall {1}. Run preprocessing-script to add it.'.format(acl, firewall))
    sys.exit(1)

# Parse IP address
try:
    host = IP(address)
except Exception, e:
    print(e)
    sys.exit(1)

# List of rules affecting this host
ruleset = []

# Loop through all rules in accesslist
for rule in accesslists[firewall][acl]['rules']:
    if direction == 'out':
        # Check if host is within the source part of the rule
        if host in rule.src:
            # Add rule to list, if rule isn't there already
            if rule.original not in ruleset:
                ruleset.append(rule.original)
    else:
        # Check if host is within the destination part of the rule
        if host in rule.dst:
            # Add rule to list, if rule isn't there already
            if rule.original not in ruleset:
                ruleset.append(rule.original)

# Print results
print('Matching rules found (count: {0}):'.format(len(ruleset)))
for line in ruleset:
    print line

