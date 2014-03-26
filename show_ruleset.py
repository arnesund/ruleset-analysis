#!/usr/bin/env python
# coding: utf-8
#
# Print firewall rule set with identifiers
#
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
usage = '%prog [-h|--help] [--version] [-f|--firewall FIREWALL] ([-r|--rule "FIREWALLRULE"])'
description = """Print firewall rule set with identifiers."""
epilog = 'Author: Arne Sund'
version = '%prog 1.0'

# Initialize command line parsing
p = optparse.OptionParser(usage=usage, version=version, description=description, epilog=epilog)
p.add_option('-f', "--firewall", dest='firewall', metavar="FIREWALL", help='Name of firewall')
p.add_option('-r', "--rule", dest='rule', metavar="FIREWALLRULE", help='(Optional) Specific firewall rule to look up.')
options, args = p.parse_args()

# Parse command line options
if not options.firewall:
    print('ERROR: Name of firewall not supplied.\n')
    p.print_help()
    sys.exit(1)
else:
    firewall = options.firewall

# Open rule database
shelvefile = config['ACCESSLIST_DATABASE']
try:
    acldb = shelve.open(shelvefile)
except:
    sys.stderr.write('Unable to open access-list database ("{0}"). '.format(shelvefile) + \
        'Did you remember to run preprocessor?\n')
    sys.exit(1)

try:
    accesslists = acldb['accesslists']
    firewalls = acldb['firewalls']
    acldb.close()
except KeyError as e:
    sys.stderr.write('Unable to load key {0} from access-list database. '.format(e) + \
        'Did you remember to run preprocessor?\n')
    sys.exit(1)
except TypeError as e:
    sys.stderr.write('Unable to load keys from access-list database. ' + \
        'Did you remember to run preprocessor?\n')
    sys.exit(1)


# Validate firewall name
if firewall not in accesslists:
    print('ERROR: Firewall {0} not in access-list database. Run preprocessing-script to add it.'.format(firewall))
    sys.exit(1)

if options.rule:
    # Find rule and print ruledef for that rule
    for acl in accesslists[firewall]:
        ruleindex = 0
        for rule in accesslists[firewall][acl]['rules']:
            if rule.original == options.rule:
                # Print only ruledef
                print('Ruledef: {0}'.format(';'.join([firewall, acl, str(ruleindex)])))
                # Stop processing after first match
                break
            ruleindex += 1
else:
    # Loop through all rules in each accesslist and print them
    for acl in accesslists[firewall]:
        print('Firewall {0}, access-list {1}'.format(firewall, acl))
        ruleindex = 0
        for rule in accesslists[firewall][acl]['rules']:
            print('{0:32} {1:60} {2}'.format(';'.join([firewall, acl, str(ruleindex)]), str(rule), rule.original))
            ruleindex += 1
        print('')
