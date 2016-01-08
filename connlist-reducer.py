#!/usr/bin/env python
#
# Parse firewall logs and present a short summary of TCP connections
#
import re
import sys
import shelve
import os.path
from firewallrule import FirewallRule

debug = False

CONFIGFILE = 'config.py'

# Load config file
try:
    config = {}
    execfile(CONFIGFILE, config)
except:
    sys.stderr.write('Unable to load config file ({0})! Aborting.\n'.format(CONFIGFILE))
    sys.exit(1)


# Regular expressions to match info in 'Built conn'-messages
regexBuiltConn = r'[a-zA-Z]+ [0-9 ]?[0-9] ([0-9:]+) ([a-zA-Z]+) ([0-9]+) ([0-9]+) .* Built (out|in)bound ([a-zA-Z]+) .* for [a-zA-Z0-9_-]+:([0-9.]+)/([0-9]+) .* to [a-zA-Z0-9_-]+:([0-9.]+)/([0-9]+)'
BUILT = re.compile(regexBuiltConn)

# Map month names to numbers
months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']


# Open database of firewall rules
try:
    acldb = shelve.open(os.path.basename(config['ACCESSLIST_DATABASE_FILENAME']))
except:
    sys.stderr.write('Unable to open access-list database ' + \
        '("{0}"). '.format(os.path.basename(config['ACCESSLIST_DATABASE_FILENAME'])) + \
        'Did you remember to run preprocessor? Aborting reducer.\n')
    sys.exit(1)

# Read from database and close file
try:
    accesslists = acldb['accesslists']
    firewalls = acldb['firewalls']
    acldb.close()
except KeyError as e:
    sys.stderr.write('Unable to load key {0} from access-list database. '.format(e) + \
        'Did you remember to run preprocessor? Aborting reducer.\n')
    sys.exit(1)


# List of connections and timestamps
conns = {}
connFirst = {}
connLast = {}

# Work variables
currentkey = ''
currentrule = ''
currenthits = 0

for line in sys.stdin:
    line = line.strip()

    # Split mapper output into parts
    try:
        # Key
        key, value = line.split('\t', 1)
        hostname, acl, ruleindex = key.split(';', 3)
        # Value
        logline = value
        rule = accesslists[hostname][acl]['rules'][int(ruleindex)]
        # Add some locally-significant values to rule object
        rule.hostname = hostname
        rule.accesslist = acl
    except ValueError as e:
        print('Unable to unpack mapper input line, skipping it.')
        print('The line was: {0}'.format(line))
        continue

    if debug:
        print('')
        print('STARTING WITH NEW LINE')
        print('Key: {0}'.format(key))
        print('Hostname: {0}, ACL: {1}, ruleindex: {2}'.format(hostname, acl, ruleindex))
        print('Rule: {0}'.format(str(rule)))
        print('Ruleinfo: {0}'.format(rule.__dict__))
        print('Logline: {0}'.format(logline))

    # Initialization
    if currentkey == '':
        currentkey = key
    if currentrule == '':
        currentrule = rule
     
    if debug:
        print('Currentkey (1): {0}'.format(currentkey))
        print('Currentrule (1): {0}'.format(str(currentrule)))

    if key != currentkey:
        # New key found, report results for previous key before continuing
        if debug:
            print('NEW KEY FOUND!')
            print('Conns (1): {0}'.format(conns))
            print('ConnFirst (1): {0}'.format(connFirst))
            print('ConnLast (1): {0}'.format(connLast))

        # Sort list of conns
        entries = conns.keys()
        entries.sort(key=lambda conn: ' '.join(conn.split(';')[2:4]))

        # Print header
        print('')
        print('{0}: access-list {1}, rule {2}: {3}'.format(currentrule.hostname, currentrule.accesslist, currentrule.ruleindex, str(currentrule)))
        print('{0}'.format(currentrule.original))
        print('Total number of hits: {0}'.format(str(currenthits)))
        if len(conns) >= config['MAX_NUMBER_OF_CONNECTIONS_PER_RULE']:
            print('NOTE: Maximum number of connections ({0}) reached for this rule, additional connections not displayed.'.format(config['MAX_NUMBER_OF_CONNECTIONS_PER_RULE']))
        print '%6s %4s  %-15s %-14s %-5s %-19s  %-19s' % ('COUNT', 'PROTO', \
            'FROM IP', 'TO IP', 'PORT', 'FIRST SEEN', 'LAST SEEN')

        # Print connection table
        for conn in entries:
            proto, fromIP, toIP, toport = conn.split(';')
            print '%6d %4s %15s  %15s %-5s %19s  %19s' % (conns[conn], proto, fromIP, \
                    toIP, toport, connFirst[conn], connLast[conn])

        # Re-initialize list of connections and timestamps
        conns = {}
        connFirst = {}
        connLast = {}
    
        # Update current pointers
        currentkey = key
        currentrule = rule
        currenthits = 0

        if debug:
            print('Currentkey (2): {0}'.format(currentkey))
            print('Currentrule (2): {0}'.format(str(currentrule)))
            print('Conns (2): {0}'.format(conns))
            print('ConnFirst (2): {0}'.format(connFirst))
            print('ConnLast (2): {0}'.format(connLast))

    # Look for Cisco-specific log message IDs
    if logline.find('-6-302013') != -1 or logline.find('-6-302015') != -1:
        # Update hit counter
        currenthits += 1

        # Only save connection to list if maximum number of connections has not been reached yet
        if len(conns) < config['MAX_NUMBER_OF_CONNECTIONS_PER_RULE']:
            match = re.search(BUILT, logline)
            if match:
                res = match.groups()

                if debug:
                    print('Conns (3): {0}'.format(conns))
                    print('ConnFirst (3): {0}'.format(connFirst))
                    print('ConnLast (3): {0}'.format(connLast))

                # Create a connection hash: PROTO;FROMIP;TOIP;TOPORT
                conn = ';'.join([res[5], res[6], res[8], res[9]])
                # Create a timestamp
                month = str(months.index(res[1])+1).zfill(2)
                timestamp = res[3] + '-' + month + '-' + res[2].zfill(2) + ' ' + res[0]

                if conn in conns.keys():
                    conns[conn] = conns[conn] + 1
                    if timestamp < connFirst[conn]:
                        connFirst[conn] = timestamp
                    if timestamp > connLast[conn]:
                        connLast[conn] = timestamp
                else:
                    conns[conn] = 1
                    connFirst[conn] = timestamp
                    connLast[conn] = timestamp

                if debug:
                    print('Conns (4): {0}'.format(conns))
                    print('ConnFirst (4): {0}'.format(connFirst))
                    print('ConnLast (4): {0}'.format(connLast))


# Print newline to ensure at least one line of output from reducer
print('')

# Output last summary
if currentrule != '':
    # Sort list of conns
    entries = conns.keys()
    entries.sort(key=lambda conn: ' '.join(conn.split(';')[2:4]))

    # Print header
    print('{0}: access-list {1}, rule {2}: {3}'.format(currentrule.hostname, currentrule.accesslist, currentrule.ruleindex, str(currentrule)))
    print('{0}'.format(currentrule.original))
    print('Total number of hits: {0}'.format(str(currenthits)))
    if len(conns) >= config['MAX_NUMBER_OF_CONNECTIONS_PER_RULE']:
        print('NOTE: Maximum number of connections ({0}) reached for this rule, additional connections not displayed.'.format(config['MAX_NUMBER_OF_CONNECTIONS_PER_RULE']))
    print '%6s %4s  %-15s %-14s %-5s %-19s  %-19s' % ('COUNT', 'PROTO', \
        'FROM IP', 'TO IP', 'PORT', 'FIRST SEEN', 'LAST SEEN')

    # Print connection table
    for conn in entries:
        proto, fromIP, toIP, toport = conn.split(';')
        print '%6d %4s %15s  %15s %-5s %19s  %19s' % (conns[conn], proto, fromIP, \
                toIP, toport, connFirst[conn], connLast[conn])

    # Re-initialize list of connections and timestamps
    conns = {}
    connFirst = {}
    connLast = {}

