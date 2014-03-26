#!/usr/bin/env python
#
# Postprocess results of RulesetAnalysis Hadoop job
#
import os
import re
import sys
import shelve
import logging
import optparse
from glob import glob

CONFIGFILE = 'config.py'

# Load config file
try:
    config = {}
    execfile(CONFIGFILE, config)
except:
    sys.stderr.write('Unable to load config file ({0})! Aborting.\n'.format(CONFIGFILE))
    sys.exit(1)

# Only process rules for supported protocols and actions
SUPPORTED_PROTOCOLS = ['ip', 'tcp', 'udp']
SUPPORTED_ACTIONS = [True]     # True=permit

if __name__ == '__main__':
    prog = os.path.basename(sys.argv[0])
    usage = """%prog [-h] [-v] [-v] -f <output file>"""
    description = """%prog processes output from RulesetAnalysis jobs to determine which access-list rules had zero hits."""
    epilog = "2013 - Arne Sund"
    version = "%prog 0.9"

    p = optparse.OptionParser(usage=usage, version=version, description=description, epilog=epilog)
    p.add_option('-v', "--verbose", dest='verbose', action='count', default=0, help='turn on verbose output, apply twice for debug')
    p.add_option('-f', help="output file for Hadoop job", metavar="FILE")
    o, args = p.parse_args()

    # Determine log level from verbose flag
    if o.verbose > 1:
        # Debug logging
        DEBUG = True
        logging.BASIC_FORMAT = "%(levelname)s - %(funcName)s:%(lineno)d - %(message)s"
        logging.basicConfig(level=logging.DEBUG)
    else:
        DEBUG = False
        logging.BASIC_FORMAT = "%(levelname)s - %(message)s"
        if o.verbose:
            logging.basicConfig(level=logging.INFO)
        else:
            logging.basicConfig(level=logging.WARNING)

    # File argument is mandatory
    if not o.f:
        p.print_usage()
        sys.exit(1)


    # Open access-list database
    try:
        acldb = shelve.open(config['ACCESSLIST_DATABASE'])
    except:
        logging.error('Unable to open access-list database ' + \
            '("{0}"). '.format(config['ACCESSLIST_DATABASE']) + \
            'Did you remember to run preprocessor?')
        sys.exit(1)

    # Read from database and close file
    try:
        accesslists = acldb['accesslists']
        acldb.close()
    except KeyError as e:
        logging.error('Unable to find database entry {0} in shelve file "{1}"'.format(e, config['ACCESSLIST_DATABASE']))
        sys.exit(1)


    # Dict of hostnames (level 1) and access-list names (level 2) seen in output files
    seenhosts = {}
    
    # Process output file from Hadoop job
    if DEBUG:
        print('Parsing output file {0}'.format(o.f))

    # Read result file from Hadoop job
    try:
        entries = open(o.f).read().split('\t\n\t\n')
    except Exception:
        logging.error('unable to read result file {0}'.format(o.f))
        sys.exit(1)
    if DEBUG:
        print('Output file {0} has {1} entries.'.format(o.f, len(entries)))

    # Save results to the corresponding FirewallRule object 
    for entry in entries:
        # Extract info to identify rule
        firewall, acl, ruleindex = re.findall(r'([a-zA-Z0-9_-]+): access-list ([a-zA-Z0-9_-]+), rule ([0-9]+):', entry, re.DOTALL)[0]
        # Save entry to rule object
        accesslists[firewall][acl]['rules'][int(ruleindex)].results = entry
        # Log host and acl to list of seen hosts
        if firewall not in seenhosts:
            seenhosts[firewall] = []
        if acl not in seenhosts[firewall]:
            seenhosts[firewall].append(acl)
        if DEBUG:
            print('Processed firewall {0}: access-list {1}, ruleindex {2}'.format(firewall, acl, ruleindex))

    # Print entire ruleset with hit counter at beginning of line
    print('ENTIRE RULESET WITH HITCOUNTS')
    print('')
    for firewall in seenhosts:
        for acl in seenhosts[firewall]:
            for rule in accesslists[firewall][acl]['rules']:
                try:
                    hitcount = int(re.findall(r'Total number of hits: ([0-9]+)', rule.results, re.DOTALL)[0])
                except AttributeError:
                    # No results found
                    hitcount = 0
                if rule.protocol in SUPPORTED_PROTOCOLS and rule.action in SUPPORTED_ACTIONS:
                    # Print access-list entry with hitcount
                    print(' {0:15}  {1}  ({2})'.format(hitcount, rule.original, str(rule)))
                # Save hitcount to rule object
                accesslists[firewall][acl]['rules'][rule.ruleindex].hitcount = hitcount
    print('')

    print('DISTINCT RULES WITH NO HITS')
    print('')
    for firewall in seenhosts:
        for acl in seenhosts[firewall]:
            if DEBUG:
                print('{0} access-list: {1}'.format(firewall, acl))
            currentrule = False
            nonehits = True
            for rule in accesslists[firewall][acl]['rules']:
                if not currentrule:
                    currentrule = rule
                if DEBUG:
                    print('Currentrule (1): num {0} index {1} contents: {2}'.format(currentrule.rulenum, currentrule.ruleindex, currentrule.original))
                    print('Nonehits    (1): {0}'.format(nonehits))

                if rule.rulenum == currentrule.rulenum:
                    if DEBUG:
                        print('Same rulenum, hitcount is {0} for ruleindex {1}'.format(rule.hitcount, rule.ruleindex))
                    if rule.hitcount > 0:
                        nonehits = False
                else:
                    if DEBUG:
                        print('NEW rulenum: {0} with hitcount {1} and ruleindex {2}'.format(rule.rulenum, rule.hitcount, rule.ruleindex))
                    if nonehits and currentrule.protocol in SUPPORTED_PROTOCOLS and currentrule.action in SUPPORTED_ACTIONS:
                        # Print rule with comments
                        for line in currentrule.comments:
                            print line.strip()
                        print('{0}'.format(currentrule.original))
                    currentrule = rule
                    # Set nonehits to False if this new rule has hits, else reset to default value
                    nonehits = False if rule.hitcount > 0 else True
                if DEBUG:
                    print('Currentrule (2): num {0} index {1} contents: {2}'.format(currentrule.rulenum, currentrule.ruleindex, currentrule.original))
                    print('Nonehits    (2): {0}'.format(nonehits))
                    print('')
    print('')


    # Print each rule and the results found for it
    print('CONNLIST FOR EACH RULE')
    print('')
    for firewall in seenhosts:
        for acl in seenhosts[firewall]:
            for rule in accesslists[firewall][acl]['rules']:
                if rule.protocol in SUPPORTED_PROTOCOLS and rule.action in SUPPORTED_ACTIONS:
                    try:
                        print(rule.results)
                        print('')
                    except AttributeError:
                        # No results found, just print info about rule
                        print('{0}: access-list {1}, rule {2}: {3}'.format(firewall, acl, str(rule.ruleindex), str(rule)))
                        print('{0}'.format(rule.original))
                        print('')

    
