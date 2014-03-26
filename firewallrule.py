#!/usr/bin/env python
#
# Module with classes for representing firewall rules
#
from IPy import IP


class FirewallRule:
    '''
    A firewall rule with properties like action, protocol, source, destination and so on.

    Attributes:
        action: Boolean where True = Packet is allowed and False = Packet is dropped.
        protocol: String - Protocol name. All names are lowercased.
        original: String - Firewall rule in the native format of the firewall in question.
        src: String - IP address or network. Input is saved as an IP object.
        sport: List of Integers - Source ports.
        dst: String - IP address or network. Input is saved as an IP object.
        dport: List of Integers - Destination ports.
        comments: List of Strings describing the firewall rule.
        rulenum: Integer - Index of the original rule in the access-list it belongs to.
        ruleindex: Integer - Index of the expanded rule in the access-list structure.

    NOTE: The integer -1 is used as port number to indicate 'No port number'.
    '''

    # Placeholder for 'No port number' for the integer port number fields
    NO_PORT = -1

    # Special address range matching all IPv4 addresses
    ANY = IP('0.0.0.0/0')

    def __init__(self, action, protocol, original, src, dst, sport=NO_PORT, dport=NO_PORT, comments=[], rulenum=-1, ruleindex=-1):
        '''Initializes FirewallRule with required information'''

        # Validate action
        if isinstance(action, basestring):
            try:
                action = bool(action)
            except ValueError, e:
                raise ValueError('unable to convert action to boolean, action must be True/False')

        if not isinstance(action, bool):
            raise ValueError('action must be True/False where True=Permit and False=Deny')

        # If source or destination port are strings, convert to integer
        try:
            if isinstance(sport, basestring):
                sport = [int(sport)]
            if isinstance(dport, basestring):
                dport = [int(dport)]
        except ValueError, e:
            raise ValueError('unable to convert either source or destination port to Integer')

        # Convert source and destination port to lists
        if not isinstance(sport, list):
            sport = [sport]
        if not isinstance(dport, list):
            dport = [dport]

        # Catch empty lists and convert to placeholder value
        if len(sport) == 0:
            sport = [self.NO_PORT]
        if len(dport) == 0:
            dport = [self.NO_PORT]

        # Source port must be a list of integers
        for item in sport:
            if not isinstance(item, int):
                raise ValueError('Source port must be an integer or -1 for "No port"')      

        # Destination port must be a list of integers
        for item in dport:
            if not isinstance(item, int):
                raise ValueError('Source port must be an integer or -1 for "No port"')      

        # Convert source to IP object
        if src == 'any':
            self.src = self.ANY
        else:
            try:
                self.src = IP(src)
            except ValueError, e:
                raise ValueError('argument "src" must be a valid IP address or network. Error: ' + str(e))

        # Convert destination to IP object
        if dst == 'any':
            self.dst = self.ANY
        else:
            try:
                self.dst = IP(dst)
            except ValueError, e:
                raise ValueError('argument "dst" must be a valid IP address or network. Error: ' + str(e))

        # Save input
        self.action = action
        self.protocol = str(protocol)
        self.original = original
        self.sport = sport
        self.dport = dport
        self.comments = comments
        self.rulenum = rulenum
        self.ruleindex = ruleindex


    def __eq__(self, other):
        '''Check if this rule is equal to the other. Done by comparing contents of all object attributes.'''
        if isinstance(other, FirewallRule):
            return self.__dict__ == other.__dict__
        else:
            return False

    def __str__(self):
        '''Return a short textual summary of the firewall rule'''
        action = 'permit' if self.action else 'deny'
        source = str(self.src) if self.sport == [self.NO_PORT] else str(self.src) + ':' + str(self.sport)
        destination = str(self.dst) if self.dport == [self.NO_PORT] else str(self.dst) + ':' + str(self.dport)
        return action + ' ' + self.protocol + ' ' + source + ' -> ' + destination


    def __repr__(self):
        '''Return the Python representation of this object'''
        return 'FirewallRule(' + repr(self.action) + ", " + repr(self.protocol) + ", '" + self.original + "', '" + \
            str(self.src) + "', '" + str(self.dst) + "', sport=" + repr(self.sport) + ", dport=" + repr(self.dport) + \
            ", comments=" + repr(self.comments) + ", rulenum=" + str(self.rulenum) + ", ruleindex=" + str(self.ruleindex) + ')'
            

    def __contains__(self, other):
        '''
        Check whether this rule contains the other rule. True if all matches to the other rule will match this rule too.

        Args:
            other: FirewallRule object
        
        Returns:
            True if this rule contains the other rule. False if not.

        Throws:
            ValueError if other object is something else than a FirewallRule object.
        '''

        if not isinstance(other, FirewallRule):
            raise ValueError('both objects must be FirewallRule objects')
        
        # Action must match
        if self.action != other.action:
            return False

        # Protocol must either match or be the special case of IP (layer 3) which contains all layer 4 protocols
        if self.protocol != 'ip' and self.protocol != other.protocol:
            return False

        # The source address of this rule must contain the source of the other rule entirely
        if other.src not in self.src:
            return False

        # The destination address of this rule must contain the destination of the other rule entirely
        if other.dst not in self.dst:
            return False

        # If this rule has source ports defined, the list must contain the source ports of the other rule
        if self.sport != [self.NO_PORT]:
            for port in other.sport:
                if port not in self.sport:
                    return False

        # If this rule has destination ports defined, the list must contain the destination ports of the other rule
        if self.dport != [self.NO_PORT]:
            for port in other.dport:
                if port not in self.dport:
                    return False

        # Assume all tests above is enough to parse out rules not contained in this rule
        return True


def testcases():
    # Test rules
    orig = 'original line unknown'
    rule1 = FirewallRule(True, 'ip', orig, 'any', 'any')
    rule2 = FirewallRule(True, 'tcp', orig, '198.51.100.0/24', '192.0.2.14/32', dport=80)
    rule3 = FirewallRule(True, 'ip', orig, '198.51.100.0/24', '192.0.2.14/32')
    rule4 = FirewallRule(True, 'tcp', orig, '198.51.100.0/24', 'any', dport=80)

    icmp1 = FirewallRule(True, 'icmp', orig, 'any', 'any', 30)
    icmp2 = FirewallRule(True, 'icmp', orig, 'any', 'any')

    conn1 = FirewallRule(True, 'tcp', orig, '198.51.100.247', '174.35.64.57', sport=54742, dport=80)
    conn2 = FirewallRule(True, 'tcp', orig, '203.0.113.247', '174.35.64.57', sport=54742, dport=80)
    conn3 = FirewallRule(True, 'tcp', orig, '198.51.100.247', '174.35.64.57', sport=54742, dport=81)
    conn4 = FirewallRule(True, 'udp', orig, '198.51.100.247', '174.35.64.57', sport=54742, dport=80)

    # API correctness
    if not rule1 == eval(repr(rule1)):
        print('Failed test case:')
        print('  rule1 == eval(repr(rule1))')
        print('')

    # Test cases
    tests = [ (rule2, rule1, True), (rule2, rule3, True), (rule3, rule2, False),
              (conn1, rule4, True), (conn2, rule4, False), (conn3, rule4, False), (conn4, rule4, False)
            ]

    # Run all tests and report failed ones, if any
    for r1, r2, res in tests:
        if res:
            if r1 not in r2:
                print('Failed test case:')
                print('  {0}  in  {1}'.format(r1, r2))
                print('  -> Expected {0}, got {1}'.format(res, r1 in r2))
                print('')
        else:
            if r1 in r2:
                print('Failed test case:')
                print('  {0}  in  {1}'.format(r1, r2))
                print('  -> Expected {0}, got {1}'.format(res, r1 in r2))
                print('')
            

    print('All tests completed.')


if __name__ == '__main__':
    # Run test cases
    testcases()
