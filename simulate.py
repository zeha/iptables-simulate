#!/usr/bin/python
#
# Parses output from iptables-save and matches it against a supplied "packet".
#
# Copyright 2010 INQNET GmbH <oss@inqnet.at>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
# 

import sys
from optparse import OptionParser

input_filename = 'rules-live.iptablessave'

final_targets = ['ACCEPT','DROP','QUEUE','RETURN','REJECT','DNAT','MARK','MASQUERADE','SNAT','NOTRACK','REDIRECT']
continue_targets = ['LOG','ULOG']

rules = {}
policies = {}

class TerminalColor:
        RED = '\033[91m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        ENDC = '\033[0m'

        @staticmethod
        def colored(color, string):
                return '%s%s%s' % (color, string, TerminalColor.ENDC)

# dict-style object which also allows attribute-based access to the dict
class ObjectDict(dict):
        def __setattr__(self,k,v):
                self[k] = v
        def __getattr__(self,k):
                return self[k]
        def __delattr__(self,k):
                del self[k]

# ObjectDict with nicer print-ability
class IptablesRule(ObjectDict):
        def __str__(self):
                def keysorter(a,b):
                        typetable = {'ignore': 0, 'action': 2, 'match': 1, 'targetarg': 3}
                        typesort_a = typetable[iptables_optdests[a]['type']]
                        typesort_b = typetable[iptables_optdests[b]['type']]
                        if typesort_a > typesort_b: return 1
                        if typesort_a < typesort_b: return -1
                        return a > b
                x = []
                keys = self.keys()
                keys.sort(cmp=keysorter)
                for key in keys:
                        value = self[key]
                        if key == 'jump' or key == 'goto': value = TerminalColor.colored(TerminalColor.YELLOW, value)
                        x.append("%s %s" % (iptables_optdests[key]['opt'], value))
                return " ".join(x)

iptables_options = ObjectDict()
iptables_optdests = ObjectDict()

def comparator_state(a, b):
        if a in b.split(','): return True
        return False

def add_iptables_option(opt, **kwargs):
        if not kwargs.has_key('type'): kwargs['type'] = 'match'
        if not kwargs.has_key('comparator'): kwargs['comparator'] = str.__eq__
        iptables_options[opt] = kwargs
        kwargs['opt'] = opt
        iptables_optdests[kwargs['dest']] = kwargs

def init_iptables_options():
        add_iptables_option("-t", dest="table", type='ignore')
        add_iptables_option("-A", dest="chain", type='ignore')

        add_iptables_option("-j", dest="jump", type='action')
        add_iptables_option("-g", dest="goto", type='action')

        add_iptables_option("-i", dest="in_iface")
        add_iptables_option("-o", dest="out_iface")
        add_iptables_option("-s", dest="source_ip")
        add_iptables_option("-d", dest="dest_ip")
        add_iptables_option("--pol", dest="policy_pol")
        add_iptables_option("--dir", dest="policy_dir")
        add_iptables_option("-p", dest="protocol")
        add_iptables_option("--sport", dest="sport")
        add_iptables_option("--sports", dest="sports")
        add_iptables_option("--src-type", dest="src_type")
        add_iptables_option("--dport", dest="dport")
        add_iptables_option("--dports", dest="dports")
        add_iptables_option("--dst-type", dest="dst_type")
        add_iptables_option("--state", dest="state", comparator=comparator_state)
        add_iptables_option("--icmp-type", dest="icmp_type")
        add_iptables_option("--tcp-flags", dest="tcp_flags")
        add_iptables_option("--ctorigdst", dest="ctorigdst")
        add_iptables_option("--ctorigdstport", dest="ctorigdstport")       

        add_iptables_option("--log-prefix", dest="log_prefix", type='targetarg')
        add_iptables_option("--log-level", dest="log_level", type='targetarg')
        add_iptables_option("--ulog-prefix", dest="ulog_prefix", type='targetarg')
        add_iptables_option("--ulog-level", dest="ulog_level", type='targetarg')
        add_iptables_option("--to-destination", dest="nat_todest", type='targetarg')
        add_iptables_option("--to-source", dest="nat_tosrc", type='targetarg')
        add_iptables_option("--reject-with", dest="reject_with", type='targetarg')

        add_iptables_option("--comment", dest="comment", type='ignore')
        add_iptables_option("-m", dest="module_load", type='ignore')

def add_iptables_options_to_optparser(parser):
        for opt in iptables_options:
                dst = iptables_options[opt]['dest']
                parser.add_option(opt, dest=dst)

def apply_matchopts_defaults(match_opts):
        # policy module ...
        if not match_opts.has_key('policy_pol'):
                # default to no IPsec
                match_opts.policy_pol = 'none'
                print '(setting default: policy_pol = %s)' % match_opts.policy_pol
        if not match_opts.has_key('policy_dir'):
                # these are the only valid values, anyway
                if match_opts.chain in "PREROUTING,INPUT".split(','): match_opts.policy_dir = 'in'
                if match_opts.chain in "POSTROUTING,OUTPUT".split(','): match_opts.policy_dir = 'out'
                # FORWARD can have policy in or out. default to in.
                if match_opts.chain in ['FORWARD']: match_opts.policy_dir = 'in'
                print '(setting default: policy_dir = %s)' % match_opts.policy_dir
        # state module ...
        if not match_opts.has_key('state'):
                match_opts.state = 'NEW'
                print '(setting default: state = %s)' % match_opts.state


def load_rules(filename):
        # prepare ruleparser
        iptables_parser = OptionParser()
        add_iptables_options_to_optparser(iptables_parser)

        table = ''
        count = 0
        rulesfile = file(filename, 'r')
        for line in rulesfile:
                if line.startswith('#'): continue
                if line.startswith('*'):
                        table = line[1:].strip()
                        print "Loading table %s" % table
                        rules[table] = {}
                        policies[table] = {}
                        continue
                if line.startswith('COMMIT'):
                        table = ''
                        continue
                if line.startswith(':'):
                        rules[table][line[1:].strip().split(' ')[0]] = []
                        policies[table][line[1:].strip().split(' ')[0]] = line[1:].strip().split(' ')[1]
                        continue

                count = count + 1

                (rule, rule_args) = iptables_parser.parse_args(line.split(' '), values=IptablesRule())
                rule.table = table

                # HACK: policy module seems to ignore --dir if --pol none is set
                if rule.has_key('policy_pol') and rule.has_key('policy_dir'):
                        if rule.policy_pol == 'none': del rule['policy_dir']

                rules[table][rule.chain].append(rule)

        print "Loaded %d rules" % count

def match_rules(match_opts):
        global checked_rules_count
        checked_rules_count = 0
        table = match_opts.table
        chain = match_opts.chain
        rv = match_rules_inner(match_opts, table, chain, 0)
        if not rv:
                print "Applying POLICY: %s" % policies[table][chain]
        print "Checked %d rules" % checked_rules_count

# reentrant
def match_rules_inner(match_opts, table, chain, level):
        global checked_rules_count
        prefix = " " * level
        level = level + 1
        print prefix, '%s>> table %s chain %s' % (TerminalColor.RED, table, TerminalColor.colored(TerminalColor.YELLOW, chain))
        my_rv = False
        for rule in rules[table][chain]:
                checked_rules_count = checked_rules_count + 1
                print prefix, rule,
                have_all = True
                for opt in rule.keys():
                        if not iptables_optdests[opt]['type'] == 'match': continue
                        if not match_opts.has_key(opt):
                                have_all = False
                                break
                if not have_all:
                        print " (ignored, not all matches available)"
                        continue
                
                matched = True
                for opt in rule.keys():
                        if not iptables_optdests[opt]['type'] == 'match': continue
                        comp = iptables_optdests[opt]['comparator']
                        if not comp(match_opts[opt],rule[opt]):
                                matched = False
                                break

                if matched:
                        print TerminalColor.colored(TerminalColor.GREEN, ' -> matched')
                        if rule.has_key('jump'):
                                if rule.jump in final_targets:
                                        print "=== Rule reached target: %s" % TerminalColor.colored(TerminalColor.YELLOW, rule.jump)
                                        my_rv = True
                                        break
                                if rule.jump in continue_targets:
                                        print "--- Rule triggered target: %s" % TerminalColor.colored(TerminalColor.YELLOW, rule.jump)
                                        continue
                                rv = match_rules_inner(match_opts, table, rule.jump, level)
                                if rv:
                                        my_rv = True
                                        break
                        if rule.has_key('goto'):
                                rv = match_rules_inner(match_opts, table, rule.goto, level)
                                if rv: my_rv = True
                                break
                else:
                        print " (matches not satisfied)"
        if not my_rv:
                print prefix, "<< returning to previous chain"
                return
        if my_rv:
                return True


def main():
        init_iptables_options()

        # parse command line args
        prog_parser = OptionParser()
        add_iptables_options_to_optparser(prog_parser)
        (match_opts, prog_args) = prog_parser.parse_args(values=ObjectDict())

        if not match_opts.has_key('chain'):
                print "E: -A CHAIN is required"
                sys.exit(1)
        if not match_opts.has_key('table'):
                print "E: -t table is required"
                sys.exit(1)

        apply_matchopts_defaults(match_opts)

        load_rules(input_filename)

        match_rules(match_opts)

main()

