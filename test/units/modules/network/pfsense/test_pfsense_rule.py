# Copyright: (c) 2018, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import pytest
import sys

if sys.version_info < (2, 7):
    pytestmark = pytest.mark.skip("pfSense Ansible modules require Python >= 2.7")

from xml.etree.ElementTree import fromstring, ElementTree
from units.compat.mock import patch
from ansible.modules.network.pfsense import pfsense_rule
from ansible.module_utils.network.pfsense.rule import PFSenseRuleModule
from .pfsense_module import TestPFSenseModule, load_fixture


class TestPFSenseRuleModule(TestPFSenseModule):

    module = pfsense_rule

    def __init__(self, *args, **kwargs):
        super(TestPFSenseRuleModule, self).__init__(*args, **kwargs)
        self.config_file = 'pfsense_rule_config.xml'
        self.pfmodule = PFSenseRuleModule

    @staticmethod
    def runTest():
        """ dummy function needed to instantiate this test module from another in python 2.7 """
        pass

    def parse_address(self, addr):
        """ return address parsed in dict """
        parts = addr.split(':')
        res = {}
        if parts[0][0] == '!':
            res['not'] = None
            parts[0] = parts[0][1:]
        if parts[0] == 'any':
            res['any'] = None
        elif parts[0] == '(self)':
            res['network'] = '(self)'
        elif parts[0] == 'NET':
            res['network'] = self.unalias_interface(parts[1])
            del parts[1]
        elif parts[0] == 'IP':
            res['network'] = self.unalias_interface(parts[1]) + 'ip'
            del parts[1]
        elif parts[0] in ['lan', 'lan', 'vpn', 'vt1', 'lan_100']:
            res['network'] = self.unalias_interface(parts[0])
        else:
            res['address'] = parts[0]

        if len(parts) > 1:
            res['port'] = parts[1]

        return res

    def check_rule_elt_addr(self, rule, rule_elt, addr):
        """ test the addresses definition of rule """
        addr_dict = self.parse_address(rule[addr])
        addr_elt = self.assert_find_xml_elt(rule_elt, addr)
        for key, value in addr_dict.items():
            self.assert_xml_elt_equal(addr_elt, key, value)
        if 'any' in addr_dict:
            self.assert_not_find_xml_elt(addr_elt, 'address')
            self.assert_not_find_xml_elt(addr_elt, 'network')
        if 'network' in addr_dict:
            self.assert_not_find_xml_elt(addr_elt, 'address')
            self.assert_not_find_xml_elt(addr_elt, 'any')
        if 'address' in addr_dict:
            self.assert_not_find_xml_elt(addr_elt, 'network')
            self.assert_not_find_xml_elt(addr_elt, 'any')

        if 'not' not in addr_dict:
            self.assert_not_find_xml_elt(addr_elt, 'not')

    def get_target_elt(self, obj, absent=False):
        """ return target elt from XML """
        obj['interface'] = self.unalias_interface(obj['interface'])
        if 'floating' in obj and obj['floating'] == 'yes':
            return self.assert_has_xml_tag('filter', dict(descr=obj['name'], floating='yes'), absent=absent)
        return self.assert_has_xml_tag('filter', dict(descr=obj['name'], interface=obj['interface']), absent=absent)

    def check_target_elt(self, obj, target_elt):
        """ check XML definition of target elt """

        # checking source address and ports
        self.check_rule_elt_addr(obj, target_elt, 'source')

        # checking destination address and ports
        self.check_rule_elt_addr(obj, target_elt, 'destination')

        # checking log option
        if 'log' in obj and obj['log'] == 'yes':
            self.assert_xml_elt_is_none_or_empty(target_elt, 'log')
        elif 'log' not in obj or obj['log'] == 'no':
            self.assert_not_find_xml_elt(target_elt, 'log')

        # checking action option
        if 'action' in obj:
            action = obj['action']
        else:
            action = 'pass'
        self.assert_xml_elt_equal(target_elt, 'type', action)

        # checking floating option
        if 'floating' in obj and obj['floating'] == 'yes':
            self.assert_xml_elt_equal(target_elt, 'floating', 'yes')
            if 'quick' in obj and obj['quick'] == 'yes':
                self.assert_xml_elt_equal(target_elt, 'quick', 'yes')
            else:
                self.assert_not_find_xml_elt(target_elt, 'quick')

        elif 'floating' not in obj or obj['floating'] == 'no':
            self.assert_not_find_xml_elt(target_elt, 'floating')
            self.assert_not_find_xml_elt(target_elt, 'quick')

        # checking direction option
        self.check_param_equal_or_not_find(obj, target_elt, 'direction')

        # checking default queue option
        self.check_param_equal_or_not_find(obj, target_elt, 'queue', 'defaultqueue')

        # checking acknowledge queue option
        self.check_param_equal_or_not_find(obj, target_elt, 'ackqueue')

        # limiters
        self.check_param_equal_or_not_find(obj, target_elt, 'in_queue', 'dnpipe')
        self.check_param_equal_or_not_find(obj, target_elt, 'out_queue', 'pdnpipe')

        # schedule
        self.check_param_equal_or_not_find(obj, target_elt, 'sched')

        # checking ipprotocol option
        if 'ipprotocol' in obj:
            action = obj['ipprotocol']
        else:
            action = 'inet'
        self.assert_xml_elt_equal(target_elt, 'ipprotocol', action)

        # checking protocol option
        if 'protocol' in obj and obj['protocol'] != 'any':
            self.assert_xml_elt_equal(target_elt, 'protocol', obj['protocol'])
        else:
            self.assert_not_find_xml_elt(target_elt, 'protocol')

        # checking tcpflags_any option
        if 'tcpflags_any' in obj and obj['tcpflags_any'] == 'yes':
            self.assert_xml_elt_is_none_or_empty(target_elt, 'tcpflags_any')
        elif 'tcpflags_any' not in obj or obj['tcpflags_any'] == 'no':
            self.assert_not_find_xml_elt(target_elt, 'tcpflags_any')

        # checking statetype option
        if 'statetype' in obj and obj['statetype'] != 'keep state':
            statetype = obj['statetype']
        else:
            statetype = 'keep state'
        self.assert_xml_elt_equal(target_elt, 'statetype', statetype)

        # checking disabled option
        if 'disabled' in obj and obj['disabled'] == 'yes':
            self.assert_xml_elt_is_none_or_empty(target_elt, 'disabled')
        elif 'disabled' not in obj or obj['disabled'] == 'no':
            self.assert_not_find_xml_elt(target_elt, 'disabled')

        # checking gateway option
        if 'gateway' in obj and obj['gateway'] != 'default':
            self.assert_xml_elt_equal(target_elt, 'gateway', obj['gateway'])
        else:
            self.assert_not_find_xml_elt(target_elt, 'gateway')

        # checking tracker
        if 'tracker' in obj:
            self.assert_xml_elt_equal(target_elt, 'tracker', obj['tracker'])

        # checking icmptype
        if 'icmptype' in obj:
            self.assert_xml_elt_equal(target_elt, 'icmptype', obj['icmptype'])

    def check_rule_idx(self, rule, target_idx):
        """ test the xml position of rule """
        floating = 'floating' in rule and rule['floating'] == 'yes'
        rule['interface'] = self.unalias_interface(rule['interface'])
        rules_elt = self.assert_find_xml_elt(self.xml_result, 'filter')
        idx = -1
        for rule_elt in rules_elt:
            interface_elt = rule_elt.find('interface')
            floating_elt = rule_elt.find('floating')
            floating_rule = floating_elt is not None and floating_elt.text == 'yes'
            if floating and not floating_rule:
                continue
            if not floating:
                if floating_rule or interface_elt is None or interface_elt.text is None or interface_elt.text != rule['interface']:
                    continue
            idx += 1
            descr_elt = rule_elt.find('descr')
            self.assertIsNotNone(descr_elt)
            self.assertIsNotNone(descr_elt.text)
            if descr_elt.text == rule['name']:
                self.assertEqual(idx, target_idx)
                return
        self.fail('rule not found ' + str(idx))

    def check_separator_idx(self, interface, sep_name, expected_idx):
        """ test the logical position of separator """
        filter_elt = self.assert_find_xml_elt(self.xml_result, 'filter')
        separator_elt = self.assert_find_xml_elt(filter_elt, 'separator')
        iface_elt = self.assert_find_xml_elt(separator_elt, interface)
        for separator in iface_elt:
            text_elt = separator.find('text')
            if text_elt is not None and text_elt.text == sep_name:
                row_elt = self.assert_find_xml_elt(separator, 'row')
                idx = int(row_elt.text.replace('fr', ''))
                if idx != expected_idx:
                    self.fail('Idx of separator ' + sep_name + ' if wrong: ' + str(idx) + ', expected: ' + str(expected_idx))
                return
        self.fail('Separator ' + sep_name + 'not found on interface ' + interface)
