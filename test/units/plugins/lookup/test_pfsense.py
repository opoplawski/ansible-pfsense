# Copyright: (c) 2020, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os
from collections import OrderedDict
import yaml
from units.compat.mock import patch
from ansible.plugins.loader import lookup_loader
from units.modules.utils import ModuleTestCase


def ordered_dump(data, dumper_cls=yaml.Dumper):
    """ dump and return yaml string from data using ordered dicts """

    class OrderedDumper(dumper_cls):
        pass

    def dict_representer(dumper, data):
        return dumper.represent_dict(data.items())

    OrderedDumper.add_representer(OrderedDict, dict_representer)
    return yaml.dump(data, Dumper=OrderedDumper)


class TestPFSenseLookup(ModuleTestCase):
    ##############################
    # init
    #
    def __init__(self, *args, **kwargs):
        super(TestPFSenseLookup, self).__init__(*args, **kwargs)
        self.rules = None

        self.definitions = None

        self.interfaces = None

    def setUp(self):
        """ mocking up """
        super(TestPFSenseLookup, self).setUp()

        self.build_definitions()

        # self.fixture_path = os.path.join(os.path.dirname(__file__), 'fixtures', 'pfsense.yaml')
        self.mock_get_hostname = patch('ansible.plugins.lookup.pfsense.LookupModule.get_hostname')
        get_hostname = self.mock_get_hostname.start()
        get_hostname.return_value = ('pf_test1')

        self.mock_get_definitions = patch('ansible.plugins.lookup.pfsense.LookupModule.get_definitions')
        self.get_definitions = self.mock_get_definitions.start()
        self.get_definitions.return_value = self.definitions

    def tearDown(self):
        """ mocking down """
        super(TestPFSenseLookup, self).tearDown()
        self.mock_get_hostname.stop()
        self.mock_get_definitions.stop()

    def build_definitions(self):
        """ build definitions base for tests """
        self.definitions = OrderedDict()
        self.definitions['hosts_aliases'] = OrderedDict()
        self.definitions['ports_aliases'] = OrderedDict()
        self.definitions['rules'] = OrderedDict()
        self.definitions['pfsenses'] = OrderedDict()
        self.definitions['pfsenses']['pf_test1'] = OrderedDict()
        self.definitions['pfsenses']['pf_test1'] = OrderedDict()
        self.definitions['pfsenses']['pf_test1']['interfaces'] = OrderedDict()

        self.interfaces = dict(
            WAN=dict(remote_networks='0.0.0.0/0'),
            LANA=dict(base='10.20.30.x', remote_base='10.120.x', adjacent_base='10.220.x'),
            LANB=dict(base='10.20.40.x', remote_base='10.130.x', adjacent_base='10.230.x'),
        )

        for name, defs in self.interfaces.items():
            self.definitions['pfsenses']['pf_test1']['interfaces'][name] = OrderedDict()
            if 'base' in defs:
                self.definitions['pfsenses']['pf_test1']['interfaces'][name]['ip'] = defs['base'].replace('x', '1/24')
            for param in ['remote_networks', 'adjacent_networks']:
                if param in defs:
                    self.definitions['pfsenses']['pf_test1']['interfaces'][name][param] = defs[param]
            if 'remote_base' in defs:
                self.definitions['pfsenses']['pf_test1']['interfaces'][name]['remote_networks'] = defs['remote_base'].replace('x', '0.0/16')
            if 'adjacent_base' in defs:
                self.definitions['pfsenses']['pf_test1']['interfaces'][name]['adjacent_networks'] = defs['adjacent_base'].replace('x', '0.0/16')

    def save_definitions(self, filename='test_definitions.yml'):
        """ save generated definitions to file for debbuging """
        with open(filename, 'w') as outfile:
            outfile.write(ordered_dump(self.definitions))

    def run_rules(self):
        """ run the plugin for rules """
        pfsense_lookup = lookup_loader.get('pfsense')
        self.rules = pfsense_lookup.run(['dummy.yml', 'rules'], {})[0]

    def assert_get_rule(self, rule_name, count=1):
        """ check that rule_name is defined """
        rules = []
        for rule in self.rules:
            if rule['name'] == rule_name:
                rules.append(rule)

        if count == 1 and len(rules) == 0:
            self.fail('{0} not found'.format(rule_name))
        if count == 1 and len(rules) > 1:
            self.fail('Multiples {0} found: {1}'.format(rule_name, rules))
        self.assertEqual(len(rules), count)
        if count == 1:
            return rules[0]
        return rules

    def assert_rule_not_found(self, rule_name):
        """ check that rule_name is not defined """
        for rule in self.rules:
            if rule['name'] == rule_name:
                self.fail('{0} found'.format(rule_name))

    @staticmethod
    def add_missing_fields(expected_rule, rule):
        """ add missing generated field with default values """
        for param in ['ackqueue', 'gateway', 'icmptype', 'in_queue', 'out_queue', 'queue', 'log', 'sched']:
            if param not in expected_rule and param in rule:
                expected_rule[param] = None

        if 'action' not in expected_rule:
            expected_rule['action'] = 'pass'

        if 'state' not in expected_rule:
            expected_rule['state'] = 'present'

    @staticmethod
    def correct_aliases(expected_rule):
        """ we correct IP values with interface names """
        translations = {
            '10.20.30.1': 'IP:LANA',
            # '10.20.30.3': 'IP:LANB',
        }
        for field in ['source', 'destination']:
            if expected_rule[field] in translations:
                expected_rule[field] = translations[expected_rule[field]]

    def compare_rules(self, expected_rule, rule):
        """ compare rule with the expected result """
        if 'after' in rule:
            del rule['after']
        self.add_missing_fields(expected_rule, rule)
        self.correct_aliases(expected_rule)
        self.assertEqual(expected_rule, rule)

    def gen_rule(self, src, dst, interface, action):
        """ generate rule definition according parameters """
        rule = OrderedDict()
        rule['protocol'] = 'any'
        rule['name'] = src + '_' + dst + '_' + interface + '_' + action
        if src == 'l':
            rule['src'] = self.interfaces['LANA']['base'].replace('x', '2')
        elif src == 's':
            rule['src'] = self.interfaces['LANA']['base'].replace('x', '1')
        elif src == 'r':
            rule['src'] = self.interfaces['LANA']['remote_base'].replace('x', '30.30')
        elif src == 'a':
            rule['src'] = self.interfaces['LANA']['adjacent_base'].replace('x', '30.30')

        if interface == 's':
            if dst == 'l':
                rule['dst'] = self.interfaces['LANA']['base'].replace('x', '3')
            elif dst == 's':
                rule['dst'] = self.interfaces['LANA']['base'].replace('x', '1')
            elif dst == 'r':
                rule['dst'] = self.interfaces['LANA']['remote_base'].replace('x', '30.40')
            elif dst == 'a':
                rule['dst'] = self.interfaces['LANA']['adjacent_base'].replace('x', '30.40')
        else:
            if dst == 'l':
                rule['dst'] = self.interfaces['LANB']['base'].replace('x', '3')
            elif dst == 's':
                rule['dst'] = self.interfaces['LANB']['base'].replace('x', '1')
            elif dst == 'r':
                rule['dst'] = self.interfaces['LANB']['remote_base'].replace('x', '30.40')
            elif dst == 'a':
                rule['dst'] = self.interfaces['LANB']['adjacent_base'].replace('x', '30.40')

        if action == 'p':
            rule['action'] = 'pass'
        elif action == 'dr':
            rule['action'] = 'drop'
        elif action == 'dn':
            rule['action'] = 'deny'
        return rule

    def test_basic_generation(self):
        """ test simple rules generatation for verifying that remote to remote rules are not generated and almost everything else is """
        expected_rules = list()
        not_expected_rules = list()
        rules = self.definitions['rules']
        # we want to generate some rules to check
        # l => local, r => remote, a => adjacent, s => self
        # s => same interface, o => other interface
        # p => pass, dr => drop, dn => deny
        for src in ['l', 'r', 'a', 's']:
            for dst in ['l', 'r', 'a', 's']:
                for interface in ['s', 'o']:
                    for action in ['p', 'dr', 'dn']:
                        rule = self.gen_rule(src, dst, interface, action)
                        rules[rule['name']] = rule

                        generated_rule = dict(
                            name=rule['name'],
                            interface='LANA',
                            source=rule['src'],
                            destination=rule['dst'],
                            protocol='any',
                            action=rule['action']
                        )

                        # we won't generate remote to remote rules or local to local on the same interface if the traffic is allowed
                        # when the traffic is denied or dropped, we consider for now that every rule should be generated, even if it's seems dumb
                        if rule['name'] in ['r_r_s_p', 'r_r_o_p', 'l_l_s_p']:
                            not_expected_rules.append(generated_rule)
                        else:
                            expected_rules.append(generated_rule)
                        del rule['name']

        self.run_rules()
        for expected_rule in expected_rules:
            rule = self.assert_get_rule(expected_rule['name'])
            self.compare_rules(expected_rule, rule)

        for rule in not_expected_rules:
            self.assert_rule_not_found(rule['name'])
