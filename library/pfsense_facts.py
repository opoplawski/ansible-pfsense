# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = """
module: pfsense_facts
author: Orion Poplawski (@opoplawski)
version_added: "2.10"
short_description: Return pfSense configuration
description:
- Collects a set of facts about a pfSense device.
options:
  gather_subset:
	Default: "all"
  description: If supplied, restrict the additional facts collected to the
    given subset. Possible values: all, aliases, rules, rule_separators. Can
    specify a list of values to specify a larger subset. Values can also be
    used with an initial ! to specify that that specific subset should not be
    collected. For instance: !hardware,!network,!virtual,!ohai,!facter. If
    !all is specified then only the min subset is collected. To avoid
    collecting even the min subset, specify !all,!min. To collect only
    specific facts, use !all,!min, and specify the particular fact subsets.
    Use the filter parameter if you do not want to display some collected
    facts.
"""

EXAMPLES = """
- name: Get all aliases to be defined
  pfsense_facts:
    gather_subset: aliases
  register: aliases

- name: Get all rules to be defined
  pfsense_facts:
    gather_subset: rules
  register: rules

- name: Get all rule_separators to be defined
  pfsense_facts:
    gather_subset: rule_separators
  register: rule_separators

"""

RETURN = """
  ansible_aliases:
    description:
      All aliases
    type: list
  ansible_rules:
    description:
      All rules
    type: list
  ansible_separators:
    description:
      All rule separators
    type: list
"""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.network.pfsense.pfsense import PFSenseModule
from ansible.module_utils.network.pfsense.alias import PFSenseAliasModule
from ansible.module_utils.network.pfsense.interface import PFSenseInterfaceModule
from ansible.module_utils.network.pfsense.rule import PFSenseRuleModule
from ansible.module_utils.network.pfsense.rule_separator import PFSenseRuleSeparatorModule
from ansible.module_utils.network.pfsense.vlan import PFSenseVlanModule


class PFSenseModuleFacts(object):
    """ module collecting pfsense aggregated aliases, rules, rule separators, interfaces and vlans """

    def __init__(self, module):
        self.module = module
        self.name = "pfsense_facts"
        self.pfsense = PFSenseModule(module)
        self.pfsense_alias = PFSenseAliasModule(module, self.pfsense)
        self.pfsense_interface = PFSenseInterfaceModule(module, self.pfsense)
        self.pfsense_rule = PFSenseRuleModule(module, self.pfsense)
        self.pfsense_rule_separator = PFSenseRuleSeparatorModule(module, self.pfsense)
        self.pfsense_vlan = PFSenseVlanModule(module, self.pfsense)
        self.result = dict()

    def run(self, params):
        gather_list = [ 'aliases', 'interfaces', 'rules', 'rule_separators', 'vlans' ]
        if 'all' not in params['gather_subset']:
            gather_list = params['gather_subset']

        if 'aliases' in gather_list:
            self.result['ansible_aliases'] = self.pfsense_alias.get_all(params['return_unmanaged'])
        if 'interfaces' in gather_list:
            self.result['ansible_interfaces'] = self.pfsense_interface.get_all(params['return_unmanaged'])
        if 'rules' in gather_list:
            self.result['ansible_rules'] = self.pfsense_rule.get_all(params['return_unmanaged'])
        if 'rule_separators' in gather_list:
            self.result['ansible_rule_separators'] = self.pfsense_rule_separator.get_all(params['return_unmanaged'])
        if 'vlans' in gather_list:
            self.result['ansible_vlans'] = self.pfsense_vlan.get_all(params['return_unmanaged'])
        self.module.exit_json(**self.result) 


def main():
    """ Output debug helper """
    argument_spec = dict(
        gather_subset=dict(default=['all'], choices=['all','aliases','interfaces','rules','rule_separators','vlans'], type='list'),
        return_unmanaged=dict(default=False, type='bool'))

    rule_filter = None

    module = AnsibleModule(argument_spec=argument_spec)
    pfmodule = PFSenseModuleFacts(module)
    pfmodule.run(module.params)


if __name__ == '__main__':
    main()
