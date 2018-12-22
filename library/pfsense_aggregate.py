#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import time
import re
from ansible.module_utils.pfsense.pfsense import PFSenseModule
from ansible.module_utils.basic import AnsibleModule

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: pfsense_aggregate
short_description: Manage pfSense rules
description:
  >
    Manage pfSense rules
author: Orion Poplawski (@opoplawski)
        Frederic Bor (@f-bor)
notes:
options:
  name:
    description: The name the rule
    required: true
    default: null
  action:
    description: The action of the rule
    required: true
    default: pass
    choices: [ "pass", "block", "reject" ]
  state:
    description: State in which to leave the rule
    required: true
    default: present
    choices: [ "present", "absent" ]
  disabled:
    description: Is the rule disabled
    default: false
  interface:
    description: The interface for the rule
    required: true
  floating:
    description: Is the rule floating
    choices: [ "yes", "no" ]
  direction:
    description: Direction floating rule applies to
    choices: [ "any", "in", "out" ]
  ipprotocol:
    description: The IP protocol
    default: inet
    choices: [ "inet" ]
  protocol:
    description: The protocol
    default: any
    choices: [ "any", "tcp", "udp", "tcp/udp", "icmp" ]
  source:
    description: The source address, in {IP,HOST,ALIAS}[:port] or NET:INTERFACE format
    required: true
    default: null
  destination:
    description: The destination address, in {IP,HOST,ALIAS}[:port] or NET:INTERFACE format
    required: true
    default: null
  log:
    description: Log packets matched by rule
    default: no
    choices: [ "no", "yes" ]
  after:
    description: Rule to go after, or "top"
  before:
    description: Rule to go before, or "bottom"
  statetype:
    description: State type
    default: keep state
"""

EXAMPLES = """
- name: "Add Internal DNS out rule"
  pfsense_rule:
    name: 'Allow Internal DNS traffic out'
    action: pass
    interface: lan
    ipprotocol: inet
    protocol: udp
    source: dns_int
    destination: any:53
    after: 'Allow proxies out'
    state: present
"""


class PFSenseModuleAggregate(object):

    def __init__(self, module):
        self.module = module
        self.pfsense = PFSenseModule(module)
        self.rules = self.pfsense.get_element('filter')
        self.aliases = self.pfsense.get_element('aliases')

        self.stdout = ''
        self.stderr = ''
        self.changed = False
        self.diff = {}
        self.diff['added'] = []
        self.diff['deleted'] = []
        self.diff['modified'] = []

    def _find_rule_by_descr(self, descr, interface):
        found = None
        i = 0
        for rule in self.rules:
            descrEl = rule.find('descr')
            interfaceEl = rule.find('interface')
            if descrEl is not None and descrEl.text == descr and interfaceEl is not None and interfaceEl.text == interface:
                found = rule
                break
            i += 1
        return (found, i)

    def insert_rule(self, el, after=None, before='bottom'):
        interface = el.find('interface').text
        if after is None and before == 'bottom':
            self.rules.append(el)
        elif after == 'top':
            i = 0
            # Find the first rule for this interface
            for rule in self.rules:
                interfaceEl = rule.find('interface')
                if interfaceEl is not None and interfaceEl.text == interface:
                    break
                i += 1
            self.rules.insert(i, el)
        elif after is not None:
            found, i = self._find_rule_by_descr(after, interface)
            if found:
                self.rules.insert(i + 1, el)
            else:
                self.module.fail_json(msg='Failed to insert after rule=%s interface=%s' % (after, interface))
        elif before is not None:
            found, i = self._find_rule_by_descr(before, interface)
            if found:
                self.rules.insert(i, el)
            else:
                self.module.fail_json(msg='Failed to insert before rule=%s interface=%s' % (before, interface))
        else:
            self.module.fail_json(msg='Failed to add rule')

    def _update(self):
        return self.pfsense.phpshell('''require_once("filter.inc");
if (filter_configure() == 0) { clear_subsystem_dirty('rules'); }''')

    def params_to_rule(self, params):
        interface = self.pfsense.get_mapped_interface(params['interface'])
        if not interface:
            self.module.fail_json(msg='Interface ' + params['interface'] + ' does not exist on target')

        rule = dict()
        rule['descr'] = params['name']
        rule['type'] = params['action']
        rule['interface'] = interface
        if params['floating'] == 'yes':
            rule['floating'] = params['floating']
        if params['direction'] is not None:
            rule['direction'] = params['direction']
        rule['ipprotocol'] = params['ipprotocol']
        if params['protocol'] != 'any':
            rule['protocol'] = params['protocol']
        rule['source'] = dict()
        rule['source'] = self.parse_address(params['source'])
        rule['destination'] = self.parse_address(params['destination'])
        if params['log'] == 'yes':
            rule['log'] = ''
        rule['statetype'] = params['statetype']
        return rule

    def parse_address(self, s):
        if not s:
            return None
        m = re.match('([^:]+):?([^:]+)?', s)
        address = m.group(1)
        port = m.group(2)
        d = dict()
        if address == 'wanip' or address == 'lanip':
            d['network'] = address
        elif address == 'any':
            d['any'] = None
        elif address == 'NET':
            d['network'] = port
            if len(m) >= 3:
                d['port'] = m.group(3)
            return d
        else:
            if not self.pfsense.is_ip_or_alias(address):
                self.module.fail_json(msg='Cannot parse address %s, not IP or alias' % (address))
            d['address'] = address

        if port is not None:
            if not self.pfsense.is_port_or_alias(port):
                self.module.fail_json(msg='Cannot parse port %s, not port number or alias' % (port))
            d['port'] = port
        return d

    def map_params_to_obj(self, param_name):
        obj = []
        aggregated = self.module.params.get(param_name)
        if aggregated:
            for item in aggregated:
                d = item.copy()
                obj.append(d)

        return obj

    def sync_rule_param_presence(self, rule, ruleEl, param):
        changed = False
        if param not in rule:
            paramEl = ruleEl.find(param)
            if paramEl is not None:
                changed = True
                ruleEl.remove(paramEl)
        return changed

    def sync_extra_rule_params(self, rule, ruleEl):
        changed = False
        if self.sync_rule_param_presence(rule, ruleEl, 'log'): changed = True
        if self.sync_rule_param_presence(rule, ruleEl, 'floating'): changed = True
        if self.sync_rule_param_presence(rule, ruleEl, 'direction'): changed = True
        if self.sync_rule_param_presence(rule, ruleEl, 'protocol'): changed = True

        return changed

    def add_rule(self, rule, after=None, before='bottom'):
        rule_elt, i = self._find_rule_by_descr(rule['descr'], rule['interface'])
        changed = False
        timestamp = '%d' % int(time.time())
        if rule_elt is None:
            changed = True

            rule['id'] = ''
            rule['tracker'] = timestamp
            rule['created'] = rule['updated'] = dict()
            rule['created']['time'] = rule['updated']['time'] = timestamp
            rule['created']['username'] = rule['updated']['username'] = self.pfsense.get_username()
            rule_elt = self.pfsense.new_element('rule')
            self.pfsense.copy_dict_to_element(rule, rule_elt)
            self.insert_rule(rule_elt, after, before)
            self.diff['added'].append(rule)
        else:
            changed = self.pfsense.copy_dict_to_element(rule, rule_elt)
            if self.sync_extra_rule_params(rule, rule_elt): changed = True

            if after is not None:
                found, k = self._find_rule_by_descr(after, rule['interface'])
                if found:
                    if k + 1 != i:
                        self.rules.remove(rule_elt)
                        found, k = self._find_rule_by_descr(after, rule['interface'])
                        self.rules.insert(k + 1, rule_elt)
                        changed = True
                else:
                    self.module.fail_json(msg='Failed to insert after rule=%s interface=%s' % (after, rule['interface']))

            if changed:
                rule_elt.find('updated').find('time').text = timestamp
                rule_elt.find('updated').find('username').text = self.pfsense.get_username()
                self.diff['modified'].append(self.pfsense.element_to_dict(rule_elt))

        if changed:
            self.changed = True

    def remove_rule(self, rule):
        rule_elt, i = self._find_rule_by_descr(rule['descr'], rule['interface'])
        if rule_elt is not None:
            self.rules.remove(rule_elt)
            self.changed = True
            self.diff['deleted'].append(self.pfsense.element_to_dict(rule_elt))

    def has_rule(self, rule, rules):
        descr = rule.find('descr')
        interface = rule.find('interface')

        # probably not a rule
        if descr is None and interface is None:
            return True

        for _rule in rules:
            rule_interface = self.pfsense.get_mapped_interface(_rule['interface'])
            if not rule_interface:
                self.module.fail_json(msg='Interface ' + _rule['interface'] + ' does not exist on target')
            if descr is not None and _rule['name'] == descr.text and interface is not None and rule_interface == interface.text:
                return True
        return False

    def setup_rules(self):
        want = self.module.params['aggregated_rules']

        for rule in want:
            state = rule['state']
            if state == 'absent':
                self.remove_rule(self.params_to_rule(rule))
            elif state == 'present':
                if rule['after'] and rule['before']:
                    self.module.fail_json(msg='Cannot specify both after and before')
                elif rule['after']:
                    self.add_rule(self.params_to_rule(rule), after=rule['after'])
                elif rule['before']:
                    self.add_rule(self.params_to_rule(rule), before=rule['before'])
                else:
                    self.add_rule(self.params_to_rule(rule))

        if self.module.params['purge']:
            todel = []
            for rule in self.rules:
                if not self.has_rule(rule, want):
                    todel.append(rule)

            for rule in todel:
                self.diff['deleted'].append(self.pfsense.element_to_dict(rule))
                self.rules.remove(rule)
                self.changed = True

    ###############
    # Aliases part
    #
    def add_alias(self, alias):
        alias_elt = self.pfsense.find_alias(alias['name'], alias['type'])
        if alias_elt is None:
            alias_elt = self.pfsense.new_element('alias')
            self.pfsense.copy_dict_to_element(alias, alias_elt)
            self.aliases.append(alias_elt)
            changed = True
            self.diff['added'].append(alias)
        else:
            changed = self.pfsense.copy_dict_to_element(alias, alias_elt)
            if changed:
                self.diff['modified'].append(self.pfsense.element_to_dict(alias_elt))

        if changed:
            self.changed = changed

    def remove_alias(self, alias):
        alias_elt = self.pfsense.find_alias(alias['name'], alias['type'])
        if alias_elt is not None:
            self.aliases.remove(alias_elt)
            self.changed = True
            self.diff['deleted'].append(self.pfsense.element_to_dict(alias_elt))

    def want_alias(self, alias_elt, want):
        alias = self.pfsense.element_to_dict(alias_elt)
        alias_name = alias['name']
        alias_type = alias['type']
        for _alias in want:
            if alias['state'] == 'absent': continue
            if alias['name'] == alias_name and alias['type'] == alias_type:
                return True
        return False

    def setup_aliases(self):
        want = self.module.params['aggregated_aliases']
        for alias in want:
            if alias['state'] == 'absent':
                self.remove_alias(alias)
            elif alias['state'] == 'present':
                self.add_alias(alias)

        if self.module.params['purge']:
            todel = []
            for alias in self.aliases:
                if not self.want_alias(alias, want):
                    todel.append(alias)

            for alias in todel:
                self.diff['deleted'].append(self.pfsense.element_to_dict(alias))
                self.aliases.remove(alias)
                self.changed = True


def main():
    aggregate_rules_spec = dict(
        name=dict(required=True, type='str'),
        action=dict(default='pass', required=False, choices=['pass', "block", 'reject']),
        state=dict(default='present', choices=['present', 'absent']),
        disabled=dict(default=False, required=False,),
        interface=dict(required=False, type='str'),
        floating=dict(required=False, choices=["yes", "no"]),
        direction=dict(required=False, choices=["any", "in", "out"]),
        ipprotocol=dict(required=False, default='inet', choices=['inet']),
        protocol=dict(default='any', required=False, choices=["any", "tcp", "udp", "tcp/udp", "icmp"]),
        source=dict(required=False, type='str'),
        destination=dict(required=False, type='str'),
        log=dict(required=False, choices=["no", "yes"]),
        after=dict(required=False, type='str'),
        before=dict(required=False, type='str'),
        statetype=dict(required=False, default='keep state', type='str')
    )

    required_if_rules = [["floating", "yes", ["direction"]]]

    aggregate_aliases_spec = dict(
        name=dict(required=True, type='str'),
        type=dict(required=False, default='host', choices=['host', 'network', 'port', 'urltable']),
        state=dict(default='present', choices=['present', 'absent']),
        address=dict(required=True, default=None, type='str'),
        descr=dict(default=None, type='str'),
        detail=dict(default='', type='str'),
        updatefreq=dict(default=None, type='str'),
    )

    required_if_aliases = [["type", "urltable", ["updatefreq"]]]

    argument_spec = dict(
        aggregated_aliases=dict(type='list', elements='dict', options=aggregate_aliases_spec, required_if=required_if_aliases),
        aggregated_rules=dict(type='list', elements='dict', options=aggregate_rules_spec, required_if=required_if_rules),
        purge=dict(default=False, type='bool')
    )

    required_one_of = [['aggregated_aliases', 'aggregated_rules']]

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_one_of=required_one_of,
        supports_check_mode=True)

    pfmodule = PFSenseModuleAggregate(module)

    pfmodule.setup_aliases()
    pfmodule.setup_rules()

    if pfmodule.changed and not module.check_mode:
        pfmodule.pfsense.write_config(descr='changed')
        (rc, pfmodule.stdout, pfmodule.stderr) = pfmodule._update()
    module.exit_json(stdout=pfmodule.stdout, stderr=pfmodule.stderr, changed=pfmodule.changed, diff=pfmodule.diff)


if __name__ == '__main__':
    main()
