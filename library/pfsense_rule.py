#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: pfsense_rule
short_description: Manage pfSense rules
description:
  >
    Manage pfSense rules
author: Orion Poplawski (@opoplawski)
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
    choices: [ "inet", 'inet46' ]
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

from ansible.module_utils.pfsense.pfsense import pfSenseModule
import time
import re

class pfSenseRule(object):

    def __init__(self, module):
        self.module = module
        self.pfsense = pfSenseModule(module)
        self.rules = self.pfsense.get_element('filter')

    def _find_rule_by_descr(self, descr, interface):
        found = None
        i = 0
        for rule in self.rules:
            descrEl = rule.find('descr')
            interfaceEl = rule.find('interface')
            if (descrEl is not None and descrEl.text == descr
                and interfaceEl is not None and interfaceEl.text == interface):
                found = rule
                break
            i += 1
        return (found, i)

    def _find_rule_by_match(self, interface, action, ipprotocol, protocol, source, destination):
        found = None
        i = 0
        for rule in self.rules:
            interfaceEl = rule.find('interface')
            typeEl = rule.find('type')
            ipprotocolEl = rule.find('ipprotocol')
            protocolEl = rule.find('protocol')
            sourceEl = rule.find('source')
            destinationEl = rule.find('destination')
            if (interfaceEl is not Null and interfaceEl.text == interface
                and typeEl is not Null and typeEl.text == action
                and ipprotocolEl is not Null and ipprotocolEl.text == ipprotocol
                and protocolEl is not Null and protocolEl.text == protocol
                # FIXME: These two are not correct
                and sourceEl is not Null and sourceEl.find('address').text == source
                and destinationEl is not Null and destinationEl.find('address').text == destination):
                found = rule
                break
            i += 1
        return (found, i)

    def _insert(self, el, after=None, before='bottom'):
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
                self.rules.insert(i+1, el)
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

    # validate interface
    def parse_interface(self, interface):
        if self.pfsense.is_interface_name(interface):
            interface = self.pfsense.get_interface_pfsense_by_name(interface)
            return interface
        elif self.pfsense.is_interface_pfsense(interface):
            return interface
        else:
            self.module.fail_json(msg='%s is not a valid interface' % (interface))

    def parse_address(self, s):
        m = re.match('([^:]+):?([^:]+)?', s)
        address = m.group(1)
        port = m.group(2)
        d = dict()
        if address == 'any':
            d['any'] = None
        elif address == 'NET':
            d['network'] = port
            return d
        # rule with interface name (LAN, WAN...)
        elif self.pfsense.is_interface_name(address):
            interface = self.pfsense.get_interface_pfsense_by_name(address)
            d['network'] = interface
        else:
            if not self.pfsense.is_ip_or_alias(address):
                self.module.fail_json(msg='Cannot parse address %s, not IP or alias' % (address))
            d['address'] = address
        if port is not None:
            if not self.pfsense.is_port_or_alias(port):
                self.module.fail_json(msg='Cannot parse port %s, not port number or alias' % (port))
            d['port'] = port
        return d

    def add(self, rule, after=None, before='bottom'):
        ruleEl, i = self._find_rule_by_descr(rule['descr'], rule['interface'])
        changed = False
        rc = 0
        stdout = ''
        stderr = ''
        timestamp = '%d' % int(time.time())
        if ruleEl is None:
            changed = True
            if self.module.check_mode:
                self.module.exit_json(changed=True)
            rule['id'] = ''
            rule['tracker'] = timestamp
            rule['created'] = rule['updated'] = dict()
            rule['created']['time'] = rule['updated']['time'] = timestamp
            rule['created']['username'] = rule['updated']['username'] = self.pfsense.get_username()
            ruleEl = self.pfsense.new_element('rule')
            self.pfsense.copy_dict_to_element(rule, ruleEl)
            self._insert(ruleEl, after, before)
            self.pfsense.write_config(descr='ansible pfsense_rule added %s' % (rule['descr']))
            (rc, stdout, stderr) = self._update()
        else:
            changed = self.pfsense.copy_dict_to_element(rule, ruleEl)
            if self.module.check_mode:
                self.module.exit_json(changed=changed)
            if changed:
                ruleEl.find('updated').find('time').text = timestamp
                ruleEl.find('updated').find('username').text = self.pfsense.get_username()
                self.pfsense.write_config(descr='ansible pfsense_rule updated "%s" interface %s action %s' % (rule['descr'], rule['interface'], rule['type']))
                (rc, stdout, stderr) = self._update()
        self.module.exit_json(stdout=stdout, stderr=stderr, changed=changed)

    def remove(self, rule):
        ruleEl, i = self._find_rule_by_descr(rule['descr'], rule['interface'])
        changed = False
        rc = 0
        stdout = ''
        stderr = ''
        if ruleEl is not None:
            if self.module.check_mode:
                self.module.exit_json(changed=True)
            self.rules.remove(ruleEl)
            changed = True
            self.pfsense.write_config(descr='ansible pfsense_rule removed "%s" interface %s' % (rule['descr'], rule['interface']))
            (rc, stdout, stderr) = self._update()
        self.module.exit_json(stdout=stdout, stderr=stderr, changed=changed)

def main():
    module = AnsibleModule(
        argument_spec={
            'name': {'required': True, 'type': 'str'},
            'action': {
                'default': 'pass',
                'required': False,
                'choices': ['pass', "block", 'reject']
            },
            'state': {
                'required': True,
                'choices': ['present', 'absent']
            },
            'disabled': {
                'default': False,
                'required': False,
            },
            'interface': {
                'required': True,
                'type': 'str'
            },
            'floating': {
                'required': False,
                'choices': [ "yes", "no" ]
            },
            'direction': {
                'required': False,
                'choices': [ "any", "in", "out" ]
            },
            'ipprotocol': {
                'required': False,
                'default': 'inet',
                'choices': [ 'inet', 'inet46' ]
            },
            'protocol': {
                'default': 'any',
                'required': False,
                'choices': [ "any", "tcp", "udp", "tcp/udp", "icmp" ]
            },
            'source': {
                'required': True,
                'type': 'str'
            },
            'destination': {
                'required': True,
                'type': 'str'
            },
            'log': {
                'required': False,
                'choices': [ "no", "yes" ]
            },
            'after': {
                'required': False,
                'type': 'str'
            },
            'before': {
                'required': False,
                'type': 'str'
            },
            'statetype': {
                'required': False,
                'default': 'keep state',
                'type': 'str'
            }
        },
        required_if = [
            [ "floating", "yes", [ "direction" ] ],
        ],
        supports_check_mode=True)

    pfrule = pfSenseRule(module)

    rule = dict()
    rule['descr'] = module.params['name']
    rule['type'] = module.params['action']
    #rule['interface'] = module.params['interface']
    # Parse interface
    rule['interface'] = pfrule.parse_interface(module.params['interface'])
    if module.params['floating'] == 'yes':
        rule['floating'] = module.params['floating']
    if module.params['direction'] is not None:
        rule['direction'] = module.params['direction']
    rule['ipprotocol'] = module.params['ipprotocol']
    if module.params['protocol'] != 'any':
        rule['protocol'] = module.params['protocol']
    rule['source'] = dict()
    rule['source'] = pfrule.parse_address(module.params['source'])
    rule['destination'] = pfrule.parse_address(module.params['destination'])
    if module.params['log'] == 'yes':
        rule['log'] == ''
    rule['statetype'] = module.params['statetype']

    state = module.params['state']
    if state == 'absent':
        pfrule.remove(rule)
    elif state == 'present':
        if module.params['after'] and module.params['before']:
            module.fail_json(msg='Cannot specify both after and before')
        elif module.params['after']:
            pfrule.add(rule, after=module.params['after'])
        elif module.params['before']:
            pfrule.add(rule, before=module.params['before'])
        else:
            pfrule.add(rule)


# import module snippets
from ansible.module_utils.basic import AnsibleModule

main()
