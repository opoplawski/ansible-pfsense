#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: pfsense_alias
short_description: Manage pfSense aliases
description:
  >
    Manage pfSense aliases
author: Orion Poplawski (@opoplawski)
notes:
options:
  name:
    description: The name the alias
    required: true
    default: null
  type:
    description: The type of the alias
    required: true
    default: hostrue
    choices: [ "host", "port", "urltable" ]
  state:
    description: State in which to leave the alias
    default: present
    choices: [ "present", "absent" ]
  address:
    description: The address of the alias
    required: true
    default: null
  descr:
    description: Description
    default: null
  detail:
    description: Details for items
    default: ""
  updatefreq:
    description: Update frequency in days for urltable
"""

EXAMPLES = """
- name: Add adservers alias
  pfsense_alias:
    name: adservers
    address: 10.0.0.1 10.0.0.2
    state: present

- name: Remove adservers alias
  pfsense_alias:
    name: adservers
    state: absent
"""

from ansible.module_utils.pfsense.pfsense import pfSenseModule

class pfSenseAlias(object):

    def __init__(self, module):
        self.module = module
        self.pfsense = pfSenseModule(module)
        self.aliases = self.pfsense.get_element('aliases')

    def _update(self):
        return self.pfsense.phpshell('''require_once("filter.inc");
if (filter_configure() == 0) { clear_subsystem_dirty('aliases'); }''')

    def add(self, alias):
        aliasEl = self.pfsense.find_alias(alias['name'], alias['type'])
        changed = False
        rc = 0
        stdout = ''
        stderr = ''
        diff = {}
        diff['after'] = alias
        if aliasEl is None:
            diff['before'] = ''
            changed = True
            aliasEl = self.pfsense.new_element('alias')
            self.pfsense.copy_dict_to_element(alias, aliasEl)
            descr='ansible pfsense_alias added %s type %s' % (alias['name'], alias['type'])
            if not self.module.check_mode:
                self.aliases.append(aliasEl)
        else:
            diff['before'] = self.pfsense.element_to_dict(aliasEl)
            changed = self.pfsense.copy_dict_to_element(alias, aliasEl)
            descr='ansible pfsense_alias updated "%s" type %s' % (alias['name'], alias['type'])
        if changed and not self.module.check_mode:
            self.pfsense.write_config(descr=descr)
            (rc, stdout, stderr) = self._update()
        self.module.exit_json(stdout=stdout, stderr=stderr, changed=changed, diff=diff)

    def remove(self, alias):
        aliasEl = self.pfsense.find_alias(alias['name'], alias['type'])
        changed = False
        rc = 0
        stdout = ''
        stderr = ''
        diff = {}
        diff['after'] = ''
        diff['before'] = ''
        if aliasEl is not None:
            diff['before'] = self.pfsense.element_to_dict(aliasEl)
            changed = True
            if not self.module.check_mode:
                self.aliases.remove(aliasEl)
                self.pfsense.write_config(descr='ansible pfsense_alias removed "%s"' % (alias['name']))
                (rc, stdout, stderr) = self._update()
        self.module.exit_json(stdout=stdout, stderr=stderr, changed=changed, diff=diff)


def main():
    module = AnsibleModule(
        argument_spec={
            'name': {'required': True, 'type': 'str'},
            'type': {
                'default': 'host',
                'required': False,
                'choices': ['host', 'port', 'urltable']
            },
            'state': {
                'required': True,
                'choices': ['present', 'absent']
            },
            'address': {'default': None, 'required': False, 'type': 'str'},
            'descr': {'default': None, 'required': False, 'type': 'str'},
            'detail': {'default': '', 'required': False, 'type': 'str'},
            'updatefreq': {'default': None, 'required': False, 'type': 'str'},
        },
        required_if = [
            [ "type", "urltable", [ "updatefreq" ] ],
        ],
        supports_check_mode=True)

    pfalias = pfSenseAlias(module)

    alias = dict()
    alias['name'] = module.params['name']
    alias['type'] = module.params['type']
    state = module.params['state']

    if state == 'absent':
        pfalias.remove(alias)
    elif state == 'present':
        alias['address'] = module.params['address']
        alias['descr'] = module.params['descr']
        alias['detail'] = module.params['detail']
        if alias['type'] == 'urltable':
            alias['url'] = module.params['address']
            alias['updatefreq'] = module.params['updatefreq']
        pfalias.add(alias)


# import module snippets
from ansible.module_utils.basic import AnsibleModule

main()
